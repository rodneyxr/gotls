package cmd

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var (
	fullchain  bool
	caCertPath string
	base64Out  bool
)

// infoCmd prints information about a certificate or key file or directory
var infoCmd = &cobra.Command{
	Use:   "info <file|dir>",
	Short: "Show information about a certificate or key PEM file (or all certs in a directory)",
	Long: `The info command inspects certificates and private keys and prints useful details.

When given a certificate file (.crt/.pem) the command prints subject CN, SANs (DNS names, IPs, emails),
serial number, validity (Not Before / Not After), whether it's a CA, key usages, issuer,
OCSP/CRL endpoints, and public key algorithm/size.

When given a directory, the command scans for .crt and .pem files and prints the same info
for each certificate it finds.`,
	Example: `  # Show info for a single cert
  gotls info ./certs/example.com.crt

  # Show info for all certs in a directory
  gotls info ./certs/

  # Create fullchain for each cert (auto-detects CA in same directory)
  gotls info ./certs/ --fullchain

  # Create fullchain with specific CA cert
  gotls info ./certs/ --fullchain --ca-cert ./certs/ca.crt

  # Same as above but print base64-encoded fullchain to stdout
  gotls info ./certs/ --fullchain --base64`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		path := args[0]
		abs, err := filepath.Abs(path)
		if err == nil {
			path = abs
		}

		st, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("failed to stat path: %w", err)
		}

		// If fullchain requested, ensure CA path provided or try to find CA in same directory and load CA data
		var caData []byte
		if fullchain {
			if caCertPath == "" {
				// try to find a CA cert in the same directory as the path (or inside the dir itself)
				dir := path
				if !st.IsDir() {
					dir = filepath.Dir(path)
				}
				foundPath, b, err := findCAInDir(dir)
				if err != nil {
					return fmt.Errorf("--ca-cert not provided and no CA certificate found in %s: %w", dir, err)
				}
				caCertPath = foundPath
				caData = b
			} else {
				b, err := os.ReadFile(caCertPath)
				if err != nil {
					return fmt.Errorf("failed to read CA certificate: %w", err)
				}
				caData = b
			}
		}

		handleFile := func(p string) error {
			data, err := os.ReadFile(p)
			if err != nil {
				return fmt.Errorf("failed to read file %s: %w", p, err)
			}
			orig := make([]byte, len(data))
			copy(orig, data)

			var found bool
			// decode PEM blocks (could be cert or key)
			for {
				block, rest := pem.Decode(data)
				if block == nil {
					break
				}

				switch block.Type {
				case "CERTIFICATE":
					cert, err := x509.ParseCertificate(block.Bytes)
					if err != nil {
						fmt.Printf("%s: failed to parse certificate: %v\n", p, err)
						found = true
						break
					}
					fmt.Printf("File: %s\n", p)
					printCertInfo(cert)
					found = true
				case "RSA PRIVATE KEY":
					key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
					if err != nil {
						fmt.Printf("%s: failed to parse private key: %v\n", p, err)
						found = true
						break
					}
					fmt.Printf("File: %s\n", p)
					fmt.Printf("Private Key: RSA (%d bits)\n\n", key.N.BitLen())
					found = true
				default:
					// skip other block types but mark handled
					found = true
				}

				data = rest
			}

			if !found {
				// try DER certificate
				if cert, err := x509.ParseCertificate(data); err == nil {
					fmt.Printf("File: %s\n", p)
					printCertInfo(cert)
					found = true
				}
			}

			if fullchain && len(caData) > 0 {
				full := append([]byte(nil), orig...)
				// Ensure there's a newline separator
				if len(full) > 0 && full[len(full)-1] != '\n' {
					full = append(full, '\n')
				}
				full = append(full, caData...)

				if base64Out {
					enc := base64.StdEncoding.EncodeToString(full)
					fmt.Printf("== Base64 Fullchain: %s ==\n", p)
					fmt.Println(enc)
				} else {
					fmt.Printf("== Fullchain PEM: %s ==\n", p)
					os.Stdout.Write(full)
					fmt.Println()
				}
			}

			return nil
		}

		if st.IsDir() {
			ents, err := os.ReadDir(path)
			if err != nil {
				return fmt.Errorf("failed to read dir: %w", err)
			}

			for _, e := range ents {
				if e.IsDir() {
					continue
				}
				name := e.Name()
				ext := strings.ToLower(filepath.Ext(name))
				if ext != ".crt" && ext != ".pem" {
					continue
				}
				p := filepath.Join(path, name)
				if err := handleFile(p); err != nil {
					fmt.Fprintf(os.Stderr, "warning: %v\n", err)
				}
			}
			return nil
		}

		// single file
		return handleFile(path)
	},
}

func printCertInfo(cert *x509.Certificate) {
	fmt.Println("Certificate:")
	fmt.Printf("  Subject CN: %s\n", cert.Subject.CommonName)
	fmt.Printf("  Is CA: %t\n", cert.IsCA)
	fmt.Printf("  Serial Number: %s\n", cert.SerialNumber.String())
	fmt.Printf("  Not Before: %s\n", cert.NotBefore.Format(time.RFC3339))
	fmt.Printf("  Not After: %s\n", cert.NotAfter.Format(time.RFC3339))

	if len(cert.DNSNames) > 0 {
		fmt.Println("  DNS Names:")
		for _, d := range cert.DNSNames {
			fmt.Printf("    - %s\n", d)
		}
	}

	if len(cert.IPAddresses) > 0 {
		fmt.Println("  IP Addresses:")
		for _, ip := range cert.IPAddresses {
			fmt.Printf("    - %s\n", ip.String())
		}
	}

	// Try to show common usages
	if len(cert.ExtKeyUsage) > 0 {
		fmt.Println("  Extended Key Usages:")
		for _, eku := range cert.ExtKeyUsage {
			switch eku {
			case x509.ExtKeyUsageServerAuth:
				fmt.Println("    - Server Auth")
			case x509.ExtKeyUsageClientAuth:
				fmt.Println("    - Client Auth")
			case x509.ExtKeyUsageCodeSigning:
				fmt.Println("    - Code Signing")
			case x509.ExtKeyUsageEmailProtection:
				fmt.Println("    - Email Protection")
			case x509.ExtKeyUsageTimeStamping:
				fmt.Println("    - Timestamping")
			default:
				fmt.Printf("    - Unknown (%d)\n", eku)
			}
		}
	}

	if cert.KeyUsage != 0 {
		fmt.Println("  Key Usage:")
		if cert.KeyUsage&x509.KeyUsageDigitalSignature != 0 {
			fmt.Println("    - Digital Signature")
		}
		if cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
			fmt.Println("    - Key Encipherment")
		}
		if cert.KeyUsage&x509.KeyUsageCertSign != 0 {
			fmt.Println("    - Certificate Sign")
		}
	}

	// Print issuer
	fmt.Printf("  Issuer: %s\n", cert.Issuer.CommonName)

	// Print OCSP server and CRL if present
	if len(cert.OCSPServer) > 0 {
		fmt.Println("  OCSP Servers:")
		for _, s := range cert.OCSPServer {
			fmt.Printf("    - %s\n", s)
		}
	}
	if len(cert.CRLDistributionPoints) > 0 {
		fmt.Println("  CRL Distribution Points:")
		for _, s := range cert.CRLDistributionPoints {
			fmt.Printf("    - %s\n", s)
		}
	}

	if len(cert.EmailAddresses) > 0 {
		fmt.Println("  Email Addresses:")
		for _, e := range cert.EmailAddresses {
			fmt.Printf("    - %s\n", e)
		}
	}

	// Print public key algorithm and size
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		fmt.Printf("  Public Key: RSA (%d bits)\n", pub.N.BitLen())
	default:
		_ = pub
	}

	fmt.Println()
}

func findCAInDir(dir string) (string, []byte, error) {
	candidates := []string{"ca.crt", "ca.pem", "root.crt", "root.pem", "cacert.crt", "cacert.pem"}
	for _, name := range candidates {
		p := filepath.Join(dir, name)
		if _, err := os.Stat(p); err == nil {
			b, err := os.ReadFile(p)
			if err != nil {
				return "", nil, err
			}
			return p, b, nil
		}
	}

	// if not found, try to find any .crt/.pem that looks like a CA (IsCA true)
	ents, err := os.ReadDir(dir)
	if err != nil {
		return "", nil, err
	}
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if ext != ".crt" && ext != ".pem" {
			continue
		}
		p := filepath.Join(dir, e.Name())
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		// try parse first cert block
		block, _ := pem.Decode(b)
		var der []byte
		if block != nil && block.Type == "CERTIFICATE" {
			der = block.Bytes
		} else {
			der = b
		}
		if cert, err := x509.ParseCertificate(der); err == nil {
			if cert.IsCA {
				return p, b, nil
			}
		}
	}

	return "", nil, fmt.Errorf("no CA certificate found in %s", dir)
}

func init() {
	infoCmd.Flags().BoolVar(&fullchain, "fullchain", false, "Append CA certificate to each cert to create a fullchain")
	infoCmd.Flags().StringVar(&caCertPath, "ca-cert", "", "Path to CA certificate to append when --fullchain is used")
	infoCmd.Flags().BoolVar(&base64Out, "base64", false, "When used with --fullchain, base64 encode the fullchain and print to stdout")
	rootCmd.AddCommand(infoCmd)
}
