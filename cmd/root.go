//go:generate go run ../tools/generate_docs

package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/rodneyxr/gotls/pkg/crypt"

	"github.com/spf13/cobra"
)

var (
	caName          string
	services        []string
	caCert          string
	caKey           string
	outputDirectory string
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "gotls",
	Short: "Generate CA and server certificates for local development",
	Long: `GoTLS is a Go application that quickly creates self-signed TLS certificates
for your local development environment.

Features:
- Generate CA certificates or use existing ones
- Create server certificates for multiple domains/services
- Support for wildcard certificates
- Inspect certificate details with the info command
- Create fullchain certificates for deployment`,
	Example: `  # Generate certificates with a custom CA name
  gotls -n 'My Custom CA' -s example.dev -s api.example.dev -d ./certs

  # Use existing CA to sign new certificates
  gotls --ca-cert ./certs/ca.crt --ca-key ./certs/ca.key -s newservice.dev

  # Inspect certificate details
  gotls info ./certs/example.dev.crt

  # View all certificates in a directory
  gotls info ./certs/`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return generateCertificates()
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

// GetRootCmd returns the root command for documentation generation
func GetRootCmd() *cobra.Command {
	return rootCmd
}

func init() {
	rootCmd.Flags().StringVarP(&caName, "ca-name", "n", "GoTLS CA", "The subject for the CA certificate")
	rootCmd.Flags().StringSliceVarP(&services, "services", "s", []string{}, "The services for which to generate certificates (can be used multiple times)")
	rootCmd.Flags().StringVar(&caCert, "ca-cert", "", "The path to an existing CA certificate file (ex: ca.crt)")
	rootCmd.Flags().StringVar(&caKey, "ca-key", "", "The path to an existing CA key file (ex: ca.key)")
	rootCmd.Flags().StringVarP(&outputDirectory, "output-directory", "d", "certs", "The directory to write the certificates to")
}

func generateCertificates() error {
	// Create the output directory if it doesn't exist
	if err := os.MkdirAll(outputDirectory, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	var caPair *crypt.CertificatePair
	var err error

	if caCert != "" && caKey != "" {
		// Load the existing CA certificate and key
		caPair, err = crypt.LoadCACert(caCert, caKey)
		if err != nil {
			return fmt.Errorf("failed to load CA certificate: %w", err)
		}
		fmt.Printf("Loaded existing CA certificate from %s\n", caCert)
	} else {
		// Generate the CA certificate
		caPair, err = crypt.GenerateCACert(caName)
		if err != nil {
			return fmt.Errorf("failed to generate CA certificate: %w", err)
		}

		// Save CA certificate and key
		if err := crypt.CreateCertFile(caPair.Cert, "ca", outputDirectory); err != nil {
			return fmt.Errorf("failed to create CA certificate file: %w", err)
		}
		if err := crypt.CreateKeyFile(caPair.Key, "ca", outputDirectory); err != nil {
			return fmt.Errorf("failed to create CA key file: %w", err)
		}
		fmt.Printf("Generated new CA certificate: %s\n", caName)
	}

	// Generate the server certificates for each service
	for _, service := range services {
		subject, sans := crypt.GetSubjectAndSANsForService(service)
		filename := crypt.GetFilenameForService(service)

		serverPair, err := crypt.GenerateServerCert(caPair, subject, sans)
		if err != nil {
			return fmt.Errorf("failed to generate certificate for %s: %w", service, err)
		}

		// Write the certificate and key to files
		if err := crypt.CreateCertFile(serverPair.Cert, filename, outputDirectory); err != nil {
			return fmt.Errorf("failed to create certificate file for %s: %w", service, err)
		}
		if err := crypt.CreateKeyFile(serverPair.Key, filename, outputDirectory); err != nil {
			return fmt.Errorf("failed to create key file for %s: %w", service, err)
		}

		fmt.Printf("Generated certificate for: %s\n", service)
	}

	absPath, err := filepath.Abs(outputDirectory)
	if err != nil {
		absPath = outputDirectory
	}
	fmt.Printf("Certificates created in: %s\n", absPath)

	return nil
}
