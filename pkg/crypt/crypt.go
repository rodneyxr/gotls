package crypt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CertificatePair holds a private key and certificate
type CertificatePair struct {
	Key  *rsa.PrivateKey
	Cert *x509.Certificate
}

// LoadCACert loads an existing CA certificate and key from files
func LoadCACert(certPath, keyPath string) (*CertificatePair, error) {
	// Load certificate
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}

	certBlock, _ := pem.Decode(certData)
	if certBlock == nil {
		return nil, fmt.Errorf("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Load private key
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	keyBlock, _ := pem.Decode(keyData)
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to decode key PEM")
	}

	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return &CertificatePair{
		Key:  key,
		Cert: cert,
	}, nil
}

// GenerateCACert generates a self-signed CA certificate
func GenerateCACert(subject string) (*CertificatePair, error) {
	// Generate private key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: subject,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"GoTLS CA"},
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created certificate: %w", err)
	}

	return &CertificatePair{
		Key:  key,
		Cert: cert,
	}, nil
}

// GenerateServerCert generates a server certificate signed by the CA
func GenerateServerCert(caPair *CertificatePair, subject string, sans []string) (*CertificatePair, error) {
	// Generate private key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Generate serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Default SANs to subject if not provided
	if sans == nil {
		sans = []string{subject}
	}

	// Parse SANs for DNS names and IP addresses
	var dnsNames []string
	var ipAddresses []net.IP

	for _, san := range sans {
		if ip := net.ParseIP(san); ip != nil {
			ipAddresses = append(ipAddresses, ip)
		} else {
			dnsNames = append(dnsNames, san)
		}
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: subject,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    dnsNames,
		IPAddresses: ipAddresses,
	}

	// Create certificate signed by CA
	certDER, err := x509.CreateCertificate(rand.Reader, &template, caPair.Cert, &key.PublicKey, caPair.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created certificate: %w", err)
	}

	return &CertificatePair{
		Key:  key,
		Cert: cert,
	}, nil
}

// CreatePEMFile creates a PEM file containing the private key and certificate
func CreatePEMFile(pair *CertificatePair, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	// Write private key
	keyBytes := x509.MarshalPKCS1PrivateKey(pair.Key)
	if err := pem.Encode(file, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	}); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	// Write certificate
	if err := pem.Encode(file, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: pair.Cert.Raw,
	}); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	return nil
}

// CreateKeyFile creates a .key file containing the private key
func CreateKeyFile(key *rsa.PrivateKey, filename, directory string) error {
	if err := os.MkdirAll(directory, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	filepath := filepath.Join(directory, filename+".key")
	file, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("failed to create key file: %w", err)
	}
	defer file.Close()

	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	return pem.Encode(file, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	})
}

// CreateCertFile creates a .crt file containing the certificate
func CreateCertFile(cert *x509.Certificate, filename, directory string) error {
	if err := os.MkdirAll(directory, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	filepath := filepath.Join(directory, filename+".crt")
	file, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("failed to create cert file: %w", err)
	}
	defer file.Close()

	return pem.Encode(file, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
}

// GetFilenameForService converts service name to filename (handles wildcards)
func GetFilenameForService(service string) string {
	return strings.ReplaceAll(service, "*", "wildcard")
}

// GetSubjectAndSANsForService determines the subject CN and SANs for a service
func GetSubjectAndSANsForService(service string) (string, []string) {
	if strings.HasPrefix(service, "*.") {
		baseDomain := service[2:]
		return baseDomain, []string{service, baseDomain}
	}
	return service, []string{service}
}
