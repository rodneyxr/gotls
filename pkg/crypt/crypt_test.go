package crypt

import (
	"strings"
	"testing"
	"time"
)

func TestGenerateCACert(t *testing.T) {
	subject := "Test CA"
	pair, err := GenerateCACert(subject, 365*24*time.Hour)
	if err != nil {
		t.Fatalf("Failed to generate CA certificate: %v", err)
	}

	if pair.Cert.Subject.CommonName != subject {
		t.Errorf("Expected subject %s, got %s", subject, pair.Cert.Subject.CommonName)
	}

	if !pair.Cert.IsCA {
		t.Error("Generated certificate is not a CA certificate")
	}
}

func TestGenerateServerCert(t *testing.T) {
	// First generate CA
	caPair, err := GenerateCACert("Test CA", 365*24*time.Hour)
	if err != nil {
		t.Fatalf("Failed to generate CA certificate: %v", err)
	}

	// Then generate server cert
	subject := "test.example.com"
	sans := []string{"test.example.com", "api.test.example.com"}

	serverPair, err := GenerateServerCert(caPair, subject, sans, 365*24*time.Hour)
	if err != nil {
		t.Fatalf("Failed to generate server certificate: %v", err)
	}

	if serverPair.Cert.Subject.CommonName != subject {
		t.Errorf("Expected subject %s, got %s", subject, serverPair.Cert.Subject.CommonName)
	}

	if len(serverPair.Cert.DNSNames) != len(sans) {
		t.Errorf("Expected %d DNS names, got %d", len(sans), len(serverPair.Cert.DNSNames))
	}
}

func TestCertificatesUseConfiguredExpiry(t *testing.T) {
	const expiry = 730 * 24 * time.Hour

	before := time.Now().Add(expiry).Truncate(time.Second)
	caPair, err := GenerateCACert("Test CA", expiry)
	if err != nil {
		t.Fatalf("GenerateCACert() error = %v", err)
	}

	serverPair, err := GenerateServerCert(caPair, "test.example.com", nil, expiry)
	if err != nil {
		t.Fatalf("GenerateServerCert() error = %v", err)
	}
	after := time.Now().Add(expiry).Truncate(time.Second)

	for name, cert := range map[string]*CertificatePair{"CA": caPair, "server": serverPair} {
		if cert.Cert.NotAfter.Before(before) || cert.Cert.NotAfter.After(after) {
			t.Errorf("%s certificate expires at %s; want between %s and %s", name, cert.Cert.NotAfter, before, after)
		}
	}
}

func TestGenerateCertificatesRejectInvalidExpiry(t *testing.T) {
	if _, err := GenerateCACert("Test CA", 0); err == nil || !strings.Contains(err.Error(), "greater than zero") {
		t.Errorf("GenerateCACert() error = %v, want positive-expiry error", err)
	}

	caPair, err := GenerateCACert("Test CA", 24*time.Hour)
	if err != nil {
		t.Fatalf("GenerateCACert() error = %v", err)
	}

	if _, err := GenerateServerCert(caPair, "test.example.com", nil, -time.Hour); err == nil || !strings.Contains(err.Error(), "greater than zero") {
		t.Errorf("GenerateServerCert() error = %v, want positive-expiry error", err)
	}
}

func TestGetSubjectAndSANsForService(t *testing.T) {
	tests := []struct {
		service         string
		expectedSubject string
		expectedSANs    []string
	}{
		{
			service:         "example.com",
			expectedSubject: "example.com",
			expectedSANs:    []string{"example.com"},
		},
		{
			service:         "*.example.com",
			expectedSubject: "example.com",
			expectedSANs:    []string{"*.example.com", "example.com"},
		},
	}

	for _, test := range tests {
		subject, sans := GetSubjectAndSANsForService(test.service)
		if subject != test.expectedSubject {
			t.Errorf("For service %s, expected subject %s, got %s", test.service, test.expectedSubject, subject)
		}

		if len(sans) != len(test.expectedSANs) {
			t.Errorf("For service %s, expected %d SANs, got %d", test.service, len(test.expectedSANs), len(sans))
			continue
		}

		for i, san := range sans {
			if san != test.expectedSANs[i] {
				t.Errorf("For service %s, expected SAN %s, got %s", test.service, test.expectedSANs[i], san)
			}
		}
	}
}

func TestGetFilenameForService(t *testing.T) {
	tests := []struct {
		service  string
		expected string
	}{
		{"example.com", "example.com"},
		{"*.example.com", "wildcard.example.com"},
		{"api.*.example.com", "api.wildcard.example.com"},
	}

	for _, test := range tests {
		result := GetFilenameForService(test.service)
		if result != test.expected {
			t.Errorf("For service %s, expected filename %s, got %s", test.service, test.expected, result)
		}
	}
}
