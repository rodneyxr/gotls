package crypt

import (
	"testing"
)

func TestGenerateCACert(t *testing.T) {
	subject := "Test CA"
	pair, err := GenerateCACert(subject)
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
	caPair, err := GenerateCACert("Test CA")
	if err != nil {
		t.Fatalf("Failed to generate CA certificate: %v", err)
	}

	// Then generate server cert
	subject := "test.example.com"
	sans := []string{"test.example.com", "api.test.example.com"}

	serverPair, err := GenerateServerCert(caPair, subject, sans)
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
