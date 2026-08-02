package crypto

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestGenerateRootCAAndIssueCert(t *testing.T) {
	rootOpts := RootCAOptions{
		CommonName:   "Test Internal Root CA",
		Organization: "Test Org",
		OU:           "Test OU",
		Country:      "VN",
		State:        "Hanoi",
		Locality:     "Cau Giay",
		ValidYears:   100,
		KeyType:      "RSA4096",
	}

	rootCertPEM, rootKeyPEM, err := GenerateRootCA(rootOpts)
	if err != nil {
		t.Fatalf("GenerateRootCA failed: %v", err)
	}
	if rootCertPEM == "" || rootKeyPEM == "" {
		t.Fatal("Root cert or key PEM is empty")
	}

	block, _ := pem.Decode([]byte(rootCertPEM))
	if block == nil {
		t.Fatal("Failed to decode generated root cert PEM")
	}
	rootCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate failed: %v", err)
	}
	if !rootCert.IsCA {
		t.Fatal("Expected IsCA to be true for Root CA")
	}

	certOpts := InternalCertOptions{
		RootCertPEM:  rootCertPEM,
		RootKeyPEM:   rootKeyPEM,
		Domains:      []string{"*.internal.net", "api.internal.net", "192.168.1.50"},
		ValidYears:   50,
		Organization: "Test Org",
		OU:           "IT",
		Country:      "VN",
		State:        "Hanoi",
		Locality:     "Cau Giay",
		KeyType:      "RSA2048",
	}

	serverCertPEM, serverKeyPEM, err := IssueInternalCert(certOpts)
	if err != nil {
		t.Fatalf("IssueInternalCert failed: %v", err)
	}
	if serverCertPEM == "" || serverKeyPEM == "" {
		t.Fatal("Issued cert or key PEM is empty")
	}

	// Verify server cert signed by root cert
	serverBlock, _ := pem.Decode([]byte(serverCertPEM))
	if serverBlock == nil {
		t.Fatal("Failed to decode server cert PEM")
	}
	serverCert, err := x509.ParseCertificate(serverBlock.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate for server cert failed: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(rootCert)

	opts := x509.VerifyOptions{
		Roots:         roots,
		DNSName:       "api.internal.net",
		Intermediates: x509.NewCertPool(),
	}

	if _, err := serverCert.Verify(opts); err != nil {
		t.Fatalf("Failed to verify server cert against Root CA: %v", err)
	}
}
