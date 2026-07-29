package crypto

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"strings"
	"time"
)

type CertInfo struct {
	NotAfter          time.Time
	FingerprintSHA256 string
}

func ValidateAndParseCert(certPEM, keyPEM string) (*CertInfo, error) {
	certPEM = strings.TrimSpace(certPEM)
	keyPEM = strings.TrimSpace(keyPEM)

	if certPEM == "" {
		return nil, errors.New("certificate PEM content is empty")
	}
	if keyPEM == "" {
		return nil, errors.New("private key PEM content is empty")
	}

	// 1. Validate cert and key match
	_, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, errors.New("certificate and private key do not match: " + err.Error())
	}

	// 2. Parse X.509 certificate to extract NotAfter
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("failed to decode PEM block containing certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.New("failed to parse X.509 certificate: " + err.Error())
	}

	// 3. Compute SHA256 fingerprint of the certPEM content
	hash := sha256.Sum256([]byte(certPEM))
	fingerprint := hex.EncodeToString(hash[:])

	return &CertInfo{
		NotAfter:          cert.NotAfter,
		FingerprintSHA256: fingerprint,
	}, nil
}
