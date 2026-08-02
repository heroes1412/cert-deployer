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
	Domains           string
	SubjectCN         string
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

	// 2. Parse X.509 certificate (iterates through fullchain to locate leaf CERTIFICATE)
	var certBlock *pem.Block
	rest := []byte(certPEM)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			certBlock = block
			break
		}
	}

	if certBlock == nil {
		return nil, errors.New("failed to decode PEM block containing certificate")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, errors.New("failed to parse X.509 certificate: " + err.Error())
	}

	// 3. Compute SHA256 fingerprint of the certPEM content
	hash := sha256.Sum256([]byte(certPEM))
	fingerprint := hex.EncodeToString(hash[:])

	// 4. Extract Subject CommonName and Subject Alternative Names (SANs)
	domainMap := make(map[string]bool)
	var domainsList []string
	if cert.Subject.CommonName != "" {
		cn := strings.TrimSpace(cert.Subject.CommonName)
		domainMap[cn] = true
		domainsList = append(domainsList, cn)
	}
	for _, san := range cert.DNSNames {
		san = strings.TrimSpace(san)
		if san != "" && !domainMap[san] {
			domainMap[san] = true
			domainsList = append(domainsList, san)
		}
	}
	domainsStr := strings.Join(domainsList, ", ")

	return &CertInfo{
		NotAfter:          cert.NotAfter,
		FingerprintSHA256: fingerprint,
		Domains:           domainsStr,
		SubjectCN:         cert.Subject.CommonName,
	}, nil
}

func ExtractDomainsFromCertPEM(certPEM string) string {
	certPEM = strings.TrimSpace(certPEM)
	if certPEM == "" {
		return ""
	}

	var certBlock *pem.Block
	rest := []byte(certPEM)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			certBlock = block
			break
		}
	}

	if certBlock == nil {
		return ""
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return ""
	}

	domainMap := make(map[string]bool)
	var domainsList []string
	if cert.Subject.CommonName != "" {
		cn := strings.TrimSpace(cert.Subject.CommonName)
		domainMap[cn] = true
		domainsList = append(domainsList, cn)
	}
	for _, san := range cert.DNSNames {
		san = strings.TrimSpace(san)
		if san != "" && !domainMap[san] {
			domainMap[san] = true
			domainsList = append(domainsList, san)
		}
	}
	return strings.Join(domainsList, ", ")
}
