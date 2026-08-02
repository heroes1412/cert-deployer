package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"strings"
	"time"
)

type RootCAOptions struct {
	CommonName   string `json:"common_name"`
	Organization string `json:"organization"`
	OU           string `json:"ou"`
	Country      string `json:"country"`
	State        string `json:"state"`
	Locality     string `json:"locality"`
	ValidYears   int    `json:"valid_years"`
	KeyType      string `json:"key_type"` // RSA2048, RSA4096, ECDSA256
}

type InternalCertOptions struct {
	RootCertPEM  string   `json:"root_cert_pem"`
	RootKeyPEM   string   `json:"root_key_pem"`
	Domains      []string `json:"domains"`
	ValidYears   int      `json:"valid_years"`
	Organization string   `json:"organization"`
	OU           string   `json:"ou"`
	Country      string   `json:"country"`
	State        string   `json:"state"`
	Locality     string   `json:"locality"`
	KeyType      string   `json:"key_type"`
}

func generateKeyPair(keyType string) (any, []byte, error) {
	switch strings.ToUpper(keyType) {
	case "ECDSA256", "ECDSA-P256", "P256":
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		der, err := x509.MarshalECPrivateKey(priv)
		if err != nil {
			return nil, nil, err
		}
		pemBlock := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
		return priv, pemBlock, nil
	case "RSA2048":
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, nil, err
		}
		der := x509.MarshalPKCS1PrivateKey(priv)
		pemBlock := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
		return priv, pemBlock, nil
	default: // Default RSA4096
		priv, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return nil, nil, err
		}
		der := x509.MarshalPKCS1PrivateKey(priv)
		pemBlock := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
		return priv, pemBlock, nil
	}
}

func parsePrivateKeyPEM(keyPEM string) (any, error) {
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return nil, errors.New("failed to decode private key PEM")
	}

	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, errors.New("unsupported private key format")
}

func GenerateRootCA(opts RootCAOptions) (string, string, error) {
	if opts.ValidYears <= 0 {
		opts.ValidYears = 100
	}
	if opts.CommonName == "" {
		opts.CommonName = "Internal Root CA"
	}

	privKey, keyPEM, err := generateKeyPair(opts.KeyType)
	if err != nil {
		return "", "", err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return "", "", err
	}

	subject := pkix.Name{
		CommonName: opts.CommonName,
	}
	if opts.Organization != "" {
		subject.Organization = []string{opts.Organization}
	}
	if opts.OU != "" {
		subject.OrganizationalUnit = []string{opts.OU}
	}
	if opts.Country != "" {
		subject.Country = []string{opts.Country}
	}
	if opts.State != "" {
		subject.Province = []string{opts.State}
	}
	if opts.Locality != "" {
		subject.Locality = []string{opts.Locality}
	}

	notBefore := time.Now().Add(-5 * time.Minute)
	notAfter := time.Now().AddDate(opts.ValidYears, 0, 0)

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}

	var pubKey any
	switch k := privKey.(type) {
	case *rsa.PrivateKey:
		pubKey = &k.PublicKey
	case *ecdsa.PrivateKey:
		pubKey = &k.PublicKey
	default:
		return "", "", errors.New("invalid private key type")
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, pubKey, privKey)
	if err != nil {
		return "", "", err
	}

	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	return certPEM, string(keyPEM), nil
}

func IssueInternalCert(opts InternalCertOptions) (string, string, error) {
	if opts.ValidYears <= 0 {
		opts.ValidYears = 50
	}
	if len(opts.Domains) == 0 {
		return "", "", errors.New("at least one domain or IP is required")
	}

	// Parse Root CA cert
	rootBlock, _ := pem.Decode([]byte(opts.RootCertPEM))
	if rootBlock == nil {
		return "", "", errors.New("invalid Root CA certificate PEM")
	}
	rootCert, err := x509.ParseCertificate(rootBlock.Bytes)
	if err != nil {
		return "", "", err
	}

	// Parse Root CA private key
	rootKey, err := parsePrivateKeyPEM(opts.RootKeyPEM)
	if err != nil {
		return "", "", err
	}

	// Generate Server Key Pair
	serverPrivKey, serverKeyPEM, err := generateKeyPair(opts.KeyType)
	if err != nil {
		return "", "", err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return "", "", err
	}

	var dnsNames []string
	var ipAddresses []net.IP

	for _, domain := range opts.Domains {
		domain = strings.TrimSpace(domain)
		if domain == "" {
			continue
		}
		if ip := net.ParseIP(domain); ip != nil {
			ipAddresses = append(ipAddresses, ip)
		} else {
			dnsNames = append(dnsNames, domain)
		}
	}

	commonName := ""
	if len(dnsNames) > 0 {
		commonName = dnsNames[0]
	} else if len(ipAddresses) > 0 {
		commonName = ipAddresses[0].String()
	}

	subject := pkix.Name{
		CommonName: commonName,
	}
	if opts.Organization != "" {
		subject.Organization = []string{opts.Organization}
	}
	if opts.OU != "" {
		subject.OrganizationalUnit = []string{opts.OU}
	}
	if opts.Country != "" {
		subject.Country = []string{opts.Country}
	}
	if opts.State != "" {
		subject.Province = []string{opts.State}
	}
	if opts.Locality != "" {
		subject.Locality = []string{opts.Locality}
	}

	notBefore := time.Now().Add(-5 * time.Minute)
	notAfter := time.Now().AddDate(opts.ValidYears, 0, 0)

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              dnsNames,
		IPAddresses:           ipAddresses,
	}

	var serverPubKey any
	switch k := serverPrivKey.(type) {
	case *rsa.PrivateKey:
		serverPubKey = &k.PublicKey
	case *ecdsa.PrivateKey:
		serverPubKey = &k.PublicKey
	default:
		return "", "", errors.New("invalid server private key type")
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, rootCert, serverPubKey, rootKey)
	if err != nil {
		return "", "", err
	}

	serverCertPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	// Append Root CA cert to form full chain
	fullChainPEM := serverCertPEM + "\n" + strings.TrimSpace(opts.RootCertPEM) + "\n"

	return fullChainPEM, string(serverKeyPEM), nil
}
