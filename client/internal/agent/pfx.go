package agent

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

func parsePEMPrivateKey(keyPEM string) (interface{}, error) {
	var keyBlock *pem.Block
	rest := []byte(keyPEM)
	for {
		keyBlock, rest = pem.Decode(rest)
		if keyBlock == nil {
			break
		}
		if keyBlock.Type == "PRIVATE KEY" || keyBlock.Type == "RSA PRIVATE KEY" || keyBlock.Type == "EC PRIVATE KEY" {
			break
		}
	}
	if keyBlock == nil {
		return nil, errors.New("no valid private key block found in PEM")
	}

	if key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(keyBlock.Bytes); err == nil {
		return key, nil
	}

	return nil, errors.New("failed to parse private key block")
}

func parsePEMCertificate(certPEM string) (*x509.Certificate, []*x509.Certificate, error) {
	var leaf *x509.Certificate
	var caCerts []*x509.Certificate

	rest := []byte(certPEM)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err == nil {
				if leaf == nil {
					leaf = cert
				} else {
					caCerts = append(caCerts, cert)
				}
			}
		}
	}

	if leaf == nil {
		return nil, nil, errors.New("no valid certificate block found in PEM")
	}

	return leaf, caCerts, nil
}

func EncodePEMToPFX(certPEM, keyPEM, password string) ([]byte, error) {
	privKey, err := parsePEMPrivateKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}

	leafCert, caCerts, err := parsePEMCertificate(certPEM)
	if err != nil {
		return nil, fmt.Errorf("invalid certificate: %w", err)
	}

	pfxBytes, err := pkcs12.Encode(rand.Reader, privKey, leafCert, caCerts, password)
	if err != nil {
		return nil, fmt.Errorf("failed to encode legacy-compatible PFX: %w", err)
	}

	return pfxBytes, nil
}

func GetPFXCertSHA256(pfxPath, password string) (string, error) {
	data, err := os.ReadFile(pfxPath)
	if err != nil {
		return "", err
	}
	_, cert, err := pkcs12.Decode(data, password)
	if err != nil {
		_, cert, _, err = pkcs12.DecodeChain(data, password)
		if err != nil {
			return "", err
		}
	}
	if cert == nil {
		return "", errors.New("no certificate found in PFX")
	}
	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	return ComputeStringSHA256(string(pemBlock)), nil
}

func GetPFXCertNotAfter(pfxPath, password string) (*time.Time, error) {
	data, err := os.ReadFile(pfxPath)
	if err != nil {
		return nil, err
	}
	_, cert, err := pkcs12.Decode(data, password)
	if err != nil || cert == nil {
		_, cert, _, err = pkcs12.DecodeChain(data, password)
		if err != nil || cert == nil {
			return nil, fmt.Errorf("failed to decode PFX cert: %v", err)
		}
	}
	t := cert.NotAfter
	return &t, nil
}
