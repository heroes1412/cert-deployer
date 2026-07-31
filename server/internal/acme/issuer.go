package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"log"
	"strings"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/providers/dns/digitalocean"
	"github.com/go-acme/lego/v4/providers/dns/godaddy"
	"github.com/go-acme/lego/v4/providers/dns/route53"
	"github.com/go-acme/lego/v4/registration"
)

const (
	LetsEncryptProdURL    = "https://acme-v02.api.letsencrypt.org/directory"
	LetsEncryptStagingURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
	ZeroSSLURL            = "https://acme.zerossl.com/v2/DV90"
)

type ACMERequest struct {
	ServerCertName string
	Domains        []string
	ACMEProvider   string // "letsencrypt-prod", "letsencrypt-staging", "zerossl"
	DNSProvider    string // "cloudflare", "digitalocean", "route53", "godaddy"
	DNSAPIToken    string
	Email          string
	EABKID         string // For ZeroSSL
	EABHMACKey     string // For ZeroSSL
}

type ACMEResult struct {
	CertPEM string
	KeyPEM  string
}

func IssueCertificate(req ACMERequest) (*ACMEResult, error) {
	if len(req.Domains) == 0 {
		return nil, fmt.Errorf("at least one domain name is required")
	}

	// 1. Generate account private key (ECDSA P-256)
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate account private key: %w", err)
	}

	user := NewACMEUser(req.Email, privateKey)

	// 2. Select ACME Directory URL
	var cadir string
	switch req.ACMEProvider {
	case "zerossl":
		cadir = ZeroSSLURL
	case "letsencrypt-staging":
		cadir = LetsEncryptStagingURL
	default:
		cadir = LetsEncryptProdURL
	}

	config := lego.NewConfig(user)
	config.CADirURL = cadir
	config.Certificate.KeyType = certcrypto.RSA2048

	client, err := lego.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create lego ACME client: %w", err)
	}

	// 3. Configure DNS-01 Challenge Provider
	var provider challenge.Provider
	switch req.DNSProvider {
	case "cloudflare":
		cfCfg := cloudflare.NewDefaultConfig()
		cfCfg.AuthToken = req.DNSAPIToken
		provider, err = cloudflare.NewDNSProviderConfig(cfCfg)
	case "digitalocean":
		doCfg := digitalocean.NewDefaultConfig()
		doCfg.AuthToken = req.DNSAPIToken
		provider, err = digitalocean.NewDNSProviderConfig(doCfg)
	case "route53":
		r53Cfg := route53.NewDefaultConfig()
		provider, err = route53.NewDNSProviderConfig(r53Cfg)
	case "godaddy":
		gdCfg := godaddy.NewDefaultConfig()
		if parts := strings.SplitN(req.DNSAPIToken, ":", 2); len(parts) == 2 {
			gdCfg.APIKey = strings.TrimSpace(parts[0])
			gdCfg.APISecret = strings.TrimSpace(parts[1])
		} else {
			gdCfg.APIKey = req.DNSAPIToken
		}
		provider, err = godaddy.NewDNSProviderConfig(gdCfg)
	default:
		return nil, fmt.Errorf("unsupported DNS provider: %s", req.DNSProvider)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to initialize DNS provider %s: %w", req.DNSProvider, err)
	}

	err = client.Challenge.SetDNS01Provider(provider)
	if err != nil {
		return nil, fmt.Errorf("failed to set DNS-01 provider: %w", err)
	}

	// 4. Register ACME Account (Handle ZeroSSL EAB if applicable)
	if req.ACMEProvider == "zerossl" && req.EABKID != "" && req.EABHMACKey != "" {
		eabOpts := registration.RegisterEABOptions{
			TermsOfServiceAgreed: true,
			Kid:                  req.EABKID,
			HmacEncoded:          req.EABHMACKey,
		}
		reg, err := client.Registration.RegisterWithExternalAccountBinding(eabOpts)
		if err != nil {
			return nil, fmt.Errorf("failed ZeroSSL EAB registration: %w", err)
		}
		user.Registration = reg
	} else {
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, fmt.Errorf("failed ACME account registration: %w", err)
		}
		user.Registration = reg
	}

	// 5. Obtain Certificate
	request := certificate.ObtainRequest{
		Domains: req.Domains,
		Bundle:  true,
	}

	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain ACME certificate: %w", err)
	}

	log.Printf("[INFO] ACME Certificate successfully issued for %v via %s", req.Domains, req.ACMEProvider)

	return &ACMEResult{
		CertPEM: string(certificates.Certificate),
		KeyPEM:  string(certificates.PrivateKey),
	}, nil
}
