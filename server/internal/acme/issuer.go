package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"cert-server/internal/db"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/providers/dns/digitalocean"
	"github.com/go-acme/lego/v4/providers/dns/godaddy"
	"github.com/go-acme/lego/v4/providers/dns/route53"
	"github.com/go-acme/lego/v4/providers/dns/vultr"
	"github.com/go-acme/lego/v4/registration"
)

type zeroSSLEABResponse struct {
	Success    bool   `json:"success"`
	EABKID     string `json:"eab_kid"`
	EABHMACKey string `json:"eab_hmac_key"`
	Error      struct {
		Code int    `json:"code"`
		Type string `json:"type"`
	} `json:"error"`
}

var acmeSharedTransport = &http.Transport{
	Proxy: func(req *http.Request) (*url.URL, error) {
		if proxyURLStr := db.GetConstructedProxyURL(); proxyURLStr != "" {
			return url.Parse(proxyURLStr)
		}
		return nil, nil
	},
	MaxIdleConns:        50,
	MaxIdleConnsPerHost: 5,
	IdleConnTimeout:     90 * time.Second,
}

var acmeSharedHTTPClient = &http.Client{
	Timeout:   15 * time.Second,
	Transport: acmeSharedTransport,
}

type FreeDNSProvider struct {
	token string
}

func NewFreeDNSProvider(token string) *FreeDNSProvider {
	return &FreeDNSProvider{token: token}
}

func (p *FreeDNSProvider) Present(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	reqURL := fmt.Sprintf("https://freedns.afraid.org/api/?action=set_txt&token=%s&host=%s&value=%s",
		url.QueryEscape(p.token),
		url.QueryEscape(info.FQDN),
		url.QueryEscape(info.Value),
	)
	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: acmeSharedTransport,
	}
	resp, err := client.Get(reqURL)
	if err != nil {
		return fmt.Errorf("freedns API request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("freedns API returned HTTP status %d", resp.StatusCode)
	}
	return nil
}

func (p *FreeDNSProvider) CleanUp(domain, token, keyAuth string) error {
	return nil
}

func fetchZeroSSLEABFromAPIKey(apiKey string) (string, string, error) {
	apiURL := fmt.Sprintf("https://api.zerossl.com/acme/eab-credentials?access_key=%s", url.QueryEscape(apiKey))
	resp, err := acmeSharedHTTPClient.Post(apiURL, "application/json", nil)
	if err != nil {
		return "", "", fmt.Errorf("failed to call ZeroSSL API: %w", err)
	}
	defer resp.Body.Close()

	var res zeroSSLEABResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return "", "", fmt.Errorf("failed to parse ZeroSSL EAB response: %w", err)
	}

	if !res.Success || res.EABKID == "" || res.EABHMACKey == "" {
		return "", "", fmt.Errorf("ZeroSSL API returned error (code %d: %s)", res.Error.Code, res.Error.Type)
	}

	return res.EABKID, res.EABHMACKey, nil
}

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

	// Configure HTTP/HTTPS/SOCKS5 Proxy if enabled
	if proxyURLStr := db.GetConstructedProxyURL(); proxyURLStr != "" {
		proxyURL, err := url.Parse(proxyURLStr)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL '%s': %w", proxyURLStr, err)
		}
		customTransport := &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		}
		config.HTTPClient = &http.Client{
			Transport: customTransport,
			Timeout:   60 * time.Second,
		}
		os.Setenv("HTTP_PROXY", proxyURLStr)
		os.Setenv("HTTPS_PROXY", proxyURLStr)
		os.Setenv("http_proxy", proxyURLStr)
		os.Setenv("https_proxy", proxyURLStr)
		log.Printf("[INFO] [ACME Issuer] Using HTTP/HTTPS Proxy: %s", proxyURLStr)
	}

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
	case "vultr":
		vCfg := vultr.NewDefaultConfig()
		vCfg.APIKey = req.DNSAPIToken
		provider, err = vultr.NewDNSProviderConfig(vCfg)
	case "freedns":
		provider = NewFreeDNSProvider(req.DNSAPIToken)
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

	// 4. Register ACME Account (Handle ZeroSSL EAB / API Key if applicable)
	if req.ACMEProvider == "zerossl" {
		kid := strings.TrimSpace(req.EABKID)
		hmacKey := strings.TrimSpace(req.EABHMACKey)

		// If user entered ZeroSSL API Key in EABKID (or left HMACKey empty), fetch EAB KID & HMAC via API Key
		if hmacKey == "" && kid != "" {
			fetchedKID, fetchedHMAC, err := fetchZeroSSLEABFromAPIKey(kid)
			if err != nil {
				return nil, fmt.Errorf("failed to fetch ZeroSSL EAB credentials using API Key: %w", err)
			}
			kid = fetchedKID
			hmacKey = fetchedHMAC
			log.Printf("[INFO] [ACME Issuer] Successfully retrieved ZeroSSL EAB KID & HMAC Key using ZeroSSL API Key")
		}

		if kid != "" && hmacKey != "" {
			eabOpts := registration.RegisterEABOptions{
				TermsOfServiceAgreed: true,
				Kid:                  kid,
				HmacEncoded:          hmacKey,
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
