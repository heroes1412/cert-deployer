package acme

import (
	"log"
	"strings"
	"time"

	"cert-server/internal/crypto"
	"cert-server/internal/db"
	"cert-server/internal/models"
)

// StartAutoRenewScheduler starts a background ticker that checks ACME certificates
// and automatically re-issues them if they are within 15 days of expiration.
func StartAutoRenewScheduler() {
	go func() {
		// Run initial check after 10 seconds, then tick every 12 hours
		time.Sleep(10 * time.Second)
		log.Println("[INFO] ACME Auto-Renew Background Scheduler initialized (12h interval)")

		ticker := time.NewTicker(12 * time.Hour)
		defer ticker.Stop()

		for {
			runAutoRenewCheck()
			<-ticker.C
		}
	}()
}

func runAutoRenewCheck() {
	var acmeCerts []models.Certificate
	if err := db.DB.Where("is_acme = ? AND auto_renew = ?", true, true).Find(&acmeCerts).Error; err != nil {
		log.Printf("[ERROR] Failed to query ACME certificates for auto-renew: %v", err)
		return
	}

	for _, cert := range acmeCerts {
		daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
		if daysLeft > 15 {
			continue
		}

		log.Printf("[INFO] [ACME Auto-Renew] Certificate '%s' has %d days remaining (<= 15 days threshold). Triggering auto-renewal...", cert.ServercertName, daysLeft)

		domainList := strings.Split(cert.Domains, ",")
		var cleanedDomains []string
		for _, d := range domainList {
			d = strings.TrimSpace(d)
			if d != "" {
				cleanedDomains = append(cleanedDomains, d)
			}
		}

		if len(cleanedDomains) == 0 {
			log.Printf("[ERROR] [ACME Auto-Renew] Certificate '%s' has no domains specified. Skipping...", cert.ServercertName)
			continue
		}

		req := ACMERequest{
			ServerCertName: cert.ServercertName,
			Domains:        cleanedDomains,
			ACMEProvider:   cert.ACMEProvider,
			DNSProvider:    cert.DNSProvider,
			DNSAPIToken:    cert.DNSAPIToken,
			Email:          cert.ACMEEmail,
			EABKID:         cert.EABKID,
			EABHMACKey:     cert.EABHMACKey,
		}

		res, err := IssueCertificate(req)
		if err != nil {
			log.Printf("[ERROR] [ACME Auto-Renew] Failed to re-issue ACME cert for '%s': %v", cert.ServercertName, err)
			continue
		}

		certInfo, err := crypto.ValidateAndParseCert(res.CertPEM, res.KeyPEM)
		if err != nil {
			log.Printf("[ERROR] [ACME Auto-Renew] Failed to parse re-issued ACME cert for '%s': %v", cert.ServercertName, err)
			continue
		}

		cert.CertData = res.CertPEM
		cert.KeyData = res.KeyPEM
		cert.FingerprintSHA256 = certInfo.FingerprintSHA256
		cert.NotAfter = certInfo.NotAfter
		if err := db.DB.Save(&cert).Error; err != nil {
			log.Printf("[ERROR] [ACME Auto-Renew] Failed to update DB for '%s': %v", cert.ServercertName, err)
		} else {
			log.Printf("[SUCCESS] [ACME Auto-Renew] Certificate '%s' successfully renewed! New expiration: %s", cert.ServercertName, cert.NotAfter.Format("2006-01-02 15:04:05 UTC"))
		}
	}
}
