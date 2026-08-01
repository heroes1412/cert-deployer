package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"cert-server/internal/acme"
	"cert-server/internal/crypto"
	"cert-server/internal/db"
	"cert-server/internal/middleware"
	"cert-server/internal/models"
	"cert-server/internal/notifications"

	"github.com/gin-gonic/gin"
)

var validCertNameRegex = regexp.MustCompile(`^[a-zA-Z0-9 ._-]+$`)

func isValidCertName(name string) bool {
	if name == "" {
		return false
	}
	return validCertNameRegex.MatchString(name)
}

const (
	AdminUser         = "admin"
	DefaultAdminPass  = "admin123"
	SessionCookieName = "cert_server_session"
)

type CertViewModel struct {
	Name               string
	CertData           string
	KeyData            string
	SHA256             string
	SHA256Short        string
	SHA256Short5       string
	NotAfterISO        string
	NotAfterFormatted  string
	DaysRemaining      int
	IsExpired          bool
	IsWarning          bool
	UpdatedAtISO       string
	UpdatedAtFormatted string
	IsACME             bool
	ACMEProvider       string
	DNSProvider        string
	DNSAPIToken        string
	ACMEEmail          string
	Domains            string
	DomainsList        []string
	EABKID             string
	EABHMACKey         string
	AutoRenew          bool
}

type TokenViewModel struct {
	ID                 uint
	Token              string
	TokenMasked        string
	Description        string
	CreatedAtFormatted string
}

type AuditLogViewModel struct {
	ID                 uint
	IPAddress          string
	Action             string
	Details            string
	CreatedAtISO       string
	CreatedAtFormatted string
}

type AgentNodeViewModel struct {
	ID                uint
	Hostname          string
	IPAddress         string
	OSInfo            string
	SyncedCerts       string
	SyncedCertsList   []string
	LastSeenISO       string
	LastSeenFormatted string
	IsOnline          bool
}

func maskToken(token string) string {
	token = strings.TrimSpace(token)
	if len(token) <= 10 {
		return token
	}
	return token[:5] + "..." + token[len(token)-5:]
}

func generateSessionToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func ShowLogin(c *gin.Context) {
	currentPassHash := db.GetSetting("admin_password", "")
	isDefaultPass := db.CheckPassword(DefaultAdminPass, currentPassHash)
	c.HTML(http.StatusOK, "login.html", gin.H{
		"isDefaultPass": isDefaultPass,
	})
}

func ProcessLogin(c *gin.Context) {
	user := c.PostForm("username")
	pass := c.PostForm("password")

	currentPassHash := db.GetSetting("admin_password", "")

	if user == AdminUser && db.CheckPassword(pass, currentPassHash) {
		sessionToken := generateSessionToken()
		_ = db.SetSetting("active_session_token", sessionToken)
		c.SetSameSite(http.SameSiteLaxMode)
		c.SetCookie(SessionCookieName, sessionToken, 3600*24*365, "/", "", false, true)
		db.LogAudit(c.ClientIP(), "User Login", "Administrator signed in successfully")
		c.Redirect(http.StatusSeeOther, "/admin")
		return
	}

	isDefaultPass := db.CheckPassword(DefaultAdminPass, currentPassHash)
	c.HTML(http.StatusUnauthorized, "login.html", gin.H{
		"error":         "Invalid username or password",
		"isDefaultPass": isDefaultPass,
	})
}

func Logout(c *gin.Context) {
	_ = db.SetSetting("active_session_token", "")
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(SessionCookieName, "", -1, "/", "", false, true)
	c.Redirect(http.StatusSeeOther, "/login")
}

func WebAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		cookie, err := c.Cookie(SessionCookieName)
		activeToken := db.GetSetting("active_session_token", "")

		if err != nil || cookie == "" || activeToken == "" || cookie != activeToken {
			c.SetSameSite(http.SameSiteLaxMode)
			c.SetCookie(SessionCookieName, "", -1, "/", "", false, true)
			c.Redirect(http.StatusSeeOther, "/login")
			c.Abort()
			return
		}
		c.Next()
	}
}

func ShowDashboard(c *gin.Context) {
	msg := c.Query("msg")
	errMsg := c.Query("error")

	var certs []models.Certificate
	db.DB.Order("created_at desc").Find(&certs)

	now := time.Now()
	var certVMs []CertViewModel
	expiredCerts := 0
	expiringSoonCerts := 0
	activeACMECerts := 0

	for _, cert := range certs {
		domains := cert.Domains
		if domains == "" && cert.CertData != "" {
			domains = crypto.ExtractDomainsFromCertPEM(cert.CertData)
			if domains != "" {
				db.DB.Model(&models.Certificate{}).Where("id = ?", cert.ID).Update("domains", domains)
			}
		}

		daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
		isExpired := daysLeft < 0 || cert.NotAfter.Before(now)
		isWarning := !isExpired && daysLeft < 30

		if isExpired {
			expiredCerts++
		} else if daysLeft <= 15 {
			expiringSoonCerts++
		}

		if cert.IsACME {
			activeACMECerts++
		}

		shaShort := cert.FingerprintSHA256
		if len(shaShort) > 16 {
			shaShort = shaShort[:16] + "..."
		}
		sha5 := cert.FingerprintSHA256
		if len(sha5) > 5 {
			sha5 = sha5[:5] + "..."
		}

		var domainsList []string
		if domains != "" {
			parts := strings.Split(domains, ",")
			for _, p := range parts {
				p = strings.TrimSpace(p)
				if p != "" {
					domainsList = append(domainsList, p)
				}
			}
		}

		certVMs = append(certVMs, CertViewModel{
			Name:               cert.ServercertName,
			CertData:           cert.CertData,
			KeyData:            cert.KeyData,
			SHA256:             cert.FingerprintSHA256,
			SHA256Short:        shaShort,
			SHA256Short5:       sha5,
			NotAfterISO:        cert.NotAfter.Format(time.RFC3339),
			NotAfterFormatted:  cert.NotAfter.Format("2006-01-02 15:04:05"),
			DaysRemaining:      daysLeft,
			IsExpired:          isExpired,
			IsWarning:          isWarning,
			UpdatedAtISO:       cert.UpdatedAt.Format(time.RFC3339),
			UpdatedAtFormatted: cert.UpdatedAt.Format("2006-01-02 15:04:05"),
			IsACME:             cert.IsACME,
			ACMEProvider:       cert.ACMEProvider,
			DNSProvider:        cert.DNSProvider,
			DNSAPIToken:        cert.DNSAPIToken,
			ACMEEmail:          cert.ACMEEmail,
			Domains:            domains,
			DomainsList:        domainsList,
			EABKID:             cert.EABKID,
			EABHMACKey:         cert.EABHMACKey,
			AutoRenew:          cert.AutoRenew,
		})
	}

	var tokens []models.APIToken
	db.DB.Order("created_at desc").Find(&tokens)

	var tokenVMs []TokenViewModel
	for _, t := range tokens {
		tokenVMs = append(tokenVMs, TokenViewModel{
			ID:                 t.ID,
			Token:              t.Token,
			TokenMasked:        maskToken(t.Token),
			Description:        t.Description,
			CreatedAtFormatted: t.CreatedAt.Format("2006-01-02 15:04:05"),
		})
	}

	// Fetch Audit Logs (latest 50)
	var rawAuditLogs []models.AuditLog
	db.DB.Order("created_at desc").Limit(50).Find(&rawAuditLogs)
	var auditLogVMs []AuditLogViewModel
	for _, log := range rawAuditLogs {
		auditLogVMs = append(auditLogVMs, AuditLogViewModel{
			ID:                 log.ID,
			IPAddress:          log.IPAddress,
			Action:             log.Action,
			Details:            log.Details,
			CreatedAtISO:       log.CreatedAt.Format(time.RFC3339),
			CreatedAtFormatted: log.CreatedAt.Format("2006-01-02 15:04:05"),
		})
	}

	// Fetch Agent Nodes
	var rawAgentNodes []models.AgentNode
	db.DB.Order("last_seen_at desc").Find(&rawAgentNodes)
	var agentNodeVMs []AgentNodeViewModel
	for _, node := range rawAgentNodes {
		isOnline := time.Since(node.LastSeenAt) < 24*time.Hour
		var syncedList []string
		if node.SyncedCerts != "" {
			parts := strings.Split(node.SyncedCerts, ",")
			for _, p := range parts {
				p = strings.TrimSpace(p)
				if p != "" {
					syncedList = append(syncedList, p)
				}
			}
		}

		agentNodeVMs = append(agentNodeVMs, AgentNodeViewModel{
			ID:                node.ID,
			Hostname:          node.Hostname,
			IPAddress:         node.IPAddress,
			OSInfo:            node.OSInfo,
			SyncedCerts:       node.SyncedCerts,
			SyncedCertsList:   syncedList,
			LastSeenISO:       node.LastSeenAt.Format(time.RFC3339),
			LastSeenFormatted: node.LastSeenAt.Format("2006-01-02 15:04:05"),
			IsOnline:          isOnline,
		})
	}

	serverPort := db.GetSetting("server_port", "8080")

	c.HTML(http.StatusOK, "index.html", gin.H{
		"totalCerts":               len(certs),
		"expiredCerts":             expiredCerts,
		"expiringSoonCerts":        expiringSoonCerts,
		"activeACMECerts":           activeACMECerts,
		"certs":                    certVMs,
		"tokens":                   tokenVMs,
		"auditLogs":                auditLogVMs,
		"agentNodes":               agentNodeVMs,
		"serverPort":               serverPort,
		"msg":                      msg,
		"error":                    errMsg,
		"telegramBotToken":         db.GetSetting("telegram_bot_token", ""),
		"telegramChatID":           db.GetSetting("telegram_chat_id", ""),
		"slackWebhookURL":          db.GetSetting("slack_webhook_url", ""),
		"emailSMTPHost":            db.GetSetting("email_smtp_host", ""),
		"emailSMTPPort":            db.GetSetting("email_smtp_port", "587"),
		"emailSMTPUser":            db.GetSetting("email_smtp_user", ""),
		"emailSMTPPass":            db.GetSetting("email_smtp_pass", ""),
		"emailRecipient":           db.GetSetting("email_recipient", ""),
		"notifyWarningDays":        db.GetSetting("notify_warning_days", "15"),
		"notifyCheckIntervalHours": db.GetSetting("notify_check_interval_hours", "12"),
		"enableTelegram":           db.GetSetting("enable_telegram", "false") == "true",
		"enableSlack":              db.GetSetting("enable_slack", "false") == "true",
		"enableEmail":              db.GetSetting("enable_email", "false") == "true",
		"customWebhookURL":         db.GetSetting("custom_webhook_url", ""),
		"customWebhookSecret":      db.GetSetting("custom_webhook_secret", ""),
		"enableWebhook":            db.GetSetting("enable_webhook", "false") == "true",
		"enableProxy":              db.GetSetting("enable_proxy", "false") == "true",
		"proxyProtocol":            db.GetSetting("proxy_protocol", "http"),
		"proxyHost":                db.GetSetting("proxy_host", ""),
		"proxyPort":                db.GetSetting("proxy_port", "8080"),
		"enableProxyAuth":          db.GetSetting("enable_proxy_auth", "false") == "true",
		"proxyUser":                db.GetSetting("proxy_user", ""),
		"proxyPass":                db.GetSetting("proxy_pass", ""),
		"acmeDefaultEmail":            db.GetSetting("acme_default_email", ""),
		"acmeDefaultCloudflareToken":  db.GetSetting("acme_default_cloudflare_token", ""),
		"acmeDefaultDigitalOceanToken": db.GetSetting("acme_default_digitalocean_token", ""),
		"acmeDefaultRoute53Secret":    db.GetSetting("acme_default_route53_secret", ""),
		"acmeDefaultGoDaddyToken":     db.GetSetting("acme_default_godaddy_token", ""),
		"acmeDefaultZeroSSLKID":       db.GetSetting("acme_default_zerossl_kid", ""),
		"acmeDefaultZeroSSLHMAC":      db.GetSetting("acme_default_zerossl_hmac", ""),
	})
}

func SaveCertificate(c *gin.Context) {
	name := strings.TrimSpace(c.PostForm("servercert_name"))
	if !isValidCertName(name) {
		c.Redirect(http.StatusSeeOther, "/admin?error=Invalid+ServerCert+Name.+Only+letters,+numbers,+space,+dot+(.),+hyphen+(-),+and+underscore+(_)+are+allowed.")
		return
	}
	certPEM := c.PostForm("cert_data")
	keyPEM := c.PostForm("key_data")

	certInfo, err := crypto.ValidateAndParseCert(certPEM, keyPEM)
	if err != nil {
		c.Redirect(http.StatusSeeOther, "/admin?error="+err.Error())
		return
	}

	var existing models.Certificate
	result := db.DB.Where("servercert_name = ?", name).First(&existing)
	if result.Error == nil {
		// Update existing
		existing.CertData = certPEM
		existing.KeyData = keyPEM
		existing.FingerprintSHA256 = certInfo.FingerprintSHA256
		existing.NotAfter = certInfo.NotAfter
		existing.Domains = certInfo.Domains
		if existing.IsACME {
			existing.AutoRenew = true
			db.DB.Save(&existing)
			db.LogAudit(c.ClientIP(), "Update ACME Cert", fmt.Sprintf("Updated ACME certificate '%s'", name))
		} else {
			db.DB.Save(&existing)
			db.LogAudit(c.ClientIP(), "Update Manual Cert", fmt.Sprintf("Updated manual certificate '%s'", name))
		}
	} else {
		// Create new
		newCert := models.Certificate{
			ServercertName:    name,
			CertData:          certPEM,
			KeyData:           keyPEM,
			FingerprintSHA256: certInfo.FingerprintSHA256,
			NotAfter:          certInfo.NotAfter,
			Domains:           certInfo.Domains,
		}
		db.DB.Create(&newCert)
		db.LogAudit(c.ClientIP(), "Create Manual Cert", fmt.Sprintf("Created manual certificate '%s'", name))
	}

	c.Redirect(http.StatusSeeOther, "/admin?msg=Certificate+saved+successfully")
}

func DeleteCertificate(c *gin.Context) {
	name := c.PostForm("servercert_name")
	db.DB.Where("servercert_name = ?", name).Delete(&models.Certificate{})
	db.LogAudit(c.ClientIP(), "Delete Certificate", fmt.Sprintf("Deleted certificate '%s'", name))
	c.Redirect(http.StatusSeeOther, "/admin?msg=Certificate+deleted+successfully")
}

func GenerateAPIToken(c *gin.Context) {
	var count int64
	db.DB.Model(&models.APIToken{}).Count(&count)
	if count >= 1 {
		c.Redirect(http.StatusSeeOther, "/admin?error=An+API+token+already+exists.+Please+revoke+the+existing+token+first.")
		return
	}

	desc := c.PostForm("description")

	tokenBytes := make([]byte, 32)
	_, err := rand.Read(tokenBytes)
	if err != nil {
		c.Redirect(http.StatusSeeOther, "/admin?error=Failed+to+generate+token")
		return
	}

	rawToken := hex.EncodeToString(tokenBytes)
	tokenHash := middleware.HashToken(rawToken)

	newToken := models.APIToken{
		Token:       rawToken,
		TokenHash:   tokenHash,
		Description: desc,
	}
	db.DB.Create(&newToken)
	db.LogAudit(c.ClientIP(), "Generate API Token", fmt.Sprintf("Generated new API bearer token '%s'", desc))

	c.Redirect(http.StatusSeeOther, "/admin?msg=Token+generated+successfully")
}

func RevokeAPIToken(c *gin.Context) {
	idStr := c.PostForm("token_id")
	id, _ := strconv.Atoi(idStr)
	db.DB.Delete(&models.APIToken{}, id)
	db.LogAudit(c.ClientIP(), "Revoke API Token", fmt.Sprintf("Revoked API bearer token ID %d", id))
	c.Redirect(http.StatusSeeOther, "/admin?msg=Token+revoked")
}

func SaveSettings(c *gin.Context) {
	currentPass := c.PostForm("current_password")
	newPass := c.PostForm("new_password")
	confirmPass := c.PostForm("confirm_password")
	newPort := c.PostForm("server_port")

	msg := "Settings+saved+successfully"

	// 1. Handle Management Port Update
	if newPort != "" {
		portNum, err := strconv.Atoi(newPort)
		if err != nil || portNum < 1 || portNum > 65535 {
			c.Redirect(http.StatusSeeOther, "/admin?error=Invalid+server+port+number")
			return
		}
		oldPort := db.GetSetting("server_port", "8080")
		if oldPort != newPort {
			_ = db.SetSetting("server_port", newPort)
			msg = "Settings+saved!+Server+port+updated+to+" + newPort + "+(restart+required)"
		}
	}

	// 2. Handle Proxy Settings Update
	_ = db.SetSetting("proxy_protocol", c.PostForm("proxy_protocol"))
	_ = db.SetSetting("proxy_host", c.PostForm("proxy_host"))
	_ = db.SetSetting("proxy_port", c.PostForm("proxy_port"))
	_ = db.SetSetting("proxy_user", c.PostForm("proxy_user"))
	_ = db.SetSetting("proxy_pass", c.PostForm("proxy_pass"))

	if c.PostForm("enable_proxy") == "on" || c.PostForm("enable_proxy") == "true" {
		_ = db.SetSetting("enable_proxy", "true")
	} else {
		_ = db.SetSetting("enable_proxy", "false")
	}
	if c.PostForm("enable_proxy_auth") == "on" || c.PostForm("enable_proxy_auth") == "true" {
		_ = db.SetSetting("enable_proxy_auth", "true")
	} else {
		_ = db.SetSetting("enable_proxy_auth", "false")
	}

	// 3. Handle Notification Settings Update
	_ = db.SetSetting("telegram_bot_token", c.PostForm("telegram_bot_token"))
	_ = db.SetSetting("telegram_chat_id", c.PostForm("telegram_chat_id"))
	_ = db.SetSetting("slack_webhook_url", c.PostForm("slack_webhook_url"))
	_ = db.SetSetting("email_smtp_host", c.PostForm("email_smtp_host"))
	_ = db.SetSetting("email_smtp_port", c.PostForm("email_smtp_port"))
	_ = db.SetSetting("email_smtp_user", c.PostForm("email_smtp_user"))
	_ = db.SetSetting("email_smtp_pass", c.PostForm("email_smtp_pass"))
	_ = db.SetSetting("email_recipient", c.PostForm("email_recipient"))
	_ = db.SetSetting("notify_warning_days", c.PostForm("notify_warning_days"))
	_ = db.SetSetting("notify_check_interval_hours", c.PostForm("notify_check_interval_hours"))

	_ = db.SetSetting("custom_webhook_url", c.PostForm("custom_webhook_url"))
	_ = db.SetSetting("custom_webhook_secret", c.PostForm("custom_webhook_secret"))

	// 3. ACME Default Credentials Settings
	_ = db.SetSetting("acme_default_email", strings.TrimSpace(c.PostForm("acme_default_email")))
	_ = db.SetSetting("acme_default_cloudflare_token", strings.TrimSpace(c.PostForm("acme_default_cloudflare_token")))
	_ = db.SetSetting("acme_default_digitalocean_token", strings.TrimSpace(c.PostForm("acme_default_digitalocean_token")))
	_ = db.SetSetting("acme_default_route53_secret", strings.TrimSpace(c.PostForm("acme_default_route53_secret")))
	_ = db.SetSetting("acme_default_godaddy_token", strings.TrimSpace(c.PostForm("acme_default_godaddy_token")))
	_ = db.SetSetting("acme_default_zerossl_kid", strings.TrimSpace(c.PostForm("acme_default_zerossl_kid")))
	_ = db.SetSetting("acme_default_zerossl_hmac", strings.TrimSpace(c.PostForm("acme_default_zerossl_hmac")))

	if c.PostForm("enable_telegram") == "on" || c.PostForm("enable_telegram") == "true" {
		_ = db.SetSetting("enable_telegram", "true")
	} else {
		_ = db.SetSetting("enable_telegram", "false")
	}
	if c.PostForm("enable_slack") == "on" || c.PostForm("enable_slack") == "true" {
		_ = db.SetSetting("enable_slack", "true")
	} else {
		_ = db.SetSetting("enable_slack", "false")
	}
	if c.PostForm("enable_email") == "on" || c.PostForm("enable_email") == "true" {
		_ = db.SetSetting("enable_email", "true")
	} else {
		_ = db.SetSetting("enable_email", "false")
	}
	if c.PostForm("enable_webhook") == "on" || c.PostForm("enable_webhook") == "true" {
		_ = db.SetSetting("enable_webhook", "true")
	} else {
		_ = db.SetSetting("enable_webhook", "false")
	}

	// 4. Handle Password Change if requested
	if currentPass != "" || newPass != "" {
		dbPassHash := db.GetSetting("admin_password", "")
		if !db.CheckPassword(currentPass, dbPassHash) {
			c.Redirect(http.StatusSeeOther, "/admin?error=Current+password+is+incorrect")
			return
		}

		if newPass == "" || newPass != confirmPass {
			c.Redirect(http.StatusSeeOther, "/admin?error=New+passwords+do+not+match+or+are+empty")
			return
		}

		hashedNewPass, err := db.HashPassword(newPass)
		if err != nil || db.SetSetting("admin_password", hashedNewPass) != nil {
			c.Redirect(http.StatusSeeOther, "/admin?error=Failed+to+update+password")
			return
		}
	}

	db.LogAudit(c.ClientIP(), "Update Settings", "Updated system settings (Proxy, Notifications, ACME Config, or Password)")
	c.Redirect(http.StatusSeeOther, "/admin?msg="+msg)
}

func IssueACMECertificate(c *gin.Context) {
	name := strings.TrimSpace(c.PostForm("servercert_name"))
	if !isValidCertName(name) {
		c.Redirect(http.StatusSeeOther, "/admin?error=Invalid+ServerCert+Name.+Only+letters,+numbers,+space,+dot+(.),+hyphen+(-),+and+underscore+(_)+are+allowed.")
		return
	}
	domainStr := strings.TrimSpace(c.PostForm("domains"))
	acmeProvider := strings.TrimSpace(c.PostForm("acme_provider"))
	dnsProvider := strings.TrimSpace(c.PostForm("dns_provider"))
	dnsToken := strings.TrimSpace(c.PostForm("dns_api_token"))
	email := strings.TrimSpace(c.PostForm("email"))
	eabKid := strings.TrimSpace(c.PostForm("eab_kid"))
	eabHmac := strings.TrimSpace(c.PostForm("eab_hmac_key"))

	var existing models.Certificate
	hasExisting := db.DB.Where("servercert_name = ?", name).First(&existing).Error == nil

	// Resolution hierarchy:
	// 1. Form input (manual override or pre-filled from cert DB)
	// 2. Existing Certificate DB record (if renewing and form input left blank)
	// 3. System Settings ACME pre-configured defaults (if issuing new cert and form left blank)

	if email == "" {
		if hasExisting && existing.ACMEEmail != "" {
			email = existing.ACMEEmail
		} else {
			email = db.GetSetting("acme_default_email", "")
		}
	}
	if dnsToken == "" {
		if hasExisting && existing.DNSAPIToken != "" && (dnsProvider == "" || dnsProvider == existing.DNSProvider) {
			dnsToken = existing.DNSAPIToken
		} else {
			switch dnsProvider {
			case "cloudflare":
				dnsToken = db.GetSetting("acme_default_cloudflare_token", "")
			case "digitalocean":
				dnsToken = db.GetSetting("acme_default_digitalocean_token", "")
			case "route53":
				dnsToken = db.GetSetting("acme_default_route53_secret", "")
			case "godaddy":
				dnsToken = db.GetSetting("acme_default_godaddy_token", "")
			}
		}
	}
	if acmeProvider == "zerossl" {
		if eabKid == "" {
			if hasExisting && existing.EABKID != "" {
				eabKid = existing.EABKID
			} else {
				eabKid = db.GetSetting("acme_default_zerossl_kid", "")
			}
		}
		if eabHmac == "" {
			if hasExisting && existing.EABHMACKey != "" {
				eabHmac = existing.EABHMACKey
			} else {
				eabHmac = db.GetSetting("acme_default_zerossl_hmac", "")
			}
		}
	}

	if name == "" || domainStr == "" || dnsToken == "" || email == "" {
		c.Redirect(http.StatusSeeOther, "/admin?error=Please+fill+in+all+required+fields+(Name,+Domains,+Email,+DNS+Token)")
		return
	}

	domainList := strings.Split(domainStr, ",")
	var cleanedDomains []string
	for _, d := range domainList {
		d = strings.TrimSpace(d)
		if d != "" {
			cleanedDomains = append(cleanedDomains, d)
		}
	}

	req := acme.ACMERequest{
		ServerCertName: name,
		Domains:        cleanedDomains,
		ACMEProvider:   acmeProvider,
		DNSProvider:    dnsProvider,
		DNSAPIToken:    dnsToken,
		Email:          email,
		EABKID:         eabKid,
		EABHMACKey:     eabHmac,
	}

	// 1. Issue ACME Certificate via lego engine
	res, err := acme.IssueCertificate(req)
	if err != nil {
		c.Redirect(http.StatusSeeOther, "/admin?error=ACME+Issuance+Failed:+"+strings.ReplaceAll(err.Error(), " ", "+"))
		return
	}

	// 2. Parse X.509 cert info
	certInfo, err := crypto.ValidateAndParseCert(res.CertPEM, res.KeyPEM)
	if err != nil {
		c.Redirect(http.StatusSeeOther, "/admin?error=Failed+to+parse+issued+ACME+certificate")
		return
	}

	// 3. Save directly into SQLite Database
	domainsJoined := strings.Join(cleanedDomains, ", ")
	if hasExisting {
		existing.CertData = res.CertPEM
		existing.KeyData = res.KeyPEM
		existing.FingerprintSHA256 = certInfo.FingerprintSHA256
		existing.NotAfter = certInfo.NotAfter
		existing.IsACME = true
		existing.ACMEProvider = acmeProvider
		existing.DNSProvider = dnsProvider
		existing.DNSAPIToken = dnsToken
		existing.ACMEEmail = email
		existing.Domains = domainsJoined
		existing.EABKID = eabKid
		existing.EABHMACKey = eabHmac
		existing.AutoRenew = true
		db.DB.Save(&existing)
	} else {
		newCert := models.Certificate{
			ServercertName:    name,
			CertData:          res.CertPEM,
			KeyData:           res.KeyPEM,
			FingerprintSHA256: certInfo.FingerprintSHA256,
			NotAfter:          certInfo.NotAfter,
			IsACME:            true,
			ACMEProvider:      acmeProvider,
			DNSProvider:       dnsProvider,
			DNSAPIToken:       dnsToken,
			ACMEEmail:          email,
			Domains:           domainsJoined,
			EABKID:            eabKid,
			EABHMACKey:        eabHmac,
			AutoRenew:         true,
		}
		db.DB.Create(&newCert)
	}

	db.LogAudit(c.ClientIP(), "Issue ACME Cert", fmt.Sprintf("Successfully issued ACME certificate '%s' via %s", name, acmeProvider))
	c.Redirect(http.StatusSeeOther, "/admin?msg=ACME+Certificate+successfully+issued+and+saved+for+"+name)
}

func CheckCertName(c *gin.Context) {
	name := strings.TrimSpace(c.Query("name"))
	if name == "" {
		c.JSON(http.StatusOK, gin.H{"exists": false, "invalid": false})
		return
	}
	if !isValidCertName(name) {
		c.JSON(http.StatusOK, gin.H{"exists": false, "invalid": true, "message": "Only letters, numbers, space, dot (.), hyphen (-), and underscore (_) are allowed!"})
		return
	}
	var existing models.Certificate
	err := db.DB.Where("servercert_name = ?", name).First(&existing).Error
	c.JSON(http.StatusOK, gin.H{"exists": err == nil, "invalid": false})
}

func TestNotification(c *gin.Context) {
	channel := c.PostForm("channel")
	switch channel {
	case "telegram":
		token := c.PostForm("telegram_bot_token")
		chatID := c.PostForm("telegram_chat_id")
		err := notifications.TestTelegram(token, chatID)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{"success": false, "message": err.Error()})
			return
		}
	case "slack":
		url := c.PostForm("slack_webhook_url")
		err := notifications.TestSlack(url)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{"success": false, "message": err.Error()})
			return
		}
	case "webhook":
		url := c.PostForm("custom_webhook_url")
		secret := c.PostForm("custom_webhook_secret")
		err := notifications.TestCustomWebhook(url, secret)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{"success": false, "message": err.Error()})
			return
		}
	case "email":
		host := c.PostForm("email_smtp_host")
		port := c.PostForm("email_smtp_port")
		user := c.PostForm("email_smtp_user")
		pass := c.PostForm("email_smtp_pass")
		to := c.PostForm("email_recipient")
		err := notifications.TestEmail(host, port, user, pass, to)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{"success": false, "message": err.Error()})
			return
		}
	default:
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Unknown notification channel"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "Test notification sent successfully!"})
}
