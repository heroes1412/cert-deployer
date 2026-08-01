package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
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

const (
	AdminUser         = "admin"
	DefaultAdminPass  = "admin123"
	SessionCookieName = "cert_vault_session"
)

type CertViewModel struct {
	Name               string
	CertData           string
	KeyData            string
	SHA256             string
	SHA256Short        string
	NotAfterFormatted  string
	DaysRemaining      int
	IsExpired          bool
	IsWarning          bool
	UpdatedAtFormatted string
	IsACME             bool
	ACMEProvider       string
	DNSProvider        string
	DNSAPIToken        string
	ACMEEmail          string
	Domains            string
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

func maskToken(token string) string {
	token = strings.TrimSpace(token)
	if len(token) <= 10 {
		return token
	}
	return token[:5] + "..." + token[len(token)-5:]
}

func ShowLogin(c *gin.Context) {
	c.HTML(http.StatusOK, "login.html", gin.H{})
}

func ProcessLogin(c *gin.Context) {
	user := c.PostForm("username")
	pass := c.PostForm("password")

	currentPass := db.GetSetting("admin_password", DefaultAdminPass)

	if user == AdminUser && pass == currentPass {
		c.SetCookie(SessionCookieName, "valid_session", 3600*24, "/", "", false, true)
		c.Redirect(http.StatusSeeOther, "/admin")
		return
	}

	c.HTML(http.StatusUnauthorized, "login.html", gin.H{
		"error": "Invalid username or password",
	})
}

func Logout(c *gin.Context) {
	c.SetCookie(SessionCookieName, "", -1, "/", "", false, true)
	c.Redirect(http.StatusSeeOther, "/login")
}

func WebAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		cookie, err := c.Cookie(SessionCookieName)
		if err != nil || cookie != "valid_session" {
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
	for _, cert := range certs {
		daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
		shaShort := cert.FingerprintSHA256
		if len(shaShort) > 16 {
			shaShort = shaShort[:16] + "..."
		}
		isExpired := daysLeft < 0 || cert.NotAfter.Before(now)
		isWarning := !isExpired && daysLeft < 30

		certVMs = append(certVMs, CertViewModel{
			Name:               cert.ServercertName,
			CertData:           cert.CertData,
			KeyData:            cert.KeyData,
			SHA256:             cert.FingerprintSHA256,
			SHA256Short:        shaShort,
			NotAfterFormatted:  cert.NotAfter.Format("2006-01-02 15:04:05 UTC"),
			DaysRemaining:      daysLeft,
			IsExpired:          isExpired,
			IsWarning:          isWarning,
			UpdatedAtFormatted: cert.UpdatedAt.Format("2006-01-02 15:04:05"),
			IsACME:             cert.IsACME,
			ACMEProvider:       cert.ACMEProvider,
			DNSProvider:        cert.DNSProvider,
			DNSAPIToken:        cert.DNSAPIToken,
			ACMEEmail:          cert.ACMEEmail,
			Domains:            cert.Domains,
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

	serverPort := db.GetSetting("server_port", "8080")

	c.HTML(http.StatusOK, "index.html", gin.H{
		"certs":                    certVMs,
		"tokens":                   tokenVMs,
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
	})
}

func SaveCertificate(c *gin.Context) {
	name := c.PostForm("servercert_name")
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
		db.DB.Save(&existing)
	} else {
		// Create new
		newCert := models.Certificate{
			ServercertName:    name,
			CertData:          certPEM,
			KeyData:           keyPEM,
			FingerprintSHA256: certInfo.FingerprintSHA256,
			NotAfter:          certInfo.NotAfter,
		}
		db.DB.Create(&newCert)
	}

	c.Redirect(http.StatusSeeOther, "/admin?msg=Certificate+saved+successfully")
}

func DeleteCertificate(c *gin.Context) {
	name := c.PostForm("servercert_name")
	db.DB.Where("servercert_name = ?", name).Delete(&models.Certificate{})
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

	c.Redirect(http.StatusSeeOther, "/admin?msg=Token+generated+successfully")
}

func RevokeAPIToken(c *gin.Context) {
	idStr := c.PostForm("token_id")
	id, _ := strconv.Atoi(idStr)
	db.DB.Delete(&models.APIToken{}, id)
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

	// 3. Handle Password Change if requested
	if currentPass != "" || newPass != "" {
		dbPass := db.GetSetting("admin_password", DefaultAdminPass)
		if currentPass != dbPass {
			c.Redirect(http.StatusSeeOther, "/admin?error=Current+password+is+incorrect")
			return
		}

		if newPass == "" || newPass != confirmPass {
			c.Redirect(http.StatusSeeOther, "/admin?error=New+passwords+do+not+match+or+are+empty")
			return
		}

		if err := db.SetSetting("admin_password", newPass); err != nil {
			c.Redirect(http.StatusSeeOther, "/admin?error=Failed+to+update+password")
			return
		}
	}

	c.Redirect(http.StatusSeeOther, "/admin?msg="+msg)
}

func IssueACMECertificate(c *gin.Context) {
	name := strings.TrimSpace(c.PostForm("servercert_name"))
	domainStr := strings.TrimSpace(c.PostForm("domains"))
	acmeProvider := strings.TrimSpace(c.PostForm("acme_provider"))
	dnsProvider := strings.TrimSpace(c.PostForm("dns_provider"))
	dnsToken := strings.TrimSpace(c.PostForm("dns_api_token"))
	email := strings.TrimSpace(c.PostForm("email"))
	eabKid := strings.TrimSpace(c.PostForm("eab_kid"))
	eabHmac := strings.TrimSpace(c.PostForm("eab_hmac_key"))

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
	var existing models.Certificate
	if err := db.DB.Where("servercert_name = ?", name).First(&existing).Error; err == nil {
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

	c.Redirect(http.StatusSeeOther, "/admin?msg=ACME+Certificate+successfully+issued+and+saved+for+"+name)
}

func CheckCertName(c *gin.Context) {
	name := strings.TrimSpace(c.Query("name"))
	if name == "" {
		c.JSON(http.StatusOK, gin.H{"exists": false})
		return
	}
	var existing models.Certificate
	err := db.DB.Where("servercert_name = ?", name).First(&existing).Error
	c.JSON(http.StatusOK, gin.H{"exists": err == nil})
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
