package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"cert-server/internal/crypto"
	"cert-server/internal/db"
	"cert-server/internal/middleware"
	"cert-server/internal/models"

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
	db.DB.Order("updated_at desc").Find(&certs)

	now := time.Now()
	var certVMs []CertViewModel
	for _, cert := range certs {
		daysLeft := int(math.Ceil(cert.NotAfter.Sub(now).Hours() / 24))
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
		"certs":      certVMs,
		"tokens":     tokenVMs,
		"serverPort": serverPort,
		"msg":        msg,
		"error":      errMsg,
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
	c.Redirect(http.StatusSeeOther, "/admin?msg=Certificate+deleted")
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
	newPort := c.PostForm("server_port")
	currentPass := c.PostForm("current_password")
	newPass := c.PostForm("new_password")
	confirmPass := c.PostForm("confirm_password")

	msg := "Settings+saved+successfully!"

	// 1. Handle Server Port Update
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

	// 2. Handle Password Change if requested
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
