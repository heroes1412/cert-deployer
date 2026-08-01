package notifications

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/smtp"
	"net/url"
	"strconv"
	"strings"
	"time"

	"cert-server/internal/db"
	"cert-server/internal/models"
)

var (
	sharedTransport = &http.Transport{
		Proxy: func(req *http.Request) (*url.URL, error) {
			if proxyURLStr := db.GetConstructedProxyURL(); proxyURLStr != "" {
				return url.Parse(proxyURLStr)
			}
			return nil, nil
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}
	sharedHTTPClient = &http.Client{
		Timeout:   15 * time.Second,
		Transport: sharedTransport,
	}
)

func getHTTPClientWithProxy() *http.Client {
	return sharedHTTPClient
}

// StartNotificationScheduler initializes the automated background scanner
// that checks certificate expiration and sends alerts across enabled channels.
func StartNotificationScheduler() {
	go func() {
		time.Sleep(15 * time.Second)
		log.Println("[INFO] Notification Background Scheduler initialized")

		for {
			intervalHoursStr := db.GetSetting("notify_check_interval_hours", "12")
			intervalHours, err := strconv.Atoi(intervalHoursStr)
			if err != nil || intervalHours < 1 {
				intervalHours = 12
			}

			RunNotificationCheck()

			time.Sleep(time.Duration(intervalHours) * time.Hour)
		}
	}()
}

func RunNotificationCheck() {
	warningDaysStr := db.GetSetting("notify_warning_days", "15")
	warningDays, err := strconv.Atoi(warningDaysStr)
	if err != nil || warningDays < 1 {
		warningDays = 15
	}

	var certs []models.Certificate
	if err := db.DB.Find(&certs).Error; err != nil {
		log.Printf("[ERROR] [Notification Scheduler] Failed to query certs: %v", err)
		return
	}

	var warningCerts []models.Certificate
	for _, cert := range certs {
		daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
		if daysLeft <= warningDays {
			warningCerts = append(warningCerts, cert)
		}
	}

	if len(warningCerts) == 0 {
		return
	}

	enableTelegram := db.GetSetting("enable_telegram", "false") == "true"
	enableSlack := db.GetSetting("enable_slack", "false") == "true"
	enableWebhook := db.GetSetting("enable_webhook", "false") == "true"
	enableEmail := db.GetSetting("enable_email", "false") == "true"

	if !enableTelegram && !enableSlack && !enableWebhook && !enableEmail {
		return
	}

	log.Printf("[INFO] [Notification Scheduler] Found %d certificate(s) expiring within %d days. Sending alerts...", len(warningCerts), warningDays)

	if enableTelegram {
		sendTelegramAlert(warningCerts, warningDays)
	}
	if enableSlack {
		sendSlackAlert(warningCerts, warningDays)
	}
	if enableWebhook {
		sendCustomWebhookAlert(warningCerts, warningDays)
	}
	if enableEmail {
		sendEmailAlert(warningCerts, warningDays)
	}
}

func sendTelegramAlert(certs []models.Certificate, thresholdDays int) {
	token := db.GetSetting("telegram_bot_token", "")
	chatID := db.GetSetting("telegram_chat_id", "")
	if token == "" || chatID == "" {
		return
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("⚠️ <b>Cert Deployer Expiration Alert</b>\nThe following %d certificate(s) are expiring within %d days:\n\n", len(certs), thresholdDays))
	for _, c := range certs {
		daysLeft := int(time.Until(c.NotAfter).Hours() / 24)
		sb.WriteString(fmt.Sprintf("• <b>%s</b>: %d days left (Expires: %s)\n", c.ServercertName, daysLeft, c.NotAfter.Format("2006-01-02")))
	}

	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token)
	payload := map[string]string{
		"chat_id":    chatID,
		"text":       sb.String(),
		"parse_mode": "HTML",
	}
	body, _ := json.Marshal(payload)
	client := getHTTPClientWithProxy()
	resp, err := client.Post(apiURL, "application/json", bytes.NewBuffer(body))
	if err != nil {
		log.Printf("[ERROR] [Telegram Alert] Failed to send: %v", err)
		return
	}
	_ = resp.Body.Close()
	log.Println("[INFO] [Telegram Alert] Expiration notification sent successfully")
}

func sendSlackAlert(certs []models.Certificate, thresholdDays int) {
	webhookURL := db.GetSetting("slack_webhook_url", "")
	if webhookURL == "" {
		return
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("⚠️ *Cert Deployer Expiration Alert*\nThe following %d certificate(s) are expiring within %d days:\n", len(certs), thresholdDays))
	for _, c := range certs {
		daysLeft := int(time.Until(c.NotAfter).Hours() / 24)
		sb.WriteString(fmt.Sprintf("• *%s*: %d days left (Expires: %s)\n", c.ServercertName, daysLeft, c.NotAfter.Format("2006-01-02")))
	}

	payload := map[string]string{"text": sb.String()}
	body, _ := json.Marshal(payload)
	client := getHTTPClientWithProxy()
	resp, err := client.Post(webhookURL, "application/json", bytes.NewBuffer(body))
	if err != nil {
		log.Printf("[ERROR] [Slack Alert] Failed to send: %v", err)
		return
	}
	_ = resp.Body.Close()
	log.Println("[INFO] [Slack Alert] Expiration notification sent successfully")
}

func sendCustomWebhookAlert(certs []models.Certificate, thresholdDays int) {
	webhookURL := db.GetSetting("custom_webhook_url", "")
	if webhookURL == "" {
		return
	}

	payload := map[string]interface{}{
		"event":          "certificate_expiration_alert",
		"threshold_days": thresholdDays,
		"total_expiring": len(certs),
		"timestamp":      time.Now().Format(time.RFC3339),
		"certificates":   certs,
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", webhookURL, bytes.NewBuffer(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if secret := db.GetSetting("custom_webhook_secret", ""); secret != "" {
		req.Header.Set("X-Webhook-Secret", secret)
	}

	client := getHTTPClientWithProxy()
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[ERROR] [Custom Webhook Alert] Failed to send: %v", err)
		return
	}
	_ = resp.Body.Close()
	log.Println("[INFO] [Custom Webhook Alert] Expiration notification sent successfully")
}

func sendEmailAlert(certs []models.Certificate, thresholdDays int) {
	host := db.GetSetting("email_smtp_host", "")
	port := db.GetSetting("email_smtp_port", "587")
	user := db.GetSetting("email_smtp_user", "")
	pass := db.GetSetting("email_smtp_pass", "")
	to := db.GetSetting("email_recipient", "")
	if host == "" || to == "" {
		return
	}

	subject := fmt.Sprintf("Subject: [Alert] %d Certificate(s) Expiring Soon\r\n", len(certs))
	header := "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n"

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Cert Deployer Expiration Alert\n\nThe following %d certificate(s) are expiring within %d days:\n\n", len(certs), thresholdDays))
	for _, c := range certs {
		daysLeft := int(time.Until(c.NotAfter).Hours() / 24)
		sb.WriteString(fmt.Sprintf("- %s: %d days left (Expires: %s)\n", c.ServercertName, daysLeft, c.NotAfter.Format("2006-01-02")))
	}

	msg := []byte(subject + header + sb.String())
	auth := smtp.PlainAuth("", user, pass, host)

	addr := fmt.Sprintf("%s:%s", host, port)
	err := smtp.SendMail(addr, auth, user, []string{to}, msg)
	if err != nil {
		log.Printf("[ERROR] [Email Alert] Failed to send email: %v", err)
		return
	}
	log.Println("[INFO] [Email Alert] Expiration email sent successfully")
}

func TestTelegram(token, chatID string) error {
	if token == "" || chatID == "" {
		return fmt.Errorf("Bot Token and Chat ID are required")
	}
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token)
	payload := map[string]string{
		"chat_id":    chatID,
		"text":       "🔔 <b>[TEST] Cert Deployer Notification System Test</b>\nYour Telegram bot configuration is working successfully!",
		"parse_mode": "HTML",
	}
	body, _ := json.Marshal(payload)
	client := getHTTPClientWithProxy()
	resp, err := client.Post(apiURL, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Telegram API returned status code %d", resp.StatusCode)
	}
	return nil
}

func TestSlack(webhookURL string) error {
	if webhookURL == "" {
		return fmt.Errorf("Slack Webhook URL is required")
	}
	payload := map[string]string{
		"text": "🔔 *[TEST] Cert Deployer Notification System Test*\nYour Slack webhook configuration is working successfully!",
	}
	body, _ := json.Marshal(payload)
	client := getHTTPClientWithProxy()
	resp, err := client.Post(webhookURL, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Slack Webhook returned status code %d", resp.StatusCode)
	}
	return nil
}

func TestCustomWebhook(webhookURL, secret string) error {
	if webhookURL == "" {
		return fmt.Errorf("Custom Webhook URL is required")
	}
	payload := map[string]interface{}{
		"event":     "test_notification",
		"message":   "Cert Deployer Custom Webhook test successful!",
		"timestamp": time.Now().Format(time.RFC3339),
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", webhookURL, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if secret != "" {
		req.Header.Set("X-Webhook-Secret", secret)
	}

	client := getHTTPClientWithProxy()
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("Custom Webhook returned HTTP status code %d", resp.StatusCode)
	}
	return nil
}

func TestEmail(host, port, user, pass, to string) error {
	if host == "" || to == "" {
		return fmt.Errorf("SMTP Host and Recipient Email are required")
	}
	if port == "" {
		port = "587"
	}
	subject := "Subject: [TEST] Cert Deployer Notification System Test\r\n"
	header := "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n"
	bodyText := "Cert Deployer Notification System Test\n\nYour Email SMTP configuration is working successfully!"

	msg := []byte(subject + header + bodyText)
	var auth smtp.Auth
	if user != "" && pass != "" {
		auth = smtp.PlainAuth("", user, pass, host)
	}

	addr := fmt.Sprintf("%s:%s", host, port)
	err := smtp.SendMail(addr, auth, user, []string{to}, msg)
	if err != nil {
		return fmt.Errorf("SMTP SendMail failed: %w", err)
	}
	return nil
}
