package handlers

import (
	"net/http"
	"strings"
	"time"

	"cert-server/internal/db"
	"cert-server/internal/models"

	"github.com/gin-gonic/gin"
)

type FullCertResponse struct {
	ServercertName string `json:"servercert_name"`
	CertPEM        string `json:"cert_pem"`
	KeyPEM         string `json:"key_pem"`
	SHA256         string `json:"sha256"`
	NotAfter       string `json:"not_after"`
	Domains        string `json:"domains"`
}

type MetaCertResponse struct {
	ServercertName string `json:"servercert_name"`
	SHA256         string `json:"sha256"`
	NotAfter       string `json:"not_after"`
	Domains        string `json:"domains"`
}

func GetCertFull(c *gin.Context) {
	name := c.Param("servercert_name")

	var cert models.Certificate
	result := db.DB.Where("servercert_name = ?", name).First(&cert)
	if result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Certificate not found"})
		return
	}

	c.JSON(http.StatusOK, FullCertResponse{
		ServercertName: cert.ServercertName,
		CertPEM:        cert.CertData,
		KeyPEM:         cert.KeyData,
		SHA256:         cert.FingerprintSHA256,
		NotAfter:       cert.NotAfter.Format("2006-01-02T15:04:05Z"),
		Domains:        cert.Domains,
	})
}

func GetCertMeta(c *gin.Context) {
	name := c.Param("servercert_name")

	var cert models.Certificate
	result := db.DB.Where("servercert_name = ?", name).First(&cert)
	if result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Certificate not found"})
		return
	}

	c.JSON(http.StatusOK, MetaCertResponse{
		ServercertName: cert.ServercertName,
		SHA256:         cert.FingerprintSHA256,
		NotAfter:       cert.NotAfter.Format("2006-01-02T15:04:05Z"),
		Domains:        cert.Domains,
	})
}

type AgentHeartbeatRequest struct {
	Hostname    string   `json:"hostname"`
	IPAddress   string   `json:"ip_address"`
	OS          string   `json:"os"`
	SyncedCerts []string `json:"synced_certs"`
}

func PostAgentHeartbeat(c *gin.Context) {
	var req AgentHeartbeatRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid heartbeat payload"})
		return
	}

	hostname := strings.TrimSpace(req.Hostname)
	if hostname == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Hostname is required"})
		return
	}

	ip := strings.TrimSpace(req.IPAddress)
	if ip == "" {
		ip = c.ClientIP()
	}

	syncedCertsStr := strings.Join(req.SyncedCerts, ", ")

	var node models.AgentNode
	err := db.DB.Where("hostname = ?", hostname).First(&node).Error
	if err != nil {
		node = models.AgentNode{
			Hostname:    hostname,
			IPAddress:   ip,
			OSInfo:      req.OS,
			SyncedCerts: syncedCertsStr,
			LastSeenAt:  time.Now(),
		}
		db.DB.Create(&node)
	} else {
		node.IPAddress = ip
		node.OSInfo = req.OS
		node.SyncedCerts = syncedCertsStr
		node.LastSeenAt = time.Now()
		db.DB.Save(&node)
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok", "message": "Heartbeat recorded"})
}
