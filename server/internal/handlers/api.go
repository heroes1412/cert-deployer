package handlers

import (
	"net/http"

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
}

type MetaCertResponse struct {
	ServercertName string `json:"servercert_name"`
	SHA256         string `json:"sha256"`
	NotAfter       string `json:"not_after"`
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
	})
}
