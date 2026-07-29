package middleware

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"

	"cert-server/internal/db"
	"cert-server/internal/models"

	"github.com/gin-gonic/gin"
)

func HashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

func BearerAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if !(len(parts) == 2 && strings.EqualFold(parts[0], "Bearer")) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header format must be Bearer <token>"})
			c.Abort()
			return
		}

		token := strings.TrimSpace(parts[1])
		if token == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Bearer token cannot be empty"})
			c.Abort()
			return
		}

		tokenHash := HashToken(token)

		var apiToken models.APIToken
		result := db.DB.Where("token_hash = ?", tokenHash).First(&apiToken)
		if result.Error != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or revoked Bearer token"})
			c.Abort()
			return
		}

		c.Next()
	}
}
