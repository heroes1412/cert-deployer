package main

import (
	"html/template"
	"log"
	"net/http"
	"os"

	"cert-server/internal/db"
	"cert-server/internal/handlers"
	"cert-server/internal/middleware"
	"cert-server/templates"

	"github.com/gin-gonic/gin"
)

func main() {
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "cert-vault.db"
	}

	_, err := db.InitDB(dbPath)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	r := gin.Default()

	// Load embedded HTML templates
	templ := template.Must(template.ParseFS(templates.FS, "*.html"))
	r.SetHTMLTemplate(templ)

	// Public Routes
	r.GET("/login", handlers.ShowLogin)
	r.POST("/login", handlers.ProcessLogin)
	r.GET("/logout", handlers.Logout)

	// Web Admin Protected Routes
	admin := r.Group("/admin")
	admin.Use(handlers.WebAuthMiddleware())
	{
		admin.GET("", handlers.ShowDashboard)
		admin.POST("/certs/save", handlers.SaveCertificate)
		admin.POST("/certs/delete", handlers.DeleteCertificate)
		admin.POST("/tokens/generate", handlers.GenerateAPIToken)
		admin.POST("/tokens/revoke", handlers.RevokeAPIToken)
		admin.POST("/password/change", handlers.ChangePassword)
	}

	// Redirect root to /admin
	r.GET("/", func(c *gin.Context) {
		c.Redirect(http.StatusSeeOther, "/admin")
	})

	// Bearer Token Protected REST API v1
	api := r.Group("/api/v1")
	api.Use(middleware.BearerAuthMiddleware())
	{
		api.GET("/certs/:servercert_name", handlers.GetCertFull)
		api.GET("/certs/:servercert_name/meta", handlers.GetCertMeta)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("[INFO] Server starting on http://localhost:%s", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatalf("Server failed to run: %v", err)
	}
}
