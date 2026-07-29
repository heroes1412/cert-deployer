package main

import (
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"cert-server/internal/db"
	"cert-server/internal/handlers"
	"cert-server/internal/middleware"
	"cert-server/templates"

	"github.com/gin-gonic/gin"
)

func initEnvironment() {
	// Set working directory to executable directory to avoid running inside C:\Windows\System32
	execPath, err := os.Executable()
	if err == nil {
		execDir := filepath.Dir(execPath)
		_ = os.Chdir(execDir)
	}

	// Setup log file cert-server.log in the application directory
	logFile, err := os.OpenFile("cert-server.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err == nil {
		multiWriter := io.MultiWriter(os.Stdout, logFile)
		log.SetOutput(multiWriter)
		gin.DefaultWriter = multiWriter
		gin.DefaultErrorWriter = multiWriter
	}
}

func runServer() {
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		if _, err := os.Stat("cert-vault.db"); err == nil {
			dbPath = "cert-vault.db"
		} else {
			_ = os.MkdirAll("data", 0755)
			dbPath = filepath.Join("data", "cert-vault.db")
		}
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
		admin.POST("/settings/save", handlers.SaveSettings)
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
		port = db.GetSetting("server_port", "8080")
	}

	log.Printf("[INFO] Server starting on http://localhost:%s", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatalf("Server failed to run: %v", err)
	}
}

func main() {
	initEnvironment()

	if runWindowsServiceIfService() {
		return
	}

	// Interactive Console Mode
	runServer()
}
