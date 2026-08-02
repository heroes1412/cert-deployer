package main

import (
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"cert-server/internal/acme"
	"cert-server/internal/db"
	"cert-server/internal/handlers"
	"cert-server/internal/middleware"
	"cert-server/internal/notifications"
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
		_ = os.MkdirAll("data", 0755)
		dbPath = filepath.Join("data", "cert-server.db")
	}

	_, err := db.InitDB(dbPath)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	// Start ACME Auto-Renew Background Scheduler
	acme.StartAutoRenewScheduler()

	// Start Automated Expiration Notification Background Scheduler
	notifications.StartNotificationScheduler()

	// Start Daily SQLite Database Maintenance & VACUUM Scheduler
	db.StartDailyDatabaseMaintenance()

	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()
	_ = r.SetTrustedProxies(nil)

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
		admin.GET("/certs/check-name", handlers.CheckCertName)
		admin.POST("/certs/save", handlers.SaveCertificate)
		admin.POST("/certs/delete", handlers.DeleteCertificate)
		admin.POST("/certs/acme/issue", handlers.IssueACMECertificate)
		admin.POST("/tokens/generate", handlers.GenerateAPIToken)
		admin.POST("/tokens/revoke", handlers.RevokeAPIToken)
		admin.POST("/settings/save", handlers.SaveSettings)
		admin.POST("/notifications/test", handlers.TestNotification)
		admin.POST("/certs/internal/issue", handlers.HandleIssueInternalCert)
		admin.POST("/settings/ca/generate", handlers.HandleGenerateRootCA)
		admin.POST("/settings/ca/upload", handlers.HandleUploadRootCA)
		admin.GET("/settings/ca/download", handlers.HandleDownloadRootCA)
		admin.POST("/settings/ca/delete", handlers.HandleDeleteRootCA)
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
		api.POST("/agent/heartbeat", handlers.PostAgentHeartbeat)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = db.GetSetting("server_port", "8080")
	}

	log.Printf("[INFO] Cert Server starting on http://localhost:%s", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatalf("Cert Server failed to run: %v", err)
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
