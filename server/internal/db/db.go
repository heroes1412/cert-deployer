package db

import (
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

	"cert-server/internal/models"

	"github.com/glebarez/sqlite"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

var DB *gorm.DB

func InitDB(dbPath string) (*gorm.DB, error) {
	// Enable WAL mode and 5000ms busy timeout for SQLite stability under concurrent load
	connStr := dbPath
	if !strings.Contains(dbPath, "?") {
		connStr += "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
	}

	database, err := gorm.Open(sqlite.Open(connStr), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	sqlDB, err := database.DB()
	if err == nil {
		sqlDB.SetMaxOpenConns(25)
		sqlDB.SetMaxIdleConns(5)
	}

	err = database.AutoMigrate(&models.Certificate{}, &models.APIToken{}, &models.Setting{}, &models.AuditLog{}, &models.AgentNode{})
	if err != nil {
		return nil, err
	}

	// Seed default admin password if not exists (bcrypt hashed)
	var setting models.Setting
	if err := database.Where("key = ?", "admin_password").First(&setting).Error; err != nil {
		hashed, _ := HashPassword("admin123")
		database.Create(&models.Setting{
			Key:   "admin_password",
			Value: hashed,
		})
		log.Println("[INFO] Initialized default admin_password setting (bcrypt hashed)")
	}

	DB = database
	log.Println("[INFO] SQLite Database initialized at:", dbPath)
	return database, nil
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func CheckPassword(providedPass, storedPassHash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(storedPassHash), []byte(providedPass))
	if err == nil {
		return true
	}
	// Fallback check for legacy plain-text password and auto-upgrade to bcrypt hash
	if providedPass == storedPassHash {
		if newHash, err := HashPassword(providedPass); err == nil {
			_ = SetSetting("admin_password", newHash)
			log.Println("[INFO] Automatically upgraded legacy plaintext admin password to bcrypt hash")
		}
		return true
	}
	return false
}

func GetSetting(key string, defaultValue string) string {
	var setting models.Setting
	if err := DB.Where("key = ?", key).First(&setting).Error; err == nil {
		return setting.Value
	}
	return defaultValue
}

func SetSetting(key string, value string) error {
	var setting models.Setting
	if err := DB.Where("key = ?", key).First(&setting).Error; err == nil {
		setting.Value = value
		return DB.Save(&setting).Error
	}
	newSetting := models.Setting{Key: key, Value: value}
	return DB.Create(&newSetting).Error
}

func GetConstructedProxyURL() string {
	if GetSetting("enable_proxy", "false") != "true" {
		return ""
	}

	proto := GetSetting("proxy_protocol", "http")
	host := strings.TrimSpace(GetSetting("proxy_host", ""))
	port := strings.TrimSpace(GetSetting("proxy_port", ""))
	if host == "" {
		return ""
	}
	if port == "" {
		port = "8080"
	}

	enableAuth := GetSetting("enable_proxy_auth", "false") == "true"
	user := strings.TrimSpace(GetSetting("proxy_user", ""))
	pass := GetSetting("proxy_pass", "")

	if enableAuth && user != "" {
		if pass != "" {
			return fmt.Sprintf("%s://%s:%s@%s:%s", proto, url.QueryEscape(user), url.QueryEscape(pass), host, port)
		}
		return fmt.Sprintf("%s://%s@%s:%s", proto, url.QueryEscape(user), host, port)
	}

	return fmt.Sprintf("%s://%s:%s", proto, host, port)
}

// StartDailyDatabaseMaintenance initializes a background scheduler that runs once every 24 hours
// to truncate the SQLite WAL journal and perform VACUUM to defragment and optimize disk space.
func StartDailyDatabaseMaintenance() {
	go func() {
		// Run initial maintenance 1 minute after server startup
		time.Sleep(1 * time.Minute)
		runDatabaseMaintenance()

		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()

		for range ticker.C {
			runDatabaseMaintenance()
		}
	}()
}

func runDatabaseMaintenance() {
	if DB == nil {
		return
	}
	log.Println("[INFO] [DB Maintenance] Running daily SQLite WAL checkpoint, audit log retention cleanup & VACUUM...")

	// 1. Purge audit logs older than 6 months (180 days)
	sixMonthsAgo := time.Now().AddDate(0, -6, 0)
	res := DB.Where("created_at < ?", sixMonthsAgo).Delete(&models.AuditLog{})
	if res.Error != nil {
		log.Printf("[WARNING] [DB Maintenance] Failed to purge audit logs older than 6 months: %v", res.Error)
	} else if res.RowsAffected > 0 {
		log.Printf("[INFO] [DB Maintenance] Purged %d audit log entries older than 6 months (%s)", res.RowsAffected, sixMonthsAgo.Format("2006-01-02"))
	}

	// 2. Truncate WAL journal
	if err := DB.Exec("PRAGMA wal_checkpoint(TRUNCATE)").Error; err != nil {
		log.Printf("[WARNING] [DB Maintenance] Failed to truncate WAL journal: %v", err)
	}

	// 3. Reclaim unallocated database disk space
	if err := DB.Exec("VACUUM").Error; err != nil {
		log.Printf("[WARNING] [DB Maintenance] Failed to execute VACUUM: %v", err)
	} else {
		log.Println("[SUCCESS] [DB Maintenance] SQLite database successfully vacuumed & optimized")
	}
}

func LogAudit(ipAddress, action, details string) {
	if DB == nil {
		return
	}
	if ipAddress == "" {
		ipAddress = "127.0.0.1"
	}
	entry := models.AuditLog{
		IPAddress: ipAddress,
		Action:    action,
		Details:   details,
	}
	if err := DB.Create(&entry).Error; err != nil {
		log.Printf("[WARNING] Failed to write audit log: %v", err)
	}
}
