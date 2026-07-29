package db

import (
	"log"

	"cert-server/internal/models"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

var DB *gorm.DB

func InitDB(dbPath string) (*gorm.DB, error) {
	database, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	err = database.AutoMigrate(&models.Certificate{}, &models.APIToken{}, &models.Setting{})
	if err != nil {
		return nil, err
	}

	// Seed default admin password if not exists
	var setting models.Setting
	if err := database.Where("key = ?", "admin_password").First(&setting).Error; err != nil {
		database.Create(&models.Setting{
			Key:   "admin_password",
			Value: "admin123",
		})
		log.Println("[INFO] Initialized default admin_password setting ('admin123')")
	}

	DB = database
	log.Println("[INFO] SQLite Database initialized at:", dbPath)
	return database, nil
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
	return DB.Create(&models.Setting{Key: key, Value: value}).Error
}
