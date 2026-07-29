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

	err = database.AutoMigrate(&models.Certificate{}, &models.APIToken{})
	if err != nil {
		return nil, err
	}

	DB = database
	log.Println("[INFO] SQLite Database initialized at:", dbPath)
	return database, nil
}
