package models

import (
	"time"
)

type Certificate struct {
	ID                uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	ServercertName    string    `gorm:"type:text;uniqueIndex;not null" json:"servercert_name"`
	CertData          string    `gorm:"type:text;not null" json:"cert_data"`
	KeyData           string    `gorm:"type:text;not null" json:"key_data"`
	FingerprintSHA256 string    `gorm:"type:text;not null" json:"fingerprint_sha256"`
	NotAfter          time.Time `gorm:"type:datetime;not null" json:"not_after"`
	CreatedAt         time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt         time.Time `gorm:"autoUpdateTime" json:"updated_at"`
}
