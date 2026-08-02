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
	IsACME            bool      `gorm:"default:false" json:"is_acme"`
	ACMEProvider      string    `gorm:"type:text" json:"acme_provider"`
	DNSProvider       string    `gorm:"type:text" json:"dns_provider"`
	DNSAPIToken       string    `gorm:"type:text" json:"dns_api_token"`
	ACMEEmail         string    `gorm:"type:text" json:"acme_email"`
	Domains           string    `gorm:"type:text" json:"domains"`
	EABKID            string    `gorm:"type:text" json:"eab_kid"`
	EABHMACKey        string    `gorm:"type:text" json:"eab_hmac_key"`
	AutoRenew         bool      `gorm:"default:true" json:"auto_renew"`
	Provider          string    `gorm:"type:text;default:'manual'" json:"provider"`
	CreatedAt         time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt         time.Time `gorm:"autoUpdateTime" json:"updated_at"`
}

type AuditLog struct {
	ID        uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	IPAddress string    `gorm:"type:text;not null" json:"ip_address"`
	Action    string    `gorm:"type:text;not null" json:"action"`
	Details   string    `gorm:"type:text" json:"details"`
	CreatedAt time.Time `gorm:"autoCreateTime" json:"created_at"`
}

type AgentNode struct {
	ID          uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	Hostname    string    `gorm:"type:text;uniqueIndex;not null" json:"hostname"`
	IPAddress   string    `gorm:"type:text" json:"ip_address"`
	OSInfo      string    `gorm:"type:text" json:"os_info"`
	SyncedCerts string    `gorm:"type:text" json:"synced_certs"`
	LastSeenAt  time.Time `gorm:"type:datetime" json:"last_seen_at"`
}
