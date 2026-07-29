package models

import (
	"time"
)

type APIToken struct {
	ID          uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	TokenHash   string    `gorm:"type:text;uniqueIndex;not null" json:"token_hash"`
	Description string    `gorm:"type:text" json:"description"`
	CreatedAt   time.Time `gorm:"autoCreateTime" json:"created_at"`
}
