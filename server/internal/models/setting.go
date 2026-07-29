package models

type Setting struct {
	Key   string `gorm:"primaryKey;type:text" json:"key"`
	Value string `gorm:"type:text;not null" json:"value"`
}
