# API Token Masking and Audit Logging Design Specification

## 1. Overview
Enhance the API Token management in Cert Vault Server by:
1. Masking displayed token strings in the Web Admin UI (showing only the first 5 and last 5 characters).
2. Tracking audit metadata: `last_used_at` timestamp and `last_used_ip` address whenever an API token is authenticated via Bearer token middleware.

---

## 2. Technical Specifications

### 2.1 Database Model (`server/internal/models/token.go`)
Update `APIToken` struct:
```go
type APIToken struct {
	ID          uint       `gorm:"primaryKey;autoIncrement" json:"id"`
	Token       string     `gorm:"type:text" json:"token"`
	TokenHash   string     `gorm:"type:text;uniqueIndex;not null" json:"token_hash"`
	Description string     `gorm:"type:text" json:"description"`
	LastUsedAt  *time.Time `gorm:"type:datetime" json:"last_used_at"`
	LastUsedIP  string     `gorm:"type:text" json:"last_used_ip"`
	CreatedAt   time.Time  `gorm:"autoCreateTime" json:"created_at"`
}
```

### 2.2 Middleware Updates (`server/internal/middleware/auth.go`)
When `BearerAuthMiddleware` successfully authenticates a token:
- Update `last_used_at = time.Now()` and `last_used_ip = c.ClientIP()`.
- Perform update asynchronously or non-blocking to ensure fast API responses.

### 2.3 Dashboard View Model & UI Masking (`server/internal/handlers/web.go` & `index.html`)
Update `TokenViewModel`:
- `TokenMasked`: First 5 chars + `...` + last 5 chars (e.g. `a1b2c...8y9z0`).
- `TokenFull`: Full raw token for 1-click Copy button.
- `LastUsedFormatted`: Formatted datetime string or `"Never"`.
- `LastUsedIP`: Client IP or `"N/A"`.

In `server/templates/index.html`:
- Table columns: `ID`, `Description`, `Token Key (Masked)`, `Last Used`, `Client IP`, `Created At`, `Actions`.
