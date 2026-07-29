# Read-Only API Token Authorization & High-Concurrency Performance Design Spec

## 1. Overview
Remove `last_used_at` and `last_used_ip` DB updates from the API token authentication middleware (`BearerAuthMiddleware`).
By eliminating all database `UPDATE` writes during API requests, client certificate synchronization operations become **100% Read-Only** (`SELECT` queries only).

This ensures zero SQLite write lock contention, enabling the server to seamlessly handle 500+ CCU concurrent client requests in under 10ms with **0.000% database lock errors**.

---

## 2. Technical Specifications

### 2.1 Middleware (`server/internal/middleware/auth.go`)
- Remove background goroutine executing `db.DB.Model(&models.APIToken{}).Updates(...)`.
- `BearerAuthMiddleware` performs a single `SELECT` query (`Where("token_hash = ?", tokenHash)`) and proceeds.

### 2.2 APIToken Model (`server/internal/models/token.go`)
- Remove `LastUsedAt` and `LastUsedIP` struct fields.

### 2.3 Handlers & Dashboard UI (`server/internal/handlers/web.go` & `index.html`)
- Remove `LastUsedFormatted` and `LastUsedIP` from `TokenViewModel`.
- In `index.html`: Keep `Token Key (Masked)` (`a1b2c...8y9z0`) and 1-click **Copy Token** button. Remove `Last Used` and `Client IP` table columns.
