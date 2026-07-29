# Implementation Plan: API Token Masking & Audit Logging

> **Goal:** Mask API Tokens in the Web UI (showing first 5 & last 5 chars) and track `last_used_at` and `last_used_ip` in SQLite database.

---

## Tasks

### Task 1: Update Database Model & Auto-Migration
- Modify `server/internal/models/token.go`: Add `LastUsedAt *time.Time` and `LastUsedIP string` fields.
- `server/internal/db/db.go` handles auto-migration automatically on startup.

### Task 2: Update Bearer Middleware for Audit Tracking
- Modify `server/internal/middleware/auth.go`:
  - When Bearer token is valid, update `last_used_at` and `last_used_ip` in `api_tokens` table.

### Task 3: Update Web View Model & HTML Template
- Modify `server/internal/handlers/web.go`:
  - Create helper `maskToken(token string) string`: returns `token[:5] + "..." + token[len-5:]` if len > 10.
  - Include `TokenMasked`, `LastUsedFormatted`, `LastUsedIP` in `TokenViewModel`.
- Modify `server/templates/index.html`:
  - Render `TokenMasked` in table cell.
  - Add `Last Used` and `Client IP` columns to API Tokens table.

### Task 4: Build & Test
- Run `.\build.bat`.
- Test token generation, API authentication via curl/cert-agent, and view updated audit log & masked token in Web UI.
