# Implementation Plan: 100% Read-Only API Token Authentication

> **Goal:** Remove DB write updates (`last_used_at`, `last_used_ip`) from `BearerAuthMiddleware` to make API calls 100% Read-Only for 500+ CCU performance.

---

## Tasks

### Task 1: Update APIToken Model & Middleware
- `server/internal/models/token.go`: Remove `LastUsedAt` and `LastUsedIP`.
- `server/internal/middleware/auth.go`: Remove background DB update goroutine.

### Task 2: Update Web View Model & HTML Template
- `server/internal/handlers/web.go`: Remove `LastUsedFormatted` and `LastUsedIP` from `TokenViewModel`.
- `server/templates/index.html`: Clean up API tokens table headers and columns to remove `Last Used` and `Client IP`. Keep `Token Key (Masked)` and `Copy Token`.

### Task 3: Build & Verify
- Run `.\build.bat` to compile all 4 binaries.
