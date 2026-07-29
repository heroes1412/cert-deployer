# Implementation Plan: Centralized Certificate Management System

> **Goal:** Build a production-grade, lightweight Certificate Management System consisting of a Go Server (Web Admin + REST API + SQLite) and a Go Client CLI Agent (`cert-agent` check/sync).

**Architecture:** 
- `/server`: Go + Gin + CGO-free SQLite (`glebarez/sqlite` or `modernc.org/sqlite`) + HTML Admin UI embedded into a single static binary.
- `/client`: Go + Cobra CLI + YAML parser (`gopkg.in/yaml.v3`) + atomic file writer + cross-platform command runner.

**Global Constraints:**
- Language: Go 1.20+
- Must run cross-platform on Linux and Windows.
- Pure Go SQLite without CGO requirements.
- Private key files must have 0600 permissions.
- Pre/Post commands executed via `sh -c` (Linux) / `cmd /c` (Windows) with 30s timeout.

---

### Task 1: Server Project Setup & Database Models (`/server`)

**Files:**
- Create: `server/go.mod`
- Create: `server/internal/models/certificate.go`
- Create: `server/internal/models/token.go`
- Create: `server/internal/db/db.go`
- Create: `server/internal/crypto/cert.go`

- [ ] **Step 1: Initialize server go.mod**
  Write `server/go.mod` with dependencies (`gin-gonic/gin`, `glebarez/sqlite`, `gorm.io/gorm`).

- [ ] **Step 2: Implement models & DB initialization**
  Define `Certificate` and `APIToken` structs, and `InitDB(dbPath string)` function to automigrate tables in SQLite.

- [ ] **Step 3: Implement Certificate X.509 Parsing & Validation helper**
  Create `ParseAndValidateCert(certPEM, keyPEM string)` in `server/internal/crypto/cert.go`:
  - Parses PEM certificate using `x509.ParseCertificate`.
  - Calculates SHA256 fingerprint of `cert_data`.
  - Extracts `not_after`.
  - Validates public key match between `certPEM` and `keyPEM`.

---

### Task 2: Server Middleware & REST API Endpoints (`/server`)

**Files:**
- Create: `server/internal/middleware/auth.go`
- Create: `server/internal/handlers/api.go`

- [ ] **Step 1: Implement Bearer Token Auth Middleware**
  Check `Authorization: Bearer <token>` header against `api_tokens` table in SQLite using SHA256 hash comparison.

- [ ] **Step 2: Implement REST API Endpoints**
  - `GET /api/v1/certs/:servercert_name` -> Returns full JSON (`servercert_name`, `cert_pem`, `key_pem`, `sha256`, `not_after`).
  - `GET /api/v1/certs/:servercert_name/meta` -> Returns metadata JSON (`servercert_name`, `sha256`, `not_after`).

---

### Task 3: Server Web Admin UI & Main Binary (`/server`)

**Files:**
- Create: `server/templates/index.html`
- Create: `server/templates/login.html`
- Create: `server/internal/handlers/web.go`
- Create: `server/cmd/main.go`

- [ ] **Step 1: Create HTML Templates**
  Modern, responsive HTML UI with Tailwind CSS CDN for Admin login, dashboard table (expiry date, days remaining, SHA256, visual badge if < 30 days), cert upload/edit modal, token management.

- [ ] **Step 2: Implement Web Handlers & Auth Session**
  Session/Cookie based authentication for web dashboard, endpoints for upload cert, delete cert, generate/revoke API token.

- [ ] **Step 3: Implement Server Main Entry Point**
  `server/cmd/main.go` embedding templates via `go:embed`, initializing DB, setting up routes, starting HTTP server on port 8080 (or configurable `PORT`).

---

### Task 4: Client Agent Configuration & CLI Scaffolding (`/client`)

**Files:**
- Create: `client/go.mod`
- Create: `client/internal/config/config.go`
- Create: `client/cmd/root.go`
- Create: `client/cmd/main.go`

- [ ] **Step 1: Initialize client go.mod**
  Dependencies: `spf13/cobra`, `gopkg.in/yaml.v3`.

- [ ] **Step 2: Implement Config Parser & Directory Validator**
  Define `Config`, `CertConfig` structs in `client/internal/config/config.go`.
  Add `ValidateDirectories()` to ensure target `certfile` and `keyfile` directories exist prior to file operations.

- [ ] **Step 3: Create CLI Root Command**
  `client/cmd/root.go` with `-c / --config` flag (default `/etc/cert-agent/config.yaml`).

---

### Task 5: Client Agent `check` Command (`/client`)

**Files:**
- Create: `client/cmd/check.go`

- [ ] **Step 1: Implement `check` command**
  - Parse `config.yaml`.
  - For each `cert` entry:
    - Read local `certfile` (if present) and parse local X.509 expiration.
    - Query `GET /api/v1/certs/:servercert_name/meta` from Server URL with Bearer token.
    - Calculate days remaining for local and server.
  - Print formatted ASCII table comparing Local Expiration, Server Expiration, and Status (`UP TO DATE`, `UPDATE AVAIL`, `LOCAL MISSING`, `SERVER MISSING`).

---

### Task 6: Client Agent `sync` Command (`/client`)

**Files:**
- Create: `client/cmd/sync.go`
- Create: `client/internal/agent/executor.go`
- Create: `client/internal/agent/writer.go`

- [ ] **Step 1: Implement Shell Command Executor**
  `ExecuteCommand(cmdStr string, timeout time.Duration)` in `client/internal/agent/executor.go`:
  - Cross-platform: Uses `sh -c` on Unix/Linux and `cmd /c` on Windows.
  - Uses `context.WithTimeout` (30s).
  - Returns stdout/stderr and error/exit code.

- [ ] **Step 2: Implement Atomic File Writer**
  `WriteCertFiles(certfile, keyfile, certPEM, keyPEM string)` in `client/internal/agent/writer.go`:
  - Handles combined cert (`certfile == keyfile` or empty `keyfile`): concatenates `certPEM + "\n" + keyPEM`.
  - Writes to `.tmp` file first.
  - Enforces `0600` permissions on key / combined files.
  - Performs atomic `os.Rename`.

- [ ] **Step 3: Implement `sync` command**
  - Run `pre_cmd`. If exit code != 0, log `[ERROR] pre_cmd failed. Aborting update!` and exit with code 1.
  - Loop through certs: fetch `GET /api/v1/certs/:servercert_name`.
  - Check local file SHA256 vs server SHA256. If matching, skip.
  - If updated: invoke atomic file writer.
  - If at least one cert updated, run `post_cmd`.
  - Output structured logs with timestamps (`[INFO]`, `[WARN]`, `[ERROR]`).

---

### Task 7: Sample Config, Documentation & Git Push

**Files:**
- Create: `client/config.yaml.example`
- Create: `README.md`

- [ ] **Step 1: Create Sample `config.yaml.example`**
- [ ] **Step 2: Write README.md & Deployment Instructions**
  Building, deployment steps, systemd / crontab setup example.
- [ ] **Step 3: Verify Builds & Push to GitHub**
  Build server and client binaries (`go build`), test execution, push code to `git@github.com:heroes1412/cert-auto-rotation.git` using SSH key `C:\Users\Administrator\.ssh\id_ed25519`.
