# Implementation Plan: Fix 2 Issues

> **Goal:** Address the 3 issues specified in `Fix2.txt`.

---

## Task List

### Task 1: Fix Expiration Status Badge (Issue 1)
- Modify `server/internal/handlers/web.go`:
  - Determine `IsExpired` (`daysLeft < 0`), `IsWarning` (`0 <= daysLeft < 30`).
  - Pass `IsExpired`, `IsWarning`, and formatted status text to `CertViewModel`.
- Update `server/templates/index.html`:
  - Render a red badge for `EXPIRED` status (`Đã hết hạn`).
  - Render an amber badge for `Expiring Soon` (`Sap hết hạn`).
  - Render a green badge for valid certs (`>= 30 days`).

### Task 2: Fix Client Build & Main Entry Point (Issue 2)
- Ensure `client/main.go` exists and is properly configured for direct `go build` inside `/client`.
- Also ensure `client/cmd/main.go` or standard entry points exist so building via `go build cmd/main.go` or `go build` inside `/client` works without errors.

### Task 3: Build Scripts for Windows & Linux (Issue 3)
- Create `build.bat` at project root for Windows:
  - Builds `server/cert-server.exe` (Windows) & `server/cert-server` (Linux `GOOS=linux`).
  - Builds `client/cert-agent.exe` (Windows) & `client/cert-agent` (Linux `GOOS=linux`).
- Create `build.sh` at project root for Linux:
  - Shell script to build both Windows and Linux binaries for server and client.

### Task 4: Verification & Git Commit
- Compile both Windows and Linux binaries using the scripts.
- Verify status badge logic.
- Commit & push changes to GitHub (`git@github.com:heroes1412/cert-auto-rotation.git`).
