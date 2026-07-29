# Implementation Plan: Fix 1 Issues (Web Admin Dashboard Enhancements)

> **Goal:** Resolve all 4 UX and functional issues listed in `Fix1.txt` for the Server Web Admin Dashboard.

---

### Issues Summary & Solutions

1. **Issue 1 (API Token Copyable)**: 
   - Add `token` field to `APIToken` model so created tokens remain viewable.
   - Display full/truncated token in dashboard with a 1-click **Copy Token** button (`navigator.clipboard.writeText`).

2. **Issue 2 (Browse Cert Files & Copy SHA256 Fingerprint)**:
   - Add file upload buttons (`<input type="file">`) for Certificate PEM and Private Key PEM in the Add/Update modal. JavaScript `FileReader` auto-populates the textareas.
   - Add a 1-click **Copy Fingerprint** button next to SHA256 fingerprints in the certificate list table.

3. **Issue 3 (Edit Certificate Action)**:
   - Make `servercert_name` clickable and add an **Edit** button in the Certificate actions column.
   - Clicking Edit opens the modal with pre-filled `servercert_name`, `cert_data`, and `key_data`.

4. **Issue 4 (Change Admin Password)**:
   - Create a `Setting` model in SQLite storing system configurations like `admin_password`.
   - Update login logic to validate against DB settings.
   - Add a **Change Password** modal and backend handler `/admin/password/change`.

---

## Detailed Task Checklist

### Task 1: Update Models & Database Setup
- [ ] Create `server/internal/models/setting.go` with `Setting` struct (`Key`, `Value`).
- [ ] Modify `server/internal/models/token.go` to add `Token string` field.
- [ ] Update `server/internal/db/db.go` `InitDB()` to auto-migrate `Setting` and seed default `admin_password` = `admin123`.

### Task 2: Update Server Web Handlers
- [ ] Update `ProcessLogin` in `server/internal/handlers/web.go` to check password from DB.
- [ ] Add `ChangePassword` handler in `server/internal/handlers/web.go`.
- [ ] Update `GenerateAPIToken` to save plaintext `Token` in DB.
- [ ] Include `Token` in `TokenViewModel` passed to HTML template.
- [ ] Register `/admin/password/change` route in `server/cmd/main.go`.

### Task 3: Update Web UI HTML & JavaScript (`server/templates/index.html`)
- [ ] Add File Browse inputs (`<input type="file">`) with JS `FileReader` handlers for `cert_data` and `key_data`.
- [ ] Add Copy button for SHA256 Fingerprint in Certificates table.
- [ ] Add Edit action button & clickable cert names that invoke `openEditModal(...)`.
- [ ] Add Copy button for API Tokens in API Tokens table.
- [ ] Add "Change Password" modal & button in Navbar.

### Task 4: Verification & Git Commit
- [ ] Compile server binary (`go build`).
- [ ] Test login, changing password, adding cert via file browse, copying SHA256/Token, and editing cert.
- [ ] Commit & push changes to `git@github.com:heroes1412/cert-auto-rotation.git`.
