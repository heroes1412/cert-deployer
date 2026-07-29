# Implementation Plan: Server Settings Modal & Configurable Port

> **Goal:** Replace Change Password modal with a comprehensive Settings Modal, allowing administrators to configure both the Admin Password and the Server HTTP Management Port.

---

## Detailed Tasks

### Task 1: Update Handlers & Server Entry Points
- Modify `server/internal/handlers/web.go`:
  - Pass `serverPort` (`db.GetSetting("server_port", "8080")`) to dashboard template.
  - Implement `SaveSettings` handler to process port updates and password changes simultaneously.
- Modify `server/main.go` & `server/cmd/main.go`:
  - Register `/admin/settings/save` route.
  - Read port from `os.Getenv("PORT")` or fallback to `db.GetSetting("server_port", "8080")`.

### Task 2: Update Web UI (`server/templates/index.html`)
- Replace Navbar "Change Password" button with a **⚙️ Settings** button.
- Create **Settings Modal** featuring:
  - **Server Settings**: Configurable HTTP Port input field.
  - **Admin Security**: Current Password, New Password, Confirm New Password fields.

### Task 3: Build & Verification
- Compile server and client binaries (`build.bat`).
- Verify settings modal functionality.
