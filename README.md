# Centralized Certificate Management System (Server & Go Client)

A production-grade, lightweight Certificate Management System built in Go.

## System Architecture

The repository is structured into two independent components:
- **`server/`**: Web Admin Dashboard + REST API backed by a pure Go SQLite database for SSL/TLS certificate management.
- **`client/`**: CLI Agent (`cert-agent`) that synchronizes certificates on target servers based on `config.yaml`.

---

## 1. Server Component (`/server`)

### Features
- Embedded Web Admin UI (built with Go `embed.FS` and Tailwind CSS).
- SQLite Database storing certificate PEM contents, public key fingerprints (SHA256), and expiration dates (`not_after`).
- Automatic X.509 certificate parsing and public/private key cryptographic consistency check prior to saving.
- Download Cert (`.crt`) and Download Key (`.key`) buttons directly from the Web UI modal.
- API Bearer Token generation and revocation with 1-click Copy Token button.
- Change Admin Password interface.
- REST API protected by Bearer Token Authorization.

### Build & Run
```bash
cd server
go build -o cert-server main.go
./cert-server
```
By default, the server runs on `http://localhost:8080` (Default credentials: Username `admin`, Password `admin123`).

Environment variables:
- `PORT`: HTTP listener port (default `8080`).
- `DB_PATH`: SQLite database file path (default `cert-vault.db`).

---

## 2. Client Agent Component (`/client`)

### Features
- CLI Commands: `cert-agent check` and `cert-agent sync`.
- Auto-detects `./config.yaml` in the current working directory if `-c` is omitted.
- Supports both Linux (`sh -c`) and Windows (`cmd /c`) shell command and script file execution.
- Global commands (`global_pre_cmd`, `global_post_cmd`) and per-certificate commands (`pre_cmd`, `post_cmd`).
- Robust Windows path preprocessing: handles backslashes `\` (`"D:\tmp\1 1\expired.pem"`) without YAML escape errors.
- Atomic file writes using temporary files and atomic `os.Rename`.
- Strict file permission `0600` for private key files.
- Checks local file existence: skips syncing if local `certfile` or `keyfile` does not exist.
- Special handling for combined cert files (e.g. HAProxy where `certfile == keyfile`).

### Build

Using automated build scripts (compiled for both Windows & Linux):
```cmd
:: On Windows
.\build.bat
```
```bash
# On Linux
./build.sh
```

Or build manually inside `client/`:
```bash
cd client
go build -o cert-agent main.go
```

---

## 3. System Services Setup (Windows NSSM & Linux Systemd)

### Question & Architecture FAQ
- **Q: Does `cert-server` need code modifications to run as a Windows Service via NSSM?**
  * **Answer: NO.** NSSM (Non-Sucking Service Manager) acts as a transparent Windows SCM wrapper around standard console applications. `cert-server.exe` runs 100% out of the box with NSSM without any code changes.
- **Q: Can `cert-server` and `cert-agent` run under Linux `systemctl` / `systemd`?**
  * **Answer: YES.** Standard Linux binaries execute natively as `systemd` services (`Type=simple` for server, `Type=oneshot` + `timer` for client agent).

### A. Windows Service Setup (via NSSM)
1. Build binaries using `build.bat`.
2. Run `scripts/service_install_windows.bat` as Administrator:
   ```cmd
   scripts\service_install_windows.bat
   ```
   Or manage manually via NSSM:
   ```cmd
   nssm install CertVaultServer "C:\path\to\build\windows\cert-server.exe"
   nssm start CertVaultServer
   ```

### B. Linux Service Setup (via Systemd)
Run automated Linux service installer script as root:
```bash
sudo ./scripts/service_install_linux.sh
```
This automatically installs:
- **Server Service**: `/etc/systemd/system/cert-server.service` (manages `http://localhost:8080`).
- **Client Timer**: `/etc/systemd/system/cert-agent.timer` (runs `cert-agent sync` every 6 hours).

Useful Linux `systemctl` commands:
```bash
# Server status / start / stop
systemctl status cert-server
systemctl start cert-server
systemctl stop cert-server

# Client timer status
systemctl status cert-agent.timer
```

---

## 4. Configuration Guide (`config.yaml`)

```yaml
server_url: "http://localhost:8080"
auth_token: "secret-bearer-token-here"

# Global command executed ONCE before any certificate sync session starts
global_pre_cmd: "echo 'Starting cert sync session...'"

certs:
  # Nginx example: separate certfile and keyfile with per-cert pre_cmd / post_cmd
  - servercert_name: "prod_web_cert"
    certfile: "D:\\vnshell\\it\\Linux\\prod_web.crt"
    keyfile: "D:\\vnshell\\it\\Linux\\prod_web.key"
    pre_cmd: "nginx -t"
    post_cmd: "systemctl reload nginx"
  
  # HAProxy example: combined certfile and keyfile
  - servercert_name: "lb_haproxy_cert"
    certfile: "/etc/haproxy/certs/haproxy.pem"
    keyfile: "/etc/haproxy/certs/haproxy.pem"
    pre_cmd: "haproxy -c -f /etc/haproxy/haproxy.cfg"
    post_cmd: "systemctl reload haproxy"

# Global command executed ONCE after all certificate syncs finish (if at least 1 cert updated)
global_post_cmd: "echo 'Cert sync session completed successfully!'"
```

---

## 5. Crontab Setup Example

To automate certificate rotation every 6 hours on Linux via Cron:
```cron
0 */6 * * * /usr/local/bin/cert-agent sync -c /etc/cert-agent/config.yaml >> /var/log/cert-agent.log 2>&1
```
