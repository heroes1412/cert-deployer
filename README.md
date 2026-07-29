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

## 3. Native System Services Setup (Windows sc.exe & Linux Systemd)

### A. Windows Service Setup (Native `sc.exe`)
No third-party tools (like NSSM) required. Uses Windows native `sc.exe`:

1. Build binaries using `build.bat`.
2. Run `scripts/service_install_windows.bat` as Administrator:
   ```cmd
   scripts\service_install_windows.bat
   ```
   Or register manually via Windows Command Prompt (Admin):
   ```cmd
   sc create CertVaultServer binPath= "C:\path\to\build\windows\cert-server.exe" start= auto displayname= "Cert Vault Server Service"
   sc start CertVaultServer
   ```
   Useful Service commands:
   ```cmd
   sc query CertVaultServer
   sc stop CertVaultServer
   sc delete CertVaultServer
   ```

### B. Linux Service Setup (Native Systemd)
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
