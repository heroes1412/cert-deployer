# Cert Deployer - Centralized Certificate Management System

A production-grade, lightweight Certificate Management System built in Go.

## System Architecture

The **Cert Deployer** solution provides automated, secure, and centralized SSL/TLS certificate management and distribution across enterprise networks (bare-metal, VMs, Docker containers, and Kubernetes clusters).

```mermaid
graph TD
    subgraph WebAdmin["Web Admin & Security"]
        Admin["System Administrator"] -->|"HTTPS / Web UI"| ServerDashboard["Cert Server (Web Admin)"]
        ServerDashboard -->|"SQLite WAL Mode"| DB[("data/cert-server.db")]
        ServerDashboard -->|"12h Ticker (Threshold <= 15d)"| ACMEScheduler["ACME Auto-Renew Scheduler"]
        ServerDashboard -->|"Configurable Interval (Hours)"| NotifyScheduler["Expiration Alert Scheduler"]
    end

    subgraph ExternalServices["External APIs & Proxies"]
        ACMEScheduler -->|"Outbound HTTP/HTTPS/SOCKS5 Proxy"| ACMECA["Let's Encrypt / ZeroSSL (DNS-01)"]
        NotifyScheduler -->|"Telegram / Slack / Webhook / Email"| Channels["Notification Channels"]
    end

    subgraph Clients["Enterprise Infrastructure (500+ Nodes)"]
        Agent1["Cert Agent (Node 1 / Nginx)"]
        Agent2["Cert Agent (Node 2 / HAProxy)"]
        AgentN["Cert Agent (Node N / IIS)"]
    end

    Agent1 -->|"HTTP GET /api/v1/certs/:name (Bearer Token)"| ServerDashboard
    Agent2 -->|"HTTP GET /api/v1/certs/:name (Bearer Token)"| ServerDashboard
    AgentN -->|"HTTP GET /api/v1/certs/:name (Bearer Token)"| ServerDashboard

    Agent1 -->|"Atomic Write 0600 / 0644 (Preserve UID/GID)"| WebFS1["Nginx Certs & Keys"]
    Agent2 -->|"Atomic Write 0600 / 0644 (Preserve UID/GID)"| WebFS2["HAProxy PEM Bundle"]
    AgentN -->|"Atomic Write 0600 / 0644 (Preserve UID/GID)"| WebFS3["IIS Cert Store"]
```

### Component Overview

1. **Cert Server (`/server`)**:
   - **Central Management Vault**: Stores certificate PEM bundles, private keys, SHA256 fingerprints, and expiration dates in a lightweight SQLite database (`data/cert-server.db`).
   - **High-Concurrency Engine**: Configured with SQLite WAL (Write-Ahead Logging) Mode and 100% Read-Only API Token Authentication. Client sync requests perform pure non-blocking `SELECT` queries, supporting 500+ CCU without database lock contention.
   - **Automated ACME Certificate Engine**: Integrated Lego engine (`github.com/go-acme/lego/v4`) supporting 1-click SSL/TLS issuance & auto-renewal for **Let's Encrypt** (Production & Staging) and **ZeroSSL** (via 1-field ZeroSSL API Key or EAB KID & HMAC Key).
   - **Outbound Proxy Support**: Configurable HTTP, HTTPS, and SOCKS5 proxy support (Anonymous & Authenticated) for enterprise environments behind corporate firewalls.
   - **Automated Background Schedulers**:
     - **ACME Auto-Renew Ticker**: Scans every 12 hours and automatically renews ACME certificates expiring within 15 days.
     - **Expiration Alert Scheduler**: Scans at user-defined intervals (in hours) and triggers alerts when certificates reach the warning threshold (e.g. 15 days remaining).
     - **Daily SQLite Maintenance Scheduler**: Runs every 24 hours to execute `PRAGMA wal_checkpoint(TRUNCATE)` and `VACUUM`, preventing WAL journal bloat, defragmenting database pages, and reclaiming disk space.
   - **Multi-Channel Alert System**: Sends notifications to **Telegram Bot**, **Slack Webhook**, **Custom Generic Webhook**, and **Email SMTP** with instant **`🧪 Send Test`** verification.
   - **Enterprise Security & Authentication**:
     - **Bcrypt Password Hashing**: Passwords stored using bcrypt with automatic legacy plain-text migration.
     - **256-Bit Cryptographically Secure Sessions**: Uses `crypto/rand` random session tokens with `SameSite=Lax` and `HttpOnly` cookies.
     - **Dynamic Default Credentials Helper**: Automatically displays default login credentials (`admin / admin123`) on `/login` and auto-hides the banner once password is modified.
   - **Embedded Management UI**: Single-binary deployment containing an embedded Tailwind CSS Web Admin UI for certificate uploading, manual CRT/KEY downloading, live duplicate name checking, password management, and API token generation.

2. **Cert Agent (`/client`)**:
   - **Target Node Synchronization**: Independent Go CLI executable installed on target web servers (Nginx, HAProxy, Apache, IIS, etc.).
   - **Smart Check & Sync Workflow**:
     - Computes local certificate SHA256 fingerprints and compares them against the Cert Server metadata before downloading. Skips download if local files are already up-to-date.
     - Performs **Atomic Writes** using temporary files and atomic `os.Rename` operations to prevent web server downtime or corrupted certificate reads.
     - Automatically inspects and **preserves existing file permissions (Chmod) and ownership (UID/GID)** on Linux/Unix systems so non-root processes (`nginx`, `haproxy`) retain read access.
     - Enforces strict `0600` permissions on new private keys and `0644` on public certificates.
   - **Lifecycle Command Execution**: Executes configurable pre-sync (`global_pre_cmd`, `pre_cmd`) and post-sync (`post_cmd`, `global_post_cmd`) commands/scripts (supporting `.sh`, `.bat`, `.cmd`, `.ps1`, and inline shell pipelines) to validate configs (`nginx -t`) and gracefully reload web servers (`systemctl reload nginx`).

---

## 1. Cert Server (`/server`)

### Features
- Embedded Web Admin UI (built with Go `embed.FS` and Tailwind CSS).
- **Automated ACME Certificate Engine**:
  - Supports **Let's Encrypt** (Production & Staging) and **ZeroSSL**.
  - **Single ZeroSSL API Key Integration**: Enter just your single ZeroSSL API Key; the backend automatically retrieves EAB KID & HMAC Key on-the-fly via ZeroSSL REST API. Also supports direct EAB KID & HMAC Key input.
  - **Background ACME Auto-Renew Scheduler**: Ticker runs every 12 hours, auto-renewing ACME certs with `daysLeft <= 15`.
  - **ACME Re-Issuance**: `Re-issue ACME` button appears exclusively for ACME certificates, locking the certificate name and auto-populating previous domain, provider, and DNS token metadata.
- **DNS-01 Challenge Validation**: Native DNS-01 automation for **Cloudflare**, **DigitalOcean**, **AWS Route53**, and **GoDaddy** (no public IP or NAT Port 80/443 required).
- **Outbound HTTP / HTTPS / SOCKS5 Proxy**:
  - Dedicated Proxy settings supporting **Anonymous** (`http://192.168.1.100:8080`) or **Authenticated** (`http://user:pass@proxy.company.com:8080`) proxies.
  - Automatically applied to ACME certificate issuance, auto-renewals, and notification channels.
- **Automated Notification Alert Engine**:
  - User-configurable **`Expiration Warning Days Threshold`** (e.g. 15 days) and **`Notification Check Interval (Hours)`** (e.g. 12 hours).
  - Multi-channel support: **Telegram Bot**, **Slack Incoming Webhook**, **Custom Generic Webhook** (with secret header), and **Email SMTP**.
  - **Instant `🧪 Send Test` Button**: Realtime AJAX test notification directly from the modal without needing to save settings first.
- **Automated Daily SQLite Maintenance & VACUUM**:
  - Ticker runs every 24 hours (and 1 minute post-startup) executing `PRAGMA wal_checkpoint(TRUNCATE)` and `VACUUM` to defragment SQLite storage and truncate WAL logs.
- **Security & Authentication Hardening**:
  - Bcrypt password hashing (`golang.org/x/crypto/bcrypt`) with automatic legacy plain-text migration.
  - Cryptographically secure 256-bit random session token generation (`crypto/rand`) with `SameSite=Lax` & `HttpOnly` cookies.
  - Dynamic Default Credential Helper banner (`admin / admin123`) on `/login` that automatically disappears upon initial password change.
- **Dashboard Summary Stat Cards**: 3 top-level KPI metrics displaying Total Certificates, Expiring Soon (&le;15 days), and Active ACME Auto-Renew.
- **Agent Nodes Registry & Sync History**:
  - Light-weight `POST /api/v1/agent/heartbeat` endpoint for `cert-agent` nodes.
  - Automatically records agent hostname, IP address, OS/arch, list of synced certificates, and last sync timestamp upon completion of `cert-agent check` or `cert-agent sync` runs.
  - Serves as a historical registry of target web servers that have synced with Cert Server (without maintaining long-lived TCP/WebSocket connections).
- **Security Audit Logs (Modal UI & 6-Month Retention)**:
  - Full activity log recording timestamp, client IP, action (`User Login`, `Create Manual Cert`, `Update Manual Cert`, `Issue ACME Cert`, `Delete Certificate`, `Generate API Token`, `Revoke API Token`, `Update Settings`), and event details.
  - Accessible directly via the **`📋 Audit Logs`** button on the top navigation bar next to **`⚙️ Settings`**.
  - **Automatic 6-Month Retention Policy**: Integrated into the daily SQLite maintenance scheduler to automatically purge audit log records older than 6 months (180 days).
- **Enhanced Edit Certificate Modal**:
  - `📋 Copy Cert` and `📋 Copy Key` buttons alongside `💾 Download Cert` and `💾 Download Key` for fast clipboard copying (hidden during new manual cert creation).
- **REST API protected by Bearer Token Authorization.**
- Native Windows Service support (via Windows SCM) with automatic error logging to `cert-server.log`.
- **Go 1.26+ Compatible**: Build scripts use `-ldflags="-s -w"` stripping debug symbols to produce optimized ~28MB binaries.

### Build & Run (Bare Metal / VM)
```bash
cd server
go build -ldflags="-s -w" -o cert-server main.go
./cert-server
```
By default, the server runs on `http://localhost:8080` (Default credentials: Username `admin`, Password `admin123`).

Environment variables:
- `PORT`: HTTP listener port (default `8080` or configured via Web UI Settings).
- `DB_PATH`: SQLite database file path (default `data/cert-server.db`).

---

## 2. Docker & Kubernetes Deployment (Cert Server)

### A. Docker Compose Deployment (1-Command Run)
Run the server using Docker Compose with volume persistence at `/app/data`:
```bash
docker-compose up -d --build
```
This builds the multi-stage `server/Dockerfile` (~15MB image) and mounts persistent database storage to named volume `cert-server-data`.

### B. Kubernetes Deployment (K8s)
All Kubernetes manifests are provided under [`deploy/k8s/`](file:///C:/Users/Administrator/Desktop/cert-rotate-tool/deploy/k8s):

1. **Apply PVC (PersistentVolumeClaim)**:
   ```bash
   kubectl apply -f deploy/k8s/pvc.yaml
   ```
2. **Apply Deployment**:
   ```bash
   kubectl apply -f deploy/k8s/deployment.yaml
   ```
3. **Apply ClusterIP Service**:
   ```bash
   kubectl apply -f deploy/k8s/service.yaml
   ```
4. **Apply Ingress**:
   ```bash
   kubectl apply -f deploy/k8s/ingress.yaml
   ```

---

## 3. Cert Agent Component (`/client`)

### Features
- CLI Commands: `cert-agent check` and `cert-agent sync`.
- **Environment Variable Auth Token**: Supports reading Bearer token from `CERT_AGENT_TOKEN` environment variable (overriding/supplementing `config.yaml` for ISO 27001 / PCI-DSS compliance).
- Auto-detects `./config.yaml` in the current working directory if `-c` is omitted.
- Supports both Linux (`sh -c`) and Windows (`cmd /c`) shell command and script file execution.
- Global commands (`global_pre_cmd`, `global_post_cmd`) and per-certificate commands (`pre_cmd`, `post_cmd`).
- Robust Windows path preprocessing: supports natural single backslashes `\` (`"D:\tmp\1 1\expired.pem"`) without YAML escape errors.
- Automatic backup of existing cert/key files before overwriting (saves copy in the same directory as `<filename>.<DDMMYYYY>.bak` preserving mode/owner).
- Atomic file writes using temporary files and atomic `os.Rename`.
- Preserves existing file permissions (Mode) and ownership (UID/GID on Linux/Unix).
- Strict file permission `0600` fallback for new private key files (`0644` for public certs).
- Checks local file existence: skips syncing if local `certfile` or `keyfile` does not exist.
- Native PKCS#12 (`.pfx`) generation in pure Go (triggered automatically by configuring `pfxfile` in `config.yaml`).
- Automatic Windows Certificate Store (`Cert:\LocalMachine\My`) import and IIS Web Site HTTPS rebinding (`iis_site_name`, `iis_binding_host`).
- Automatic parent directory creation (`os.MkdirAll`) for missing target certificate paths.
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

---

## 4. Native System Services Setup & Management

### A. Windows Service Setup & Removal (Native `sc.exe`)
No third-party tools required. Uses Windows native `sc.exe`:

- **Install & Start Service**: Run `scripts/service_install_windows.bat` as Administrator:
  ```cmd
  scripts\service_install_windows.bat
  ```
- **Stop & Uninstall Service**: Run `scripts/service_uninstall_windows.bat` as Administrator:
  ```cmd
  scripts\service_uninstall_windows.bat
  ```

### B. Linux Service Setup & Removal (Native Systemd)
Run automated Linux service management scripts as root:

- **Install & Start Services**:
  ```bash
  sudo ./scripts/service_install_linux.sh
  ```
- **Stop & Uninstall Services**:
  ```bash
  sudo ./scripts/service_uninstall_linux.sh
  ```

---

## 5. Configuration Guide (`config.yaml`)

```yaml
server_url: "http://localhost:8080"
auth_token: "secret-bearer-token-here"

global_pre_cmd: "echo 'Starting cert sync session...'"

certs:
  - servercert_name: "prod_web_cert"
    certfile: "D:\vnshell\it\Linux\prod_web.crt"
    keyfile: "D:\vnshell\it\Linux\prod_web.key"
    pre_cmd: "nginx -t"
    post_cmd: "systemctl reload nginx"

global_post_cmd: "echo 'Cert sync session completed successfully!'"
```

### Script & Command Declaration Examples

#### Windows (`cmd.exe`)

1. **Standard `.bat` / `.cmd` Script**:
   ```yaml
   global_pre_cmd: "C:\scripts\pre_check.bat"
   # Or unquoted:
   global_pre_cmd: C:\scripts\pre_check.bat
   ```

2. **Script Path with Spaces**:
   ```yaml
   global_pre_cmd: '"C:\My Scripts\pre_check.bat"'
   ```

3. **PowerShell Script (`.ps1`)**:
   ```yaml
   global_pre_cmd: "powershell -ExecutionPolicy Bypass -File C:\scripts\pre_check.ps1"
   ```

4. **Script with Arguments**:
   ```yaml
   global_pre_cmd: "C:\scripts\pre_check.bat --env prod --port 8080"
   ```

5. **Inline Commands**:
   ```yaml
   global_pre_cmd: "copy nul c:\global_precmd.txt"
   ```

---

#### Linux (`sh`)

1. **Shell Script (`.sh`)**:
   ```yaml
   global_pre_cmd: "/usr/local/bin/pre_check.sh"
   # Or via bash:
   global_pre_cmd: "bash /etc/cert-agent/scripts/pre_check.sh"
   ```

2. **Script with Arguments**:
   ```yaml
   global_pre_cmd: "/usr/local/bin/pre_check.sh --check-all"
   ```

3. **Inline Commands**:
   ```yaml
   global_pre_cmd: "nginx -t && systemctl reload nginx"
   ```
