# TASK SPECIFICATION: CENTRALIZED CERTIFICATE MANAGEMENT SYSTEM (SERVER & GO CLIENT)

## 1. GENERAL OVERVIEW
You are a Principal Software Engineer. Build a production-grade, lightweight Certificate Management System consisting of two components:
1. **Server**: Web Admin Dashboard + REST API backed by SQLite for manual SSL/TLS certificate management.
2. **Client**: A CLI Agent written in Go (Golang) that synchronizes certificates based on explicit YAML/JSON configuration without auto-detection magic.
3. Server/client phải chạy được trên linux và windows.

---

## 2. SERVER SPECIFICATIONS

### 2.1 Technology Stack
- **Language/Framework**: Go (Gin/Fiber) - *Specify Go for a single static binary if possible*.
- **Database**: SQLite3 (used for storing metadata, raw PEM contents, and audit logs).
- **Frontend**: Clean, responsive Admin UI (HTML/Tailwind CSS/Alpine.js or basic Bootstrap).

### 2.2 Database Schema (SQLite)
Create a table named `certificates`:
- `id` (INTEGER PRIMARY KEY AUTOINCREMENT)
- `servercert_name` (TEXT UNIQUE NOT NULL) -- Unique identifier/index for client reference
- `cert_data` (TEXT NOT NULL)             -- PEM content of fullchain/certfile
- `key_data` (TEXT NOT NULL)              -- PEM content of keyfile
- `fingerprint_sha256` (TEXT NOT NULL)    -- SHA256 hash of cert_data for quick drift detection
- `not_after` (DATETIME NOT NULL)         -- Expiration date extracted automatically from cert_data
- `created_at` (DATETIME DEFAULT CURRENT_TIMESTAMP)
- `updated_at` (DATETIME DEFAULT CURRENT_TIMESTAMP)

Create a table named `api_tokens`:
- `id` (INTEGER PRIMARY KEY AUTOINCREMENT)
- `token_hash` (TEXT UNIQUE NOT NULL)
- `description` (TEXT)
- `created_at` (DATETIME)

### 2.3 Server Features & UI
1. **Web Admin UI**:
   - **Login Screen**: Basic Auth or Session Token login for Admin.
   - **Dashboard**: Table listing all certificates: `servercert_name`, Expiration Date (`not_after`), Days remaining (with visual warning badge if < 30 days), SHA256 Fingerprint, Last Updated.
   - **Add/Update Cert Modal/Page**: Form to upload/paste `certfile` (PEM) and `keyfile` (PEM) given a specific `servercert_name`.
     - Automatically parse X.509 certificate to extract `not_after` and calculate `sha256_cert`.
     - Validate that `cert_data` matches `key_data` (RSA/ECDSA public key modulus check) before saving.
   - **Delete Cert Action**: Remove certificate bundle.
   - **API Token Management**: Interface to generate/revoke Bearer Tokens for client access.

2. **REST API (Protected by Bearer Token Authorization)**:
   - `GET /api/v1/certs/:servercert_name`
     - Response (JSON):
       ```json
       {
         "servercert_name": "app-prod-wildcard",
         "cert_pem": "-----BEGIN CERTIFICATE-----\n...",
         "key_pem": "-----BEGIN PRIVATE KEY-----\n...",
         "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
         "not_after": "2026-09-15T10:00:00Z"
       }
       ```
   - `GET /api/v1/certs/:servercert_name/meta`
     - Response (JSON): Only metadata (`servercert_name`, `sha256`, `not_after`) without private key data, used for checking status.

---

## 3. CLIENT AGENT SPECIFICATIONS (GOLANG)

### 3.1 Technology Stack & Architecture
- **Language**: Go (v1.20+)
- **CLI Framework**: Cobra or standard `flag`/`os` parsing.
- **Config Parser**: `gopkg.in/yaml.v3` (prefer YAML for human readability).

### 3.2 Configuration File (`config.yaml`)
Path default: `/etc/cert-agent/config.yaml` or passed via `-c /path/to/config.yaml`.

```yaml
server_url: "[https://cert-vault.company.internal](https://cert-vault.company.internal)"
auth_token: "secret-bearer-token-here"

# Command executed BEFORE certificate download/update
# If pre_cmd fails (exit code != 0), the agent MUST abort the process immediately.
pre_cmd: "nginx -t || haproxy -c -f /etc/haproxy/haproxy.cfg" 

# Array of certificate mappings
certs:
  - servercert_name: "prod_web_cert"
    certfile: "/etc/nginx/ssl/prod_web.crt"
    keyfile: "/etc/nginx/ssl/prod_web.key"
  
  - servercert_name: "lb_haproxy_cert"
    certfile: "/etc/haproxy/certs/haproxy.pem" # If keyfile path is empty/same, append key to certfile
    keyfile: "/etc/haproxy/certs/haproxy.pem"

# Command executed AFTER successful certificate update
post_cmd: "systemctl reload nginx || systemctl reload haproxy"

### 3.3 Client CLI Commands
Command 1: agent check
Behavior:

Parse config.yaml.

For each entry in certs:

Read local file at certfile (if exists), parse X.509 expiration date.

Query Server API GET /api/v1/certs/:servercert_name/meta to get server certificate expiration date.

Output a clean ASCII table to standard output:

+-----------------+---------------------+---------------------+----------------+
| SERVERCERT NAME | LOCAL EXPIRATION    | SERVER EXPIRATION   | STATUS         |
+-----------------+---------------------+---------------------+----------------+
| prod_web_cert   | 2026-08-10 (13d)   | 2026-10-01 (65d)    | UPDATE AVAIL   |
| lb_haproxy_cert | 2026-10-01 (65d)    | 2026-10-01 (65d)    | UP TO DATE     |
+-----------------+---------------------+---------------------+----------------+
Command 2: agent sync
Behavior:

Run pre_cmd:

Support inline shell strings or paths to executable shell scripts.

Execute command using sh -c (Linux) or bash -c.

Log stdout/stderr. If exit code != 0, log [ERROR] pre_cmd failed. Aborting update! and exit with code 1.

Fetch and Compare Certificates:

Loop through certs list in config.yaml.

Call Server API GET /api/v1/certs/:servercert_name.

Calculate local file SHA256 or check if local file exists.

If local cert SHA256 matches server SHA256, skip downloading for this cert.

Atomic File Write & Permissions:

If cert is new/updated:

Write certfile and keyfile safely (write to temporary files .tmp first, then atomic os.Rename).

Ensure keyfile permission is strictly set to 0600.

Special handling for combined certs (like HAProxy where certfile == keyfile): concatenate cert_pem + \n + key_pem into single file.

Run post_cmd:

Only if at least ONE certificate was updated during the run.

Execute post_cmd. If exit code != 0, log severe error [ERROR] post_cmd failed after cert update!.

Exit code 0 on success.

4. EDGE CASE & SAFETY REQUIREMENTS
Pre-flight Check: Agent must validate that target directories for certfile and keyfile exist before attempting file writes.

Command Execution Safety: Implement context timeouts (e.g., 30s) for pre_cmd and post_cmd execution to prevent hanging processes.

Non-destructive Failure: If downloading any cert fails midway, do NOT execute post_cmd.

Crontab Friendliness: Output structured, readable logs with timestamps ([INFO], [WARN], [ERROR]) when run non-interactively.

5. DELIVERABLES REQUIRED
Please generate:

Complete Go source code for Server (with SQLite DB initializations and Web HTML templates).

Complete Go source code for Client (agent check and agent sync).

Sample config.yaml for Client.

Deployment steps and example crontab entry for Client.

---

## 6. ACME & EXTENSIONS SPECIFICATION (LET'S ENCRYPT / ZEROSSL & NOTIFICATIONS)

### 6.1 ACME Engine Integration
- **Certificate Authorities**: Let's Encrypt Production, Let's Encrypt Staging, ZeroSSL.
- **Challenge Type**: DNS-01 Challenge Validation (for internal enterprise network isolation without NAT/Public IP).
- **Supported DNS-01 Providers**: Cloudflare DNS, DigitalOcean DNS, AWS Route53, GoDaddy DNS.
- **ZeroSSL EAB**: External Account Binding (`EAB Key ID` & `EAB HMAC Key`).

### 6.2 Multi-Channel Alert Notifications
- Sub-menu tab in Web Admin Settings Modal for configuring expiration warning alerts (7, 14, 30 days thresholds).
- Supported Notification Channels: Telegram Bot, Slack Incoming Webhook, Custom Generic Webhook, Email SMTP.

### 6.3 Client Environment Token Hardening
- `CERT_AGENT_TOKEN` environment variable support in `cert-agent` for ISO 27001 / PCI-DSS compliant token provisioning.