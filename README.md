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
- API Bearer Token generation and revocation.
- REST API protected by Bearer Token Authorization.

### Build & Run
```bash
cd server
go build -o cert-server cmd/main.go
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
- Supports both Linux (`sh -c`) and Windows (`cmd /c`) shell command execution.
- Atomic file writes using temporary files and atomic `os.Rename`.
- Strict file permission `0600` for private key files.
- Special handling for combined cert files (e.g. HAProxy where `certfile == keyfile`).
- Pre-flight directory validation and 30-second context execution timeouts.

### Build
```bash
cd client
go build -o cert-agent cmd/main.go
```

### CLI Commands

#### 1. Check Status (`cert-agent check`)
Displays an ASCII comparison table of local certificate expiration vs server certificate expiration.
```bash
./cert-agent check -c /etc/cert-agent/config.yaml
```

#### 2. Sync Certificates (`cert-agent sync`)
Executes `pre_cmd`, checks SHA256 hashes, downloads new/updated certificates safely, and runs `post_cmd` if updates occurred.
```bash
./cert-agent sync -c /etc/cert-agent/config.yaml
```

---

## 3. Configuration (`config.yaml`)

```yaml
server_url: "http://localhost:8080"
auth_token: "secret-bearer-token-here"

pre_cmd: "nginx -t"

certs:
  - servercert_name: "prod_web_cert"
    certfile: "/etc/nginx/ssl/prod_web.crt"
    keyfile: "/etc/nginx/ssl/prod_web.key"
  
  - servercert_name: "lb_haproxy_cert"
    certfile: "/etc/haproxy/certs/haproxy.pem"
    keyfile: "/etc/haproxy/certs/haproxy.pem"

post_cmd: "systemctl reload nginx"
```

---

## 4. Crontab Setup Example

To automate certificate rotation every 6 hours on Linux:
```cron
0 */6 * * * /usr/local/bin/cert-agent sync -c /etc/cert-agent/config.yaml >> /var/log/cert-agent.log 2>&1
```
