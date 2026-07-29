# Implementation Plan: Docker & Kubernetes Support for Server

> **Goal:** Update DB path logic to support `data/` folder, create multi-stage `server/Dockerfile`, `docker-compose.yml`, and Kubernetes manifests (`pvc`, `deployment`, `service`, `ingress`).

---

## Tasks

### Task 1: Update Server Go Code for `data/` Directory DB Fallback
- Modify `server/main.go` and `server/cmd/main.go`:
  - Update `dbPath` resolution: Check `DB_PATH` env var. If empty, check if `cert-vault.db` exists in root. Otherwise use `filepath.Join("data", "cert-vault.db")` and create `data/` directory if missing.

### Task 2: Create Multi-stage `server/Dockerfile`
- Create `server/Dockerfile`:
  - Builder stage: `golang:1.20-alpine`, `CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o cert-server .`
  - Runtime stage: `alpine:latest`, `ca-certificates`, `tzdata`, `/app/data` volume, `PORT=8080`, `DB_PATH=/app/data/cert-vault.db`.

### Task 3: Create `docker-compose.yml`
- Create `docker-compose.yml` in root directory:
  - Build `server/`.
  - Port mapping `8080:8080`.
  - Named volume `cert-vault-data` mounted to `/app/data`.

### Task 4: Create Kubernetes Manifests in `deploy/k8s/`
- Create `deploy/k8s/cert-server-pvc.yaml`
- Create `deploy/k8s/cert-server-deployment.yaml`
- Create `deploy/k8s/cert-server-service.yaml`
- Create `deploy/k8s/cert-server-ingress.yaml`

### Task 5: Build & Verify
- Run `.\build.bat` to verify Go binaries build cleanly.
- Document Docker & K8s deployment instructions in `README.md`.
