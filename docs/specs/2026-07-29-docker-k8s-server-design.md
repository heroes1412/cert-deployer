# Server Docker & Kubernetes Deployment Design Specification

## 1. Overview
Design and implement containerization for **Cert Vault Server**:
1. Support flexible database path handling (`DB_PATH`) in Go backend with fallback to `data/cert-vault.db` (and backward compatibility for root `cert-vault.db`).
2. Create multi-stage `Dockerfile` (`server/Dockerfile`) for building an ultra-lightweight Docker image (~15MB).
3. Create `docker-compose.yml` for 1-command Docker deployment.
4. Create production-ready Kubernetes manifests in `deploy/k8s/` (Deployment, Service, PVC, Ingress).

---

## 2. Technical Specifications

### 2.1 Database Path Handling (`server/main.go` & `server/cmd/main.go`)
- Check `os.Getenv("DB_PATH")`.
- If empty:
  - If `cert-vault.db` exists in current directory, use `"cert-vault.db"`.
  - Else use `filepath.Join("data", "cert-vault.db")` (automatically creates `data/` directory).

### 2.2 Dockerfile (`server/Dockerfile`)
- Stage 1: `golang:1.20-alpine` builder. `CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o cert-server .`
- Stage 2: `alpine:latest` runtime. Install `ca-certificates` & `tzdata`. Expose port `8080`.
- Health check via `GET /login`.

### 2.3 Docker Compose (`docker-compose.yml`)
- Service `cert-server`.
- Volume `cert-vault-data` mounted to `/app/data`.
- Environment: `PORT=8080`, `DB_PATH=/app/data/cert-vault.db`.

### 2.4 Kubernetes Manifests (`deploy/k8s/`)
- `pvc.yaml`: PersistentVolumeClaim (1Gi, ReadWriteOnce).
- `deployment.yaml`: Deployment with 1 replica, mounted PVC to `/app/data`, liveness & readiness probes.
- `service.yaml`: ClusterIP Service exposing port 8080.
- `ingress.yaml`: Ingress manifest for external HTTPS access.
