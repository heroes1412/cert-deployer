# Stage 1: Build static Go binary
FROM golang:1.20-alpine AS builder

WORKDIR /app

# Copy dependency manifests
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Compile lightweight static binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o cert-server .

# Stage 2: Minimal runtime image
FROM alpine:latest

WORKDIR /app

# Install SSL certificates and timezone data
RUN apk add --no-cache ca-certificates tzdata

# Create data directory for SQLite persistence
RUN mkdir -p /app/data

# Copy compiled binary from builder stage
COPY --from=builder /app/cert-server /app/cert-server

# Environment variables
ENV PORT=8080
ENV DB_PATH=/app/data/cert-vault.db

# Expose server port
EXPOSE 8080

# Persistent volume for SQLite DB
VOLUME ["/app/data"]

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --quiet --tries=1 --spider http://localhost:8080/login || exit 1

# Run server
ENTRYPOINT ["/app/cert-server"]
