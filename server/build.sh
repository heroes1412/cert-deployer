#!/usr/bin/env bash
set -e
echo "Building Server binaries (Windows & Linux)..."
GOOS=windows GOARCH=amd64 go build -o cert-server.exe main.go
GOOS=linux GOARCH=amd64 go build -o cert-server main.go
echo "Server build complete: cert-server.exe (Windows), cert-server (Linux)"
