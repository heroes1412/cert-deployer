#!/usr/bin/env bash
set -e

echo "==================================================="
echo "Building Cert Deployer Solution (Cert Server & Cert Agent)"
echo "==================================================="

mkdir -p build/windows build/linux

echo ""
echo "[1/4] Building Cert Server for Windows (build/windows/cert-server.exe)..."
(cd server && GOOS=windows GOARCH=amd64 go build -o ../build/windows/cert-server.exe .)

echo "[2/4] Building Cert Server for Linux (build/linux/cert-server)..."
(cd server && GOOS=linux GOARCH=amd64 go build -o ../build/linux/cert-server .)

echo ""
echo "[3/4] Building Cert Agent for Windows (build/windows/cert-agent.exe)..."
(cd client && GOOS=windows GOARCH=amd64 go build -o ../build/windows/cert-agent.exe .)

echo "[4/4] Building Cert Agent for Linux (build/linux/cert-agent)..."
(cd client && GOOS=linux GOARCH=amd64 go build -o ../build/linux/cert-agent .)

echo ""
echo "==================================================="
echo "SUCCESS: All binaries successfully built!"
echo "Output Directory:"
echo "  - Windows: build/windows/cert-server.exe, build/windows/cert-agent.exe"
echo "  - Linux:   build/linux/cert-server, build/linux/cert-agent"
echo "==================================================="
