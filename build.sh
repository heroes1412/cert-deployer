#!/usr/bin/env bash
set -e

echo "==================================================="
echo "Building Cert Deployer Server and Client (Windows & Linux)"
echo "==================================================="

mkdir -p build/windows build/linux

echo ""
echo "[1/4] Building Server for Windows (build/windows/cert-deployer-server.exe)..."
(cd server && GOOS=windows GOARCH=amd64 go build -o ../build/windows/cert-deployer-server.exe .)

echo "[2/4] Building Server for Linux (build/linux/cert-deployer-server)..."
(cd server && GOOS=linux GOARCH=amd64 go build -o ../build/linux/cert-deployer-server .)

echo ""
echo "[3/4] Building Client Agent for Windows (build/windows/cert-deployer-agent.exe)..."
(cd client && GOOS=windows GOARCH=amd64 go build -o ../build/windows/cert-deployer-agent.exe .)

echo "[4/4] Building Client Agent for Linux (build/linux/cert-deployer-agent)..."
(cd client && GOOS=linux GOARCH=amd64 go build -o ../build/linux/cert-deployer-agent .)

echo ""
echo "==================================================="
echo "SUCCESS: All binaries successfully built!"
echo "Output Directory:"
echo "  - Windows: build/windows/cert-deployer-server.exe, build/windows/cert-deployer-agent.exe"
echo "  - Linux:   build/linux/cert-deployer-server, build/linux/cert-deployer-agent"
echo "==================================================="
