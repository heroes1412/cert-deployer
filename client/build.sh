#!/usr/bin/env bash
set -e
echo "Building Client Agent binaries (Windows & Linux)..."
GOOS=windows GOARCH=amd64 go build -o cert-agent.exe main.go
GOOS=linux GOARCH=amd64 go build -o cert-agent main.go
echo "Client Agent build complete: cert-agent.exe (Windows), cert-agent (Linux)"
