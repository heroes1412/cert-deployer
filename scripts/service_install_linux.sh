#!/usr/bin/env bash
# Automated Linux systemd service installer for Cert Deployer (Cert Server & Cert Agent)
set -e

if [ "$EUID" -ne 0 ]; then
  echo "[ERROR] Please run as root (sudo ./service_install_linux.sh)"
  exit 1
fi

echo "==================================================="
echo "Installing Cert Deployer (Cert Server & Cert Agent) systemd Services"
echo "==================================================="

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

# 1. Install Server Service
echo "[1/2] Setting up Cert Server Service..."
mkdir -p /opt/cert-server
if [ -f "$ROOT_DIR/build/linux/cert-server" ]; then
    cp "$ROOT_DIR/build/linux/cert-server" /opt/cert-server/cert-server
    chmod +x /opt/cert-server/cert-server
fi

cp "$SCRIPT_DIR/cert-server.service" /etc/systemd/system/cert-server.service
systemctl daemon-reload
systemctl enable cert-server.service
echo "[INFO] Cert Server service installed! Start via: systemctl start cert-server"

# 2. Install Client Service & Timer
echo "[2/2] Setting up Cert Agent Service & Timer..."
mkdir -p /etc/cert-agent
if [ -f "$ROOT_DIR/build/linux/cert-agent" ]; then
    cp "$ROOT_DIR/build/linux/cert-agent" /usr/local/bin/cert-agent
    chmod +x /usr/local/bin/cert-agent
fi

if [ ! -f /etc/cert-agent/config.yaml ] && [ -f "$ROOT_DIR/client/config.yaml.example" ]; then
    cp "$ROOT_DIR/client/config.yaml.example" /etc/cert-agent/config.yaml
    echo "[INFO] Created default config file at /etc/cert-agent/config.yaml"
fi

cp "$SCRIPT_DIR/cert-agent.service" /etc/systemd/system/cert-agent.service
cp "$SCRIPT_DIR/cert-agent.timer" /etc/systemd/system/cert-agent.timer
systemctl daemon-reload
systemctl enable --now cert-agent.timer
echo "[INFO] Cert Agent timer installed & activated! Check status via: systemctl status cert-agent.timer"

echo "==================================================="
echo "Linux Systemd Services Successfully Installed!"
echo "==================================================="
