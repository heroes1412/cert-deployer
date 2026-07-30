#!/usr/bin/env bash
# Automated Linux systemd service uninstaller for Cert Deployer (Cert Server & Cert Agent)
set -e

if [ "$EUID" -ne 0 ]; then
  echo "[ERROR] Please run as root (sudo ./service_uninstall_linux.sh)"
  exit 1
fi

echo "==================================================="
echo "Uninstalling Cert Deployer (Cert Server & Cert Agent) Services"
echo "==================================================="

# 1. Stop & disable Cert Agent timer and service
echo "[1/2] Removing Cert Agent Service & Timer..."
if systemctl is-active --quiet cert-agent.timer 2>/dev/null; then
    systemctl stop cert-agent.timer
fi
if systemctl is-enabled --quiet cert-agent.timer 2>/dev/null; then
    systemctl disable cert-agent.timer
fi

if systemctl is-active --quiet cert-agent.service 2>/dev/null; then
    systemctl stop cert-agent.service
fi
if systemctl is-enabled --quiet cert-agent.service 2>/dev/null; then
    systemctl disable cert-agent.service
fi

rm -f /etc/systemd/system/cert-agent.service
rm -f /etc/systemd/system/cert-agent.timer
rm -f /usr/local/bin/cert-agent
echo "[INFO] Cert Agent services removed."

# 2. Stop & disable Cert Server service
echo "[2/2] Removing Cert Server Service..."
if systemctl is-active --quiet cert-server.service 2>/dev/null; then
    systemctl stop cert-server.service
fi
if systemctl is-enabled --quiet cert-server.service 2>/dev/null; then
    systemctl disable cert-server.service
fi

rm -f /etc/systemd/system/cert-server.service
echo "[INFO] Cert Server service removed."

systemctl daemon-reload

echo "==================================================="
echo "Linux Systemd Services Successfully Uninstalled!"
echo "==================================================="
