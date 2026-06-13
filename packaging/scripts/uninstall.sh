#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="${OTX_SEC_BASE_DIR:-/opt/otx-sec}"

if [[ $EUID -ne 0 ]]; then
  echo "Please run as root: sudo ./packaging/scripts/uninstall.sh"
  exit 1
fi

echo "[*] Uninstalling OTX-Sec from $BASE_DIR"

systemctl disable --now otx-sec.service 2>/dev/null || true
systemctl disable --now otx-network-monitor.service 2>/dev/null || true
systemctl disable --now otx-process-monitor.service 2>/dev/null || true
systemctl disable --now otx-persistence-monitor.service 2>/dev/null || true
systemctl disable --now otx-audit-exporter.service 2>/dev/null || true
systemctl disable --now otx-incident-engine.service 2>/dev/null || true

rm -f /etc/systemd/system/otx-sec.service
rm -f /etc/systemd/system/otx-network-monitor.service
rm -f /etc/systemd/system/otx-process-monitor.service
rm -f /etc/systemd/system/otx-persistence-monitor.service
rm -f /etc/systemd/system/otx-audit-exporter.service
rm -f /etc/systemd/system/otx-incident-engine.service
rm -f /usr/local/bin/otx-sec-gui

systemctl daemon-reload

echo "[*] Keeping data/config by default:"
echo "    $BASE_DIR/config"
echo "    $BASE_DIR/data"
echo "    $BASE_DIR/db"
echo
echo "To remove everything manually:"
echo "    sudo rm -rf $BASE_DIR"
