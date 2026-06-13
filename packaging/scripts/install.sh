#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="${OTX_SEC_BASE_DIR:-/opt/otx-sec}"
PYTHON_BIN="${PYTHON:-python3}"

echo "[*] Installing OTX-Sec to $BASE_DIR"

if [[ $EUID -ne 0 ]]; then
  echo "Please run as root: sudo ./packaging/scripts/install.sh"
  exit 1
fi

mkdir -p "$BASE_DIR"

rsync -a --delete \
  --exclude ".git" \
  --exclude "venv" \
  --exclude "__pycache__" \
  --exclude "data" \
  --exclude "analysis" \
  --exclude "exports" \
  --exclude "db/*.db" \
  --exclude "db/*.json" \
  ./ "$BASE_DIR/"

cd "$BASE_DIR"

$PYTHON_BIN -m venv venv
"$BASE_DIR/venv/bin/python" -m pip install --upgrade pip
"$BASE_DIR/venv/bin/python" -m pip install -r requirements.txt

mkdir -p "$BASE_DIR/data/logs" "$BASE_DIR/data/quarantine" "$BASE_DIR/db" "$BASE_DIR/config"

if [[ ! -f "$BASE_DIR/config/settings.json" ]]; then
  cp "$BASE_DIR/config/settings.example.json" "$BASE_DIR/config/settings.json"
  chmod 600 "$BASE_DIR/config/settings.json"
fi

ln -sf "$BASE_DIR/otx-sec-gui" /usr/local/bin/otx-sec-gui

if command -v systemctl >/dev/null 2>&1; then
  cp "$BASE_DIR"/packaging/systemd/*.service /etc/systemd/system/
  systemctl daemon-reload
  echo "[*] Services installed. Enable with:"
  echo "    sudo systemctl enable --now otx-sec-agent otx-process-monitor otx-network-monitor"
fi

echo "[+] Installed."
echo "Run GUI with: otx-sec-gui"
