#!/opt/otx-sec/venv/bin/python

import sys
import subprocess
from pathlib import Path

APP_DIR = "/opt/otx-sec/app"
sys.path.insert(0, APP_DIR)

import backend


def notify(message):
    subprocess.Popen([
        "sudo", "-u", "anorial",
        "env",
        "DISPLAY=:0",
        "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus",
        "notify-send",
        "OTX-Sec Alert",
        message
    ])


def choose_action(file_path):
    cmd = [
        "sudo", "-u", "anorial",
        "env",
        "DISPLAY=:0",
        "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus",
        "kdialog",
        "--menu",
        f"Suspicious file detected:\n{file_path}",
        "allow", "Allow",
        "block", "Block / Quarantine",
        "analyze", "Analyze",
        "ignore", "Ignore"
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return result.stdout.strip()
    except Exception:
        return "ignore"


def main():
    if len(sys.argv) < 2:
        print("Usage: alert_action.py /path/to/file")
        return

    file_path = sys.argv[1]

    if not Path(file_path).exists():
        print("File not found.")
        return

    action = choose_action(file_path)

    if action == "allow":
        print(backend.allow_path(file_path))
        notify("File allowed.")

    elif action == "block":
        print(backend.block_path(file_path))
        notify("File blocked and quarantined.")

    elif action == "analyze":
        print(backend.analyze_path(file_path))
        notify("Analysis created.")

    else:
        print("Ignored.")


if __name__ == "__main__":
    main()
