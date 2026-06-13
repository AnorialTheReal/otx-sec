#!/usr/bin/env python3

import os
import sys
import subprocess
from pathlib import Path

BASE_DIR = Path(os.environ.get("OTX_SEC_BASE_DIR", Path(__file__).resolve().parent))
APP_DIR = Path(os.environ.get("OTX_SEC_APP_DIR", BASE_DIR / "app"))
sys.path.insert(0, str(APP_DIR))

import backend


def notify(message):
    cmd = [
        "notify-send",
        "OTX-Sec Alert",
        str(message)[:1000],
    ]

    env = os.environ.copy()
    env.setdefault("DISPLAY", ":0")

    try:
        subprocess.Popen(
            cmd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        print(f"[NOTIFY] {message}", flush=True)


def choose_action(file_path):
    cmd = [
        "kdialog",
        "--menu",
        f"Suspicious file detected:\n{file_path}",
        "allow", "Allow",
        "block", "Block / Quarantine",
        "analyze", "Analyze",
        "ignore", "Ignore",
    ]

    env = os.environ.copy()
    env.setdefault("DISPLAY", ":0")

    try:
        result = subprocess.run(
            cmd,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        action = result.stdout.strip()
        if action in {"allow", "block", "analyze", "ignore"}:
            return action
        return "ignore"
    except Exception:
        return "ignore"


def main():
    if len(sys.argv) < 2:
        print("Usage: alert_action.py /path/to/file")
        return

    file_path = str(Path(sys.argv[1]).expanduser())

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
