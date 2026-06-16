

#!/usr/bin/env python3

import os
import json
import time
import hashlib
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(os.environ.get("OTX_SEC_BASE_DIR", Path(__file__).resolve().parent))
REPORT = str(Path(os.environ.get("OTX_SEC_PERSISTENCE_REPORT", BASE_DIR / "data" / "logs" / "persistence_report.jsonl")))
DB = str(Path(os.environ.get("OTX_SEC_PERSISTENCE_DB", BASE_DIR / "db" / "persistence_baseline.json")))

WATCH_PATHS = [
    "/etc/systemd/system",
    "/usr/lib/systemd/system",
    "/etc/cron.d",
    "/var/spool/cron",
    "/etc/profile.d",
    "/etc/xdg/autostart",
    str(Path.home() / ".config" / "autostart"),
]

INTERVAL = 60

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def write_report(entry):
    with open(REPORT, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")

def collect():
    data = {}

    for base in WATCH_PATHS:
        if not os.path.exists(base):
            continue

        for root, dirs, files in os.walk(base):
            for name in files:
                path = os.path.join(root, name)

                if not os.path.isfile(path) or os.path.islink(path):
                    continue

                try:
                    data[path] = {
                        "sha256": sha256(path),
                        "size": os.path.getsize(path),
                        "mtime": os.path.getmtime(path),
                    }
                except Exception:
                    pass

    return data

def load_baseline():
    if not os.path.exists(DB):
        data = collect()
        with open(DB, "w") as f:
            json.dump(data, f, indent=2)

        print(f"[*] Persistence baseline created: {len(data)} files", flush=True)
        return data

    with open(DB, "r") as f:
        return json.load(f)

def save_baseline(data):
    with open(DB, "w") as f:
        json.dump(data, f, indent=2)

def check():
    baseline = load_baseline()
    current = collect()

    for path, info in current.items():
        if path not in baseline:
            entry = {
                "time": datetime.now().isoformat(),
                "event": "NEW_PERSISTENCE_FILE",
                "file": path,
                "sha256": info["sha256"],
                "recommendation": "Review with: systemctl cat FILE. Inspect the content and disable unknown autostarts."
            }
            write_report(entry)
            print(f"[!] New persistence file: {path}", flush=True)

        elif baseline[path]["sha256"] != info["sha256"]:
            entry = {
                "time": datetime.now().isoformat(),
                "event": "CHANGED_PERSISTENCE_FILE",
                "file": path,
                "old_sha256": baseline[path]["sha256"],
                "new_sha256": info["sha256"],
                "recommendation": "Review the change. If unknown: back up the file, verify the hash, and disable the service."
            }
            write_report(entry)
            print(f"[!] Changed persistence file: {path}", flush=True)

    for path in baseline:
        if path not in current:
            entry = {
                "time": datetime.now().isoformat(),
                "event": "REMOVED_PERSISTENCE_FILE",
                "file": path,
                "recommendation": "Review removal event. This may be normal after package updates."
            }
            write_report(entry)
            print(f"[!] Removed persistence file: {path}", flush=True)

    save_baseline(current)

def main():
    print("[*] Persistence monitor started", flush=True)

    while True:
        check()
        time.sleep(INTERVAL)

if __name__ == "__main__":
    main()
