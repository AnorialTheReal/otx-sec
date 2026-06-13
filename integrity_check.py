#!/usr/bin/env python3

import os
import json
import hashlib
from datetime import datetime

DB_FILE = "/opt/otx-sec/db/system_hashes.json"
REPORT_FILE = "/var/log/otx-sec/integrity_report.jsonl"

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def write_report(entry):
    with open(REPORT_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")

def main():
    with open(DB_FILE, "r") as f:
        baseline = json.load(f)

    changed = 0
    missing = 0

    for path, info in baseline["files"].items():
        if not os.path.exists(path):
            missing += 1
            write_report({
                "time": datetime.now().isoformat(),
                "event": "MISSING_FILE",
                "file": path,
                "old_sha256": info["sha256"],
                "recommendation": "Prüfen, ob Paketupdate oder verdächtige Löschung."
            })
            continue

        try:
            current_hash = sha256(path)
            if current_hash != info["sha256"]:
                changed += 1
                write_report({
                    "time": datetime.now().isoformat(),
                    "event": "CHANGED_FILE",
                    "file": path,
                    "old_sha256": info["sha256"],
                    "new_sha256": current_hash,
                    "recommendation": "Prüfen: pacman -Qo DATEI und pacman -Qkk PAKET."
                })
        except Exception as e:
            write_report({
                "time": datetime.now().isoformat(),
                "event": "ERROR",
                "file": path,
                "error": str(e)
            })

    print(f"Integrity check complete. Changed: {changed}, Missing: {missing}")
    print(f"Report: {REPORT_FILE}")

if __name__ == "__main__":
    main()
