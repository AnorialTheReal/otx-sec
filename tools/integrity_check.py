#!/usr/bin/env python3

import os
import json
import hashlib
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(os.environ.get("OTX_SEC_BASE_DIR", Path(__file__).resolve().parent))
DB_FILE = str(Path(os.environ.get("OTX_SEC_SYSTEM_HASHES", BASE_DIR / "db" / "system_hashes.json")))
REPORT_FILE = str(Path(os.environ.get("OTX_SEC_INTEGRITY_REPORT", BASE_DIR / "data" / "logs" / "integrity_report.jsonl")))

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
                "recommendation": "Check whether this was caused by a package update or a suspicious deletion."
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
                    "recommendation": "Check with: pacman -Qo FILE and pacman -Qkk PACKAGE."
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
