#!/usr/bin/env python3

import sys
import os
import json
from pathlib import Path

BASE_DIR = Path(os.environ.get("OTX_SEC_BASE_DIR", Path(__file__).resolve().parent))
sys.path.insert(0, str(BASE_DIR / "app"))

import db
import backend

LOG_DIR = Path(os.environ.get("OTX_SEC_LOG_DIR", BASE_DIR / "data" / "logs"))

MAP = {
    "File Scanner": "report.jsonl",
    "Processes": "process_report.jsonl",
    "Network": "network_report.jsonl",
    "Persistence": "persistence_report.jsonl",
    "Integrity": "integrity_report.jsonl",
    "Auditd": "audit_report.jsonl",
}

def obj(row):
    return str(
        row.get("file")
        or row.get("exe")
        or row.get("process")
        or row.get("remote_ip")
        or row.get("key")
        or ""
    )

def main():
    db.clear_events()

    count = 0

    for source, filename in MAP.items():
        path = LOG_DIR / filename

        if not path.exists():
            continue

        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                try:
                    row = json.loads(line)
                except Exception:
                    continue

                severity = backend.classify(row)
                event = row.get("event", row.get("status", "EVENT"))

                db.insert_event(
                    source,
                    severity,
                    event,
                    obj(row),
                    row,
                )

                count += 1

    print(f"Imported events: {count}")

if __name__ == "__main__":
    main()
