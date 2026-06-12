#!/opt/otx-sec/venv/bin/python

import sys
import json
from pathlib import Path

sys.path.insert(0, "/opt/otx-sec/app")

import db
import backend

LOG_DIR = Path("/var/log/otx-sec")

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
