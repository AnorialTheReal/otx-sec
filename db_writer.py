#!/usr/bin/env python3
import sys, json, time
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

OFFSETS = {}

def event_object(row):
    return str(row.get("file") or row.get("exe") or row.get("process") or row.get("remote_ip") or row.get("key") or "")

def import_once():
    count = 0
    for source, filename in MAP.items():
        path = LOG_DIR / filename
        if not path.exists():
            continue

        pos = OFFSETS.get(str(path), 0)

        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            f.seek(pos)
            for line in f:
                try:
                    row = json.loads(line)
                except Exception:
                    continue

                db.insert_event(
                    source,
                    backend.classify(row),
                    row.get("event", row.get("status", "EVENT")),
                    event_object(row),
                    row,
                )
                count += 1

            OFFSETS[str(path)] = f.tell()

    return count

def main():
    db.init_db()
    print("[*] db_writer started", flush=True)
    while True:
        c = import_once()
        if c:
            print(f"[DB] imported {c} events", flush=True)
        time.sleep(10)

if __name__ == "__main__":
    main()
