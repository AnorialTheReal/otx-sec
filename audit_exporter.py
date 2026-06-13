#!/opt/otx-sec/venv/bin/python

import os
import json
import subprocess
import time
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(os.environ.get("OTX_SEC_BASE_DIR", Path(__file__).resolve().parent))
REPORT = str(Path(os.environ.get("OTX_SEC_AUDIT_REPORT", BASE_DIR / "data" / "logs" / "audit_report.jsonl")))
SEEN = set()

KEYS = [
    "passwd_changes",
    "shadow_changes",
    "group_changes",
    "sudoers_changes",
    "binary_changes",
    "boot_changes",
    "systemd_changes",
    "root_changes",
]

def write(entry):
    Path(REPORT).parent.mkdir(parents=True, exist_ok=True)
    with open(REPORT, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")

def ausearch_key(key):
    try:
        r = subprocess.run(
            ["ausearch", "-k", key, "-ts", "recent"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return r.stdout.strip()
    except Exception as e:
        return f"ERROR: {e}"

def main():
    print("[*] Audit exporter started", flush=True)

    while True:
        for key in KEYS:
            out = ausearch_key(key)
            if not out or out.startswith("<no matches>"):
                continue

            event_id = f"{key}:{hash(out)}"

            if event_id in SEEN:
                continue

            SEEN.add(event_id)

            write({
                "time": datetime.now().isoformat(),
                "event": "AUDITD_EVENT",
                "key": key,
                "raw": out[-8000:],
                "recommendation": "System Change Checking. If Unknown: Datei/Service/Userchange analyse."
            })

            print(f"[AUDIT] {key}", flush=True)

        time.sleep(60)

if __name__ == "__main__":
    main()
