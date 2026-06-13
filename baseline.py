#!/usr/bin/env python3

import os
import json
import hashlib
from datetime import datetime
from pathlib import Path

BASELINE_PATHS = [
    "/etc",
    "/usr/bin",
    "/usr/sbin",
    "/boot",
]

BASE_DIR = Path(os.environ.get("OTX_SEC_BASE_DIR", Path(__file__).resolve().parent))
DB_FILE = str(Path(os.environ.get("OTX_SEC_SYSTEM_HASHES", BASE_DIR / "db" / "system_hashes.json")))

EXCLUDE_DIRS = {
    "/etc/ssl/certs",
}

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def is_excluded(path):
    path = os.path.abspath(path)
    for excluded in EXCLUDE_DIRS:
        if path == excluded or path.startswith(excluded + "/"):
            return True
    return False

def build_baseline():
    data = {
        "created": datetime.now().isoformat(),
        "files": {}
    }

    for base in BASELINE_PATHS:
        for root, dirs, files in os.walk(base):
            dirs[:] = [
                d for d in dirs
                if not is_excluded(os.path.join(root, d))
            ]

            for name in files:
                path = os.path.join(root, name)

                if not os.path.isfile(path) or os.path.islink(path):
                    continue

                try:
                    data["files"][path] = {
                        "sha256": sha256(path),
                        "size": os.path.getsize(path),
                        "mtime": os.path.getmtime(path),
                    }
                except Exception:
                    pass

    with open(DB_FILE, "w") as f:
        json.dump(data, f, indent=2)

    print(f"Baseline saved: {DB_FILE}")
    print(f"Files indexed: {len(data['files'])}")

if __name__ == "__main__":
    build_baseline()
