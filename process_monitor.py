#!/usr/bin/env python3

import json
import time
import psutil
from datetime import datetime

REPORT = "/var/log/otx-sec/process_report.jsonl"

SUSPICIOUS_PATHS = [
    "/tmp",
    "/dev/shm",
    "/var/tmp",
]

seen = set()

def write_report(entry):
    with open(REPORT, "a") as f:
        f.write(json.dumps(entry) + "\n")

def scan_processes():
    for proc in psutil.process_iter(["pid", "name", "exe", "username", "cmdline"]):
        try:
            exe = proc.info["exe"]

            if not exe:
                continue

            key = f"{proc.info['pid']}:{exe}"
            if key in seen:
                continue

            for bad in SUSPICIOUS_PATHS:
                if exe.startswith(bad):
                    seen.add(key)

                    entry = {
                        "time": datetime.now().isoformat(),
                        "event": "SUSPICIOUS_PROCESS",
                        "pid": proc.info["pid"],
                        "name": proc.info["name"],
                        "exe": exe,
                        "user": proc.info["username"],
                        "cmdline": proc.info["cmdline"],
                        "recommendation": "Prozess prüfen. Wenn unbekannt: kill PID, Hash berechnen, Datei quarantänen."
                    }

                    write_report(entry)
                    print(f"[!] Suspicious process: {proc.info['name']} -> {exe}", flush=True)

        except Exception:
            pass

def main():
    print("[*] Process behavior monitor started", flush=True)

    while True:
        scan_processes()
        time.sleep(10)

if __name__ == "__main__":
    main()
