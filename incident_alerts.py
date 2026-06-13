#!/opt/otx-sec/venv/bin/python

import json
import sqlite3
import subprocess
import time
from pathlib import Path

DB = "/opt/otx-sec/db/incidents.db"
STATE = Path("/opt/otx-sec/db/alerted_incidents.json")

def load_seen():
    try:
        return set(json.loads(STATE.read_text()))
    except Exception:
        return set()

def save_seen(seen):
    STATE.write_text(json.dumps(sorted(list(seen)), indent=2))

def notify(title, msg):
    subprocess.Popen([
        "sudo", "-u", "anorial",
        "env",
        "DISPLAY=:0",
        "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus",
        "notify-send",
        "-u", "critical",
        title,
        msg
    ])

def get_incidents():
    con = sqlite3.connect(DB)
    cur = con.cursor()
    cur.execute("""
        SELECT id,severity,score,title,object,reasons
        FROM incidents
        WHERE status='OPEN' AND severity IN ('HIGH','CRITICAL')
        ORDER BY id DESC
        LIMIT 20
    """)
    rows = cur.fetchall()
    con.close()
    return rows

def main():
    print("[*] Incident alert service started", flush=True)
    seen = load_seen()

    while True:
        try:
            for row in get_incidents():
                iid, sev, score, title, obj, reasons = row

                if iid in seen:
                    continue

                try:
                    reasons_text = ", ".join(json.loads(reasons or "[]")[:3])
                except Exception:
                    reasons_text = ""

                notify(
                    f"OTX-Sec {sev} Incident",
                    f"Score: {score}/100\nObject: {obj}\n{reasons_text}"
                )

                print(f"[ALERT] {sev} {score}/100 {obj}", flush=True)
                seen.add(iid)
                save_seen(seen)

        except Exception as e:
            print(f"[ERROR] {e}", flush=True)

        time.sleep(15)

if __name__ == "__main__":
    main()
