#!/usr/bin/env python3

import os
import json
import sqlite3
import subprocess
import time
from pathlib import Path

BASE_DIR = Path(os.environ.get("OTX_SEC_BASE_DIR", Path(__file__).resolve().parent))
DB = str(Path(os.environ.get("OTX_SEC_DB", BASE_DIR / "db" / "incidents.db")))
STATE = Path(os.environ.get("OTX_SEC_ALERT_STATE", BASE_DIR / "data" / "alerted_incidents.json"))


def load_seen():
    try:
        return set(json.loads(STATE.read_text()))
    except Exception:
        return set()


def save_seen(seen):
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps(sorted(list(seen)), indent=2))


def notify(title, msg):
    """
    Send desktop notification without hardcoded sudo/user.
    Safe fallback: print alert if notify-send/session bus is unavailable.
    """
    cmd = [
        "notify-send",
        "-u", "critical",
        str(title)[:120],
        str(msg)[:1000],
    ]

    env = os.environ.copy()
    env.setdefault("DISPLAY", ":0")

    try:
        subprocess.Popen(
            cmd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        print(f"[NOTIFY] {title}: {msg}", flush=True)


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
                    f"Score: {score}/100\nObject: {obj}\n{reasons_text}",
                )

                print(f"[ALERT] {sev} {score}/100 {obj}", flush=True)
                seen.add(iid)
                save_seen(seen)

        except Exception as e:
            print(f"[ERROR] {e}", flush=True)

        time.sleep(15)


if __name__ == "__main__":
    main()
