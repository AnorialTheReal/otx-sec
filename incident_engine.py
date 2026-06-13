#!/opt/otx-sec/venv/bin/python

import sqlite3
import json
import time
from pathlib import Path
from datetime import datetime, timedelta

EVENT_DB = Path("/opt/otx-sec/db/events.db")
INCIDENT_DB = Path("/opt/otx-sec/db/incidents.db")

def connect_events():
    return sqlite3.connect(EVENT_DB)

def connect_incidents():
    return sqlite3.connect(INCIDENT_DB)

def init_incident_db():
    con = connect_incidents()
    cur = con.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created TEXT,
        severity TEXT,
        score INTEGER,
        title TEXT,
        object TEXT,
        reasons TEXT,
        related_events TEXT,
        status TEXT DEFAULT 'OPEN'
    )
    """)
    con.commit()
    con.close()

def recent_events(limit=500):
    if not EVENT_DB.exists():
        return []

    con = connect_events()
    cur = con.cursor()
    cur.execute("""
        SELECT id,time,source,severity,event,object,raw
        FROM events
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))
    rows = cur.fetchall()
    con.close()

    out = []
    for r in rows:
        try:
            raw = json.loads(r[6]) if r[6] else {}
        except Exception:
            raw = {}

        out.append({
            "id": r[0],
            "time": r[1],
            "source": r[2],
            "severity": r[3],
            "event": r[4],
            "object": r[5],
            "raw": raw,
        })
    return out

def incident_exists(obj, title):
    con = connect_incidents()
    cur = con.cursor()
    cur.execute("""
        SELECT id FROM incidents
        WHERE object=? AND title=? AND status='OPEN'
        LIMIT 1
    """, (obj, title))
    row = cur.fetchone()
    con.close()
    return row is not None

def create_incident(severity, score, title, obj, reasons, events):
    if incident_exists(obj, title):
        return False

    con = connect_incidents()
    cur = con.cursor()
    cur.execute("""
        INSERT INTO incidents
        (created,severity,score,title,object,reasons,related_events,status)
        VALUES (?,?,?,?,?,?,?,?)
    """, (
        datetime.now().isoformat(),
        severity,
        score,
        title,
        obj,
        json.dumps(reasons, ensure_ascii=False),
        json.dumps(events, ensure_ascii=False),
        "OPEN",
    ))
    con.commit()
    con.close()
    return True

def score_group(obj, events):
    score = 0
    reasons = []

    text = json.dumps(events).lower()

    if "malicious" in text or "found" in text or "blocked" in text:
        score += 90
        reasons.append("Malware/block/signature hit")

    if "/tmp/" in text or "/dev/shm/" in text or "/var/tmp/" in text:
        score += 35
        reasons.append("Execution or activity in temporary path")

    if "new_persistence_file" in text or "autostart" in text or "systemd" in text:
        score += 45
        reasons.append("Persistence indicator detected")

    if "network_connection" in text or "external_connection" in text or "remote_ip" in text:
        score += 25
        reasons.append("External network activity")

    if "auditd_event" in text:
        score += 20
        reasons.append("Auditd sensitive system event")

    if "root" in text:
        score += 15
        reasons.append("Root context involved")

    if "otx_hits" in text:
        for e in events:
            raw = e.get("raw", {})
            try:
                if int(raw.get("otx_hits", 0)) > 0:
                    score += 80
                    reasons.append("OTX pulse hit")
                    break
            except Exception:
                pass

    if score >= 100:
        severity = "CRITICAL"
    elif score >= 70:
        severity = "HIGH"
    elif score >= 35:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return severity, min(score, 100), reasons

def correlate():
    events = recent_events(700)

    groups = {}

    for e in events:
        obj = e.get("object") or ""

        raw = e.get("raw", {})
        file_obj = raw.get("file") or raw.get("exe") or obj

        if file_obj:
            groups.setdefault(file_obj, []).append(e)

        pid = raw.get("pid")
        if pid:
            groups.setdefault(f"pid:{pid}", []).append(e)

        ip = raw.get("remote_ip")
        if ip:
            groups.setdefault(f"ip:{ip}", []).append(e)

    created = 0

    for obj, group in groups.items():
        if len(group) < 1:
            continue

        severity, score, reasons = score_group(obj, group)

        if score < 35:
            continue

        title = f"{severity} incident for {obj}"

        event_refs = [
            {
                "id": e["id"],
                "time": e["time"],
                "source": e["source"],
                "severity": e["severity"],
                "event": e["event"],
                "object": e["object"],
            }
            for e in group[:20]
        ]

        if create_incident(severity, score, title, obj, reasons, event_refs):
            created += 1
            print(f"[INCIDENT] {severity} {score}/100 {obj}", flush=True)

    return created

def main():
    init_incident_db()
    print("[*] Incident engine started", flush=True)

    while True:
        try:
            count = correlate()
            if count:
                print(f"[+] Created {count} incidents", flush=True)
        except Exception as e:
            print(f"[ERROR] {e}", flush=True)

        time.sleep(30)

if __name__ == "__main__":
    main()
