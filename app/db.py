import sqlite3
import json
from pathlib import Path
from datetime import datetime

DB = Path("/opt/otx-sec/db/events.db")
DB.parent.mkdir(parents=True, exist_ok=True)

def connect():
    return sqlite3.connect(DB)

def init_db():
    con = connect()
    cur = con.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        time TEXT,
        source TEXT,
        severity TEXT,
        event TEXT,
        object TEXT,
        raw TEXT
    )
    """)
    con.commit()
    con.close()

def insert_event(source, severity, event, obj, raw):
    init_db()
    con = connect()
    cur = con.cursor()
    cur.execute(
        "INSERT INTO events (time, source, severity, event, object, raw) VALUES (?, ?, ?, ?, ?, ?)",
        (
            datetime.now().isoformat(),
            source,
            severity,
            event,
            obj,
            json.dumps(raw, ensure_ascii=False),
        )
    )
    con.commit()
    con.close()

def get_events(limit=1000, severity=None):
    init_db()
    con = connect()
    cur = con.cursor()

    if severity and severity != "ALL":
        cur.execute(
            "SELECT id,time,source,severity,event,object,raw FROM events WHERE severity=? ORDER BY id DESC LIMIT ?",
            (severity, limit)
        )
    else:
        cur.execute(
            "SELECT id,time,source,severity,event,object,raw FROM events ORDER BY id DESC LIMIT ?",
            (limit,)
        )

    rows = cur.fetchall()
    con.close()

    return [
        {
            "id": r[0],
            "time": r[1],
            "source": r[2],
            "severity": r[3],
            "event": r[4],
            "object": r[5],
            "raw": json.loads(r[6]) if r[6] else {},
        }
        for r in rows
    ]

def clear_events():
    init_db()
    con = connect()
    cur = con.cursor()
    cur.execute("DELETE FROM events")
    con.commit()
    con.close()
