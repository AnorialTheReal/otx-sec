import os, json, shutil, hashlib, subprocess
from pathlib import Path
from datetime import datetime

LOG_DIR = Path("/var/log/otx-sec")
QUARANTINE_DIR = Path("/var/quarantine/otx-sec")
CONFIG_DIR = Path("/opt/otx-sec/config")
CONFIG_FILE = CONFIG_DIR / "settings.json"
EXPORT_DIR = Path("/opt/otx-sec/exports")
ANALYSIS_DIR = Path("/opt/otx-sec/analysis")

ALLOWLIST = CONFIG_DIR / "allowlist.json"
BLOCKLIST = CONFIG_DIR / "blocklist.json"

SERVICES = [
    "otx-sec",
    "otx-process-monitor",
    "otx-network-monitor",
    "otx-persistence-monitor",
    "otx-audit-exporter",
    "clamav-daemon",
    "clamav-freshclam",
    "auditd",
]

LOGS = {
    "File Scanner": "report.jsonl",
    "Processes": "process_report.jsonl",
    "Network": "network_report.jsonl",
    "Persistence": "persistence_report.jsonl",
    "Integrity": "integrity_report.jsonl",
    "Auditd": "audit_report.jsonl",
}

def ensure_dirs():
    for p in [LOG_DIR, QUARANTINE_DIR, CONFIG_DIR, EXPORT_DIR, ANALYSIS_DIR]:
        p.mkdir(parents=True, exist_ok=True)

def run_cmd(cmd, timeout=180):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (r.stdout + r.stderr).strip() or "Done."
    except Exception as e:
        return str(e)

def load_settings():
    ensure_dirs()
    if not CONFIG_FILE.exists():
        data = {"otx_api_key": "", "virustotal_api_key": "", "auto_quarantine": True}
        save_settings(data)
        return data
    try:
        return json.loads(CONFIG_FILE.read_text())
    except Exception:
        return {"otx_api_key": "", "virustotal_api_key": "", "auto_quarantine": True}

def save_settings(data):
    ensure_dirs()
    CONFIG_FILE.write_text(json.dumps(data, indent=2))
    os.chmod(CONFIG_FILE, 0o600)

def _load_list(path):
    ensure_dirs()
    if not path.exists():
        path.write_text("[]")
        os.chmod(path, 0o600)
    try:
        return json.loads(path.read_text())
    except Exception:
        return []

def _save_list(path, data):
    ensure_dirs()
    path.write_text(json.dumps(data, indent=2))
    os.chmod(path, 0o600)

def read_jsonl(filename, limit=4000):
    path = LOG_DIR / filename
    if not path.exists():
        return []
    rows = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            try:
                rows.append(json.loads(line))
            except Exception:
                pass
    return rows[-limit:]

def classify(row):
    text = json.dumps(row).lower()
    if row.get("status") == "MALICIOUS" or "malicious" in text or "high_risk" in text or "blocked" in text:
        return "HIGH"
    try:
        if int(row.get("otx_hits", 0)) > 0:
            return "HIGH"
    except Exception:
        pass
    if "suspicious" in text or "new_persistence" in text or "changed" in text or "auditd_event" in text:
        return "SUSPICIOUS"
    if "clean" in text or "ok" in text or "allowed" in text:
        return "CLEAN"
    return "INFO"

def all_events(limit=5000):
    events = []
    for source, file in LOGS.items():
        for row in read_jsonl(file, limit):
            row["_source"] = source
            events.append(row)
    events.sort(key=lambda x: x.get("time", ""), reverse=True)
    return events

def db_events(limit=3000, severity="ALL"):
    try:
        import db
        return db.get_events(limit=limit, severity=severity)
    except Exception:
        rows = []
        for e in all_events(limit):
            sev = classify(e)
            if severity != "ALL" and sev != severity:
                continue
            rows.append({
                "id": 0,
                "time": e.get("time", ""),
                "source": e.get("_source", ""),
                "severity": sev,
                "event": e.get("event", e.get("status", "EVENT")),
                "object": e.get("file") or e.get("exe") or e.get("process") or e.get("remote_ip") or "",
                "raw": e,
            })
        return rows

def service_status():
    return {
        s: subprocess.call(["systemctl", "is-active", "--quiet", s],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
        for s in SERVICES
    }

def service_action(service, action):
    if service not in SERVICES:
        return "Unknown service."
    if action == "logs":
        return run_cmd(["journalctl", "-u", service, "-n", "150", "--no-pager"], 30)
    if action == "status":
        return run_cmd(["systemctl", "status", service, "--no-pager"], 30)
    if action in ["start", "stop", "restart", "enable", "disable"]:
        return run_cmd(["systemctl", action, service], 60)
    return "Unknown action."

def restart_services():
    return run_cmd(["systemctl", "restart", "otx-sec", "otx-process-monitor", "otx-network-monitor", "otx-persistence-monitor"])

def run_integrity_check():
    return run_cmd(["/opt/otx-sec/venv/bin/python", "/opt/otx-sec/integrity_check.py"], 300)

def rebuild_baseline():
    return run_cmd(["/opt/otx-sec/venv/bin/python", "/opt/otx-sec/baseline.py"], 300)

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def md5(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def hash_file(path):
    p = Path(path)
    if not p.exists():
        return "File not found."
    if not p.is_file():
        return "Not a file."
    return f"SHA256: {sha256(str(p))}\nMD5: {md5(str(p))}"

def quarantine_files():
    ensure_dirs()
    return [{"name": p.name, "path": str(p), "size": p.stat().st_size} for p in QUARANTINE_DIR.iterdir() if p.is_file()]

def quarantine_path(path):
    p = Path(path)
    if not p.exists():
        return "File not found."
    if not p.is_file():
        return "Not a file."
    h = sha256(str(p))
    target = QUARANTINE_DIR / f"{h}_{p.name}"
    base = target
    i = 1
    while target.exists():
        target = Path(str(base) + f".{i}")
        i += 1
    shutil.move(str(p), str(target))
    target.chmod(0o000)
    return f"Quarantined: {target}"

def delete_quarantine_file(path):
    p = Path(path)
    if not str(p).startswith(str(QUARANTINE_DIR)):
        return "Blocked unsafe path."
    p.chmod(0o600)
    p.unlink()
    return "Deleted."

def restore_quarantine_file(path, target_dir="/home/anorial/Restored-OTX-Sec"):
    p = Path(path)
    if not str(p).startswith(str(QUARANTINE_DIR)):
        return "Blocked unsafe path."
    if not p.exists():
        return "File not found."
    target = Path(target_dir)
    target.mkdir(parents=True, exist_ok=True)
    p.chmod(0o600)
    name = p.name.split("_", 1)[1] if "_" in p.name else p.name
    dest = target / name
    i = 1
    while dest.exists():
        dest = target / f"{name}.{i}"
        i += 1
    shutil.move(str(p), str(dest))
    return f"Restored to: {dest}"

def resolve_event_path(event):
    for c in [event.get("quarantine_path"), event.get("file"), event.get("exe")]:
        if c and Path(c).exists():
            return c
    return event.get("quarantine_path") or event.get("file") or event.get("exe") or ""

def allow_path(path):
    p = Path(path)
    if not p.exists():
        return "File not found."
    h = sha256(str(p))
    data = _load_list(ALLOWLIST)
    if h not in data:
        data.append(h)
        _save_list(ALLOWLIST, data)
    return f"Allowed hash:\n{h}"

def block_path(path):
    p = Path(path)
    if not p.exists():
        return "File not found."
    h = sha256(str(p))
    data = _load_list(BLOCKLIST)
    if h not in data:
        data.append(h)
        _save_list(BLOCKLIST, data)
    return f"Blocked hash:\n{h}\n\n{quarantine_path(str(p))}"

def investigate_path(path):
    p = Path(path)
    if not path or not p.exists():
        return "File not found."
    return "\n".join([
        f"Path: {p}",
        f"Size: {p.stat().st_size}",
        hash_file(str(p)),
        "\n[file]", run_cmd(["file", str(p)], 20),
        "\n[ls]", run_cmd(["ls", "-lah", str(p)], 20),
        "\n[strings preview]", run_cmd(["strings", "-n", "8", str(p)], 30)[:8000],
    ])

def analyze_path(path):
    p = Path(path)
    if not p.exists():
        return "File not found."
    h = sha256(str(p))
    outdir = ANALYSIS_DIR / h
    outdir.mkdir(parents=True, exist_ok=True)
    report = {
        "time": datetime.now().isoformat(),
        "path": str(p),
        "sha256": h,
        "md5": md5(str(p)),
        "size": p.stat().st_size,
        "file": run_cmd(["file", str(p)], 20),
        "ls": run_cmd(["ls", "-lah", str(p)], 20),
    }
    (outdir / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False))
    (outdir / "strings.txt").write_text(run_cmd(["strings", "-n", "8", str(p)], 30)[:20000])
    return f"Analysis created:\n{outdir}"

def manual_scan_file(path):
    if not Path(path).exists():
        return "File not found."
    return run_cmd(["clamscan", "--no-summary", path], 180)

def manual_scan_folder(path):
    if not Path(path).exists():
        return "Folder not found."
    return run_cmd(["clamscan", "-r", "--infected", path], 900)

def make_summary():
    events = all_events()
    return {
        "events": len(events),
        "high": sum(1 for e in events if classify(e) == "HIGH"),
        "suspicious": sum(1 for e in events if classify(e) == "SUSPICIOUS"),
        "clean": sum(1 for e in events if classify(e) == "CLEAN"),
        "quarantine": len(quarantine_files()),
    }

def recommendations():
    s = make_summary()
    recs = []
    if s["high"]:
        recs.append("High-Risk Events prüfen: Quarantäne, Hash, Quelle und Prozesskontext ansehen.")
    if s["suspicious"]:
        recs.append("Suspicious Events prüfen: Persistenz, Prozesse aus /tmp, Netzwerkverbindungen und auditd Events.")
    if s["quarantine"]:
        recs.append("Quarantäne enthält Dateien. Nicht öffnen. Erst Hash bei VirusTotal/OTX prüfen.")
    recs.append("Nach vertrauenswürdigen Updates Baseline neu erstellen.")
    recs.append("Regelmäßig Integrity Check ausführen.")
    return recs

def export_full_report():
    data = {
        "generated": datetime.now().isoformat(),
        "summary": make_summary(),
        "services": service_status(),
        "recommendations": recommendations(),
        "quarantine": quarantine_files(),
        "events": all_events(),
    }
    out = EXPORT_DIR / f"otx-sec-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    out.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    return f"Exported: {out}"

def clear_old_logs():
    for file in LOGS.values():
        path = LOG_DIR / file
        if path.exists():
            path.write_text("")
    return "Logs cleared."

def action_center(action):
    if action == "restart_inactive":
        out = []
        for s, active in service_status().items():
            if not active:
                out.append(f"{s}: {service_action(s, 'restart')}")
        return "\n\n".join(out) if out else "All services active."
    if action == "integrity":
        return run_integrity_check()
    if action == "baseline":
        return rebuild_baseline()
    if action == "export":
        return export_full_report()
    if action == "clear_logs":
        return clear_old_logs()
    if action == "analyze_high":
        highs = [e for e in all_events() if classify(e) == "HIGH"]
        return "\n\n--- HIGH EVENT ---\n\n".join(json.dumps(e, indent=2, ensure_ascii=False) for e in highs[:30]) or "No high risk events."
    return "Unknown action."

def list_processes():
    try:
        import psutil
    except Exception as e:
        return [{"error": f"psutil missing: {e}"}]

    rows = []

    for p in psutil.process_iter(["pid", "name", "username", "exe", "cmdline", "cpu_percent", "memory_percent"]):
        try:
            info = p.info
            exe = info.get("exe") or ""
            risk = "LOW"

            if exe.startswith("/tmp") or exe.startswith("/dev/shm") or exe.startswith("/var/tmp"):
                risk = "HIGH"
            elif exe.startswith("/home") and "/.cache/" in exe:
                risk = "SUSPICIOUS"

            rows.append({
                "pid": info.get("pid"),
                "name": info.get("name"),
                "user": info.get("username"),
                "exe": exe,
                "cmdline": " ".join(info.get("cmdline") or []),
                "cpu": info.get("cpu_percent"),
                "ram": round(info.get("memory_percent") or 0, 2),
                "risk": risk,
            })

        except Exception:
            pass

    rows.sort(key=lambda x: (x["risk"] != "HIGH", x["risk"] != "SUSPICIOUS", x["name"] or ""))
    return rows


def kill_process(pid):
    try:
        import psutil
        p = psutil.Process(int(pid))
        p.terminate()
        return f"Terminated PID {pid}"
    except Exception as e:
        return str(e)


def process_connections(pid):
    try:
        import psutil
        p = psutil.Process(int(pid))
        conns = p.net_connections(kind="inet")
        out = []
        for c in conns:
            out.append(str(c))
        return "\n".join(out) if out else "No connections."
    except Exception as e:
        return str(e)

def list_network_connections():
    try:
        import psutil
        import ipaddress
    except Exception as e:
        return [{"error": f"missing module: {e}"}]

    rows = []

    def is_public(ip):
        try:
            return ipaddress.ip_address(ip).is_global
        except Exception:
            return False

    for c in psutil.net_connections(kind="inet"):
        try:
            if not c.raddr:
                continue

            rip = c.raddr.ip
            rport = c.raddr.port

            if not is_public(rip):
                continue

            proc_name = ""
            proc_exe = ""
            proc_user = ""

            if c.pid:
                try:
                    p = psutil.Process(c.pid)
                    proc_name = p.name()
                    proc_exe = p.exe()
                    proc_user = p.username()
                except Exception:
                    pass

            risk = "LOW"

            if not proc_name:
                risk = "SUSPICIOUS"

            if proc_exe.startswith("/tmp") or proc_exe.startswith("/dev/shm") or proc_exe.startswith("/var/tmp"):
                risk = "HIGH"

            if rport not in [53, 80, 123, 443, 853, 27015, 27016, 27017, 27018, 27019, 27020]:
                risk = "SUSPICIOUS"

            rows.append({
                "risk": risk,
                "pid": c.pid,
                "process": proc_name,
                "user": proc_user,
                "exe": proc_exe,
                "remote_ip": rip,
                "remote_port": rport,
                "status": c.status,
            })

        except Exception:
            pass

    rows.sort(key=lambda x: (x["risk"] != "HIGH", x["risk"] != "SUSPICIOUS", x["process"] or ""))
    return rows
