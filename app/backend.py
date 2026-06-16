import os, json, shutil, hashlib, subprocess
from pathlib import Path
from tools.secrets import split_settings_and_secrets, save_secrets, merge_settings_with_secrets
from datetime import datetime

# Safe path handling:
# - Installed/root mode may use /var and /opt later.
# - Dev/user mode must never require root just to open the GUI.
BASE_DIR = Path(os.environ.get("OTX_SEC_BASE_DIR", Path(__file__).resolve().parent.parent))
DATA_DIR = Path(os.environ.get("OTX_SEC_DATA_DIR", BASE_DIR / "data"))

LOG_DIR = Path(os.environ.get("OTX_SEC_LOG_DIR", DATA_DIR / "logs"))
QUARANTINE_DIR = Path(os.environ.get("OTX_SEC_QUARANTINE_DIR", DATA_DIR / "quarantine"))
CONFIG_DIR = Path(os.environ.get("OTX_SEC_CONFIG_DIR", BASE_DIR / "config"))
CONFIG_FILE = CONFIG_DIR / "settings.json"
EXPORT_DIR = Path(os.environ.get("OTX_SEC_EXPORT_DIR", BASE_DIR / "exports"))
ANALYSIS_DIR = Path(os.environ.get("OTX_SEC_ANALYSIS_DIR", BASE_DIR / "analysis"))

ALLOWLIST = CONFIG_DIR / "allowlist.json"
BLOCKLIST = CONFIG_DIR / "blocklist.json"

SERVICES = [
    "otx-sec",
    "otx-process-monitor",
    "otx-network-monitor",
    "otx-persistence-monitor",
    "otx-audit-exporter",
    "auditd",
]

LOGS = {
    "File Scanner": "report.jsonl",
    "Processes": "process_report.jsonl",
    "Network": "network_report.jsonl",
    "Persistence": "persistence_report.jsonl",
    "Integrity": "integrity_report.jsonl",
    "Auditd": "audit_report.jsonl",
    "Kernel": "kernel_report.jsonl",
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

    default = {
        "otx_api_key": "",
        "virustotal_api_key": "",
        "abuseipdb_api_key": "",
        "greynoise_api_key": "",
        "shodan_api_key": "",
        "malwarebazaar_api_key": "",
        "urlhaus_enabled": True,
        "auto_quarantine": True,
        "auto_otx_lookup": True,
        "auto_vt_lookup": False
    }

    if not CONFIG_FILE.exists():
        save_settings(default)
        return merge_settings_with_secrets(default)

    try:
        data = json.loads(CONFIG_FILE.read_text())
        for k, v in default.items():
            data.setdefault(k, v)
        return merge_settings_with_secrets(data)
    except Exception:
        return merge_settings_with_secrets(default)


def save_settings(data):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)

    public_settings, secret_settings = split_settings_and_secrets(data)
    save_secrets(secret_settings)

    CONFIG_FILE.write_text(json.dumps({
        "urlhaus_enabled": bool(public_settings.get("urlhaus_enabled", True)),
        "auto_quarantine": bool(public_settings.get("auto_quarantine", True)),
        "auto_otx_lookup": bool(public_settings.get("auto_otx_lookup", True)),
        "auto_vt_lookup": bool(public_settings.get("auto_vt_lookup", False)),
    }, indent=2))

def save_settings(data):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)

    public_settings, secret_settings = split_settings_and_secrets(data)
    save_secrets(secret_settings)

    CONFIG_FILE.write_text(json.dumps({
        "urlhaus_enabled": bool(public_settings.get("urlhaus_enabled", True)),
        "auto_quarantine": bool(public_settings.get("auto_quarantine", True)),
        "auto_otx_lookup": bool(public_settings.get("auto_otx_lookup", True)),
        "auto_vt_lookup": bool(public_settings.get("auto_vt_lookup", False)),
    }, indent=2))

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
    import sys
    return run_cmd([sys.executable, str(BASE_DIR / "tools" / "integrity_check.py")], 300)

def rebuild_baseline():
    import sys
    return run_cmd([sys.executable, str(BASE_DIR / "tools" / "baseline.py")], 300)

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

def restore_quarantine_file(path, target_dir=None):
    if target_dir is None:
        target_dir = str(Path.home() / "Restored-OTX-Sec")
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
    return analyze_path(path)

def manual_scan_folder(path):
    if not Path(path).exists():
        return "Folder not found."
    return analyze_path(path)

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
        recs.append("Review high-risk events: inspect quarantine, hash, source, and process context.")
    if s["suspicious"]:
        recs.append("Review suspicious events: check persistence, processes running from /tmp, network connections, and auditd events.")
    if s["quarantine"]:
        recs.append("Quarantine contains files. Do not open them. Check the hash with VirusTotal/OTX first.")
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

def virustotal_hash_lookup(file_hash):
    try:
        import requests
    except Exception as e:
        return f"requests missing: {e}"

    settings = load_settings()
    api_key = settings.get("virustotal_api_key", "").strip()

    if not api_key:
        return "VirusTotal API key missing. Add it in Settings."

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"

    try:
        r = requests.get(
            url,
            headers={"x-apikey": api_key},
            timeout=30,
        )

        if r.status_code == 404:
            return "VirusTotal: hash not found."

        if r.status_code != 200:
            return f"VirusTotal error {r.status_code}:\n{r.text[:2000]}"

        data = r.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

        return json.dumps({
            "hash": file_hash,
            "stats": stats,
            "reputation": data.get("data", {}).get("attributes", {}).get("reputation"),
            "meaningful_name": data.get("data", {}).get("attributes", {}).get("meaningful_name"),
            "type_description": data.get("data", {}).get("attributes", {}).get("type_description"),
        }, indent=2)

    except Exception as e:
        return str(e)


def virustotal_file_lookup(path):
    p = Path(path)

    if not p.exists() or not p.is_file():
        return "File not found."

    return virustotal_hash_lookup(sha256(str(p)))

def is_real_file(path):
    try:
        if not path:
            return False
        p = Path(path)
        return p.exists() and p.is_file()
    except Exception:
        return False


def allow_path(path):
    if not is_real_file(path):
        return "No valid file selected. This event is probably an IP, process, audit event, or directory."

    p = Path(path)
    h = sha256(str(p))
    data = _load_list(ALLOWLIST)

    if h not in data:
        data.append(h)
        _save_list(ALLOWLIST, data)

    return f"Allowed hash:\n{h}"


def block_path(path):
    if not is_real_file(path):
        return "No valid file selected. This event is probably an IP, process, audit event, or directory."

    p = Path(path)
    h = sha256(str(p))
    data = _load_list(BLOCKLIST)

    if h not in data:
        data.append(h)
        _save_list(BLOCKLIST, data)

    return f"Blocked hash:\n{h}\n\n{quarantine_path(str(p))}"


def analyze_path(path):
    if not is_real_file(path):
        return "No valid file selected. This event is probably an IP, process, audit event, or directory."

    p = Path(path)
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


def virustotal_file_lookup(path):
    if not is_real_file(path):
        return "No valid file selected. This event is probably an IP, process, audit event, or directory."

    return virustotal_hash_lookup(sha256(str(Path(path))))

def intel_lookup_hash(hash_value):
    if not hash_value:
        return "No hash entered."

    settings = load_settings()
    results = []

    # OTX
    try:
        results.append("=== AlienVault OTX ===")

        otx_key = settings.get("otx_api_key", "").strip()

        if otx_key:
            from OTXv2 import OTXv2, IndicatorTypes

            otx = OTXv2(otx_key)

            data = otx.get_indicator_details_full(
                IndicatorTypes.FILE_HASH_SHA256,
                hash_value
            )

            pulses = data.get("pulse_info", {}).get("pulses", [])

            results.append(json.dumps({
                "pulse_count": len(pulses),
                "pulses": [
                    {
                        "name": p.get("name"),
                        "id": p.get("id"),
                        "created": p.get("created"),
                        "tags": p.get("tags", [])
                    }
                    for p in pulses[:10]
                ]
            }, indent=2))
        else:
            results.append("OTX API key not configured.")

    except Exception as e:
        results.append(f"OTX error: {e}")

    # MalwareBazaar
    try:
        import sys
        sys.path.insert(0, str(BASE_DIR))

        from integrations import threat_intel

        results.append("=== MalwareBazaar ===")
        results.append(
            threat_intel.malwarebazaar_lookup(hash_value)
        )

    except Exception as e:
        results.append(f"MalwareBazaar error: {e}")

    # VirusTotal
    try:
        vt_key = settings.get("virustotal_api_key", "").strip()

        if vt_key:
            results.append("=== VirusTotal ===")
            results.append(
                virustotal_hash_lookup(hash_value)
            )

    except Exception as e:
        results.append(f"VirusTotal error: {e}")

    return "\n\n".join(results)
def intel_lookup_ip(ip):
    out = []
    try:
        import sys
        sys.path.insert(0, str(BASE_DIR))
        from integrations import threat_intel
        out.append("=== AbuseIPDB ===")
        out.append(threat_intel.abuseipdb_lookup(ip))
        out.append("\n=== GreyNoise ===")
        out.append(threat_intel.greynoise_lookup(ip))
        out.append("\n=== Shodan ===")
        out.append(threat_intel.shodan_lookup(ip))
    except Exception as e:
        out.append(f"Threat intel error: {e}")
    return "\n\n".join(out)

def intel_lookup_hash(hash_value):
    if not hash_value:
        return "No hash entered."

    settings = load_settings()
    results = []

    # OTX
    try:
        results.append("=== AlienVault OTX ===")

        otx_key = settings.get("otx_api_key", "").strip()

        if otx_key:
            from OTXv2 import OTXv2, IndicatorTypes

            otx = OTXv2(otx_key)

            data = otx.get_indicator_details_full(
                IndicatorTypes.FILE_HASH_SHA256,
                hash_value
            )

            pulses = data.get("pulse_info", {}).get("pulses", [])

            results.append(json.dumps({
                "pulse_count": len(pulses),
                "pulses": [
                    {
                        "name": p.get("name"),
                        "id": p.get("id"),
                        "created": p.get("created"),
                        "tags": p.get("tags", [])
                    }
                    for p in pulses[:10]
                ]
            }, indent=2))
        else:
            results.append("OTX API key not configured.")

    except Exception as e:
        results.append(f"OTX error: {e}")

    # MalwareBazaar
    try:
        import sys
        sys.path.insert(0, str(BASE_DIR))

        from integrations import threat_intel

        results.append("=== MalwareBazaar ===")
        results.append(
            threat_intel.malwarebazaar_lookup(hash_value)
        )

    except Exception as e:
        results.append(f"MalwareBazaar error: {e}")

    # VirusTotal
    try:
        vt_key = settings.get("virustotal_api_key", "").strip()

        if vt_key:
            results.append("=== VirusTotal ===")
            results.append(
                virustotal_hash_lookup(hash_value)
            )

    except Exception as e:
        results.append(f"VirusTotal error: {e}")

    return "\n\n".join(results)
def intel_lookup_ip(ip):
    if not ip:
        return "No IP entered."

    out = []

    try:
        import sys
        sys.path.insert(0, str(BASE_DIR))
        from integrations import threat_intel

        out.append("=== AbuseIPDB ===")
        out.append(threat_intel.abuseipdb_lookup(ip))

        out.append("\n=== GreyNoise ===")
        out.append(threat_intel.greynoise_lookup(ip))

        out.append("\n=== Shodan ===")
        out.append(threat_intel.shodan_lookup(ip))

    except Exception as e:
        out.append(f"Threat Intel error: {e}")

    return "\n\n".join(out)


# --- OTX-Sec API Settings / Threat Intel Override ---

def load_settings():
    ensure_dirs()
    default = {
        "otx_api_key": "",
        "virustotal_api_key": "",
        "abuseipdb_api_key": "",
        "greynoise_api_key": "",
        "shodan_api_key": "",
        "malwarebazaar_api_key": "",
        "ipinfo_api_key": "",
        "urlhaus_enabled": True,
        "auto_quarantine": True,
        "auto_otx_lookup": True,
        "auto_vt_lookup": False,
    }

    if not CONFIG_FILE.exists():
        save_settings(default)
        return merge_settings_with_secrets(default)

    try:
        data = json.loads(CONFIG_FILE.read_text())
        for k, v in default.items():
            data.setdefault(k, v)
        return merge_settings_with_secrets(data)
    except Exception:
        return merge_settings_with_secrets(default)


def save_settings(data):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)

    public_settings, secret_settings = split_settings_and_secrets(data)
    save_secrets(secret_settings)

    CONFIG_FILE.write_text(json.dumps({
        "urlhaus_enabled": bool(public_settings.get("urlhaus_enabled", True)),
        "auto_quarantine": bool(public_settings.get("auto_quarantine", True)),
        "auto_otx_lookup": bool(public_settings.get("auto_otx_lookup", True)),
        "auto_vt_lookup": bool(public_settings.get("auto_vt_lookup", False)),
    }, indent=2))

def ipinfo_lookup(ip):
    try:
        import requests
    except Exception as e:
        return f"requests missing: {e}"

    settings = load_settings()
    key = settings.get("ipinfo_api_key", "").strip()

    url = f"https://ipinfo.io/{ip}/json"

    headers = {}
    if key:
        headers["Authorization"] = f"Bearer {key}"

    try:
        r = requests.get(url, headers=headers, timeout=20)
        if not r.ok:
            return f"IPinfo error {r.status_code}:\n{r.text[:1200]}"
        data = r.json()
        return json.dumps({
            "ip": data.get("ip"),
            "hostname": data.get("hostname"),
            "city": data.get("city"),
            "region": data.get("region"),
            "country": data.get("country"),
            "loc": data.get("loc"),
            "org": data.get("org"),
            "postal": data.get("postal"),
            "timezone": data.get("timezone"),
            "privacy": data.get("privacy"),
            "abuse": data.get("abuse"),
        }, indent=2)
    except Exception as e:
        return str(e)


def intel_lookup_ip(ip):
    if not ip:
        return "No IP entered."

    settings = load_settings()
    out = []

    # Always try IPinfo first because it works without a key, and with a key if configured.
    out.append("=== IPinfo ===")
    info = ipinfo_lookup(ip)
    out.append(info)

    # If IPinfo returns useful data, stop here unless other keys are explicitly set.
    any_extra_key = any([
        settings.get("abuseipdb_api_key", "").strip(),
        settings.get("greynoise_api_key", "").strip(),
        settings.get("shodan_api_key", "").strip(),
    ])

    if not any_extra_key:
        return "\n\n".join(out)

    try:
        import sys
        sys.path.insert(0, str(BASE_DIR))
        from integrations import threat_intel

        if settings.get("abuseipdb_api_key", "").strip():
            out.append("\n=== AbuseIPDB ===")
            out.append(threat_intel.abuseipdb_lookup(ip))

        if settings.get("greynoise_api_key", "").strip():
            out.append("\n=== GreyNoise ===")
            out.append(threat_intel.greynoise_lookup(ip))

        if settings.get("shodan_api_key", "").strip():
            out.append("\n=== Shodan ===")
            out.append(threat_intel.shodan_lookup(ip))

    except Exception as e:
        out.append(f"\nThreat Intel error: {e}")

    return "\n\n".join(out)


def intel_lookup_hash(hash_value):
    if not hash_value:
        return "No hash entered."

    settings = load_settings()
    results = []

    # OTX
    try:
        results.append("=== AlienVault OTX ===")

        otx_key = settings.get("otx_api_key", "").strip()

        if otx_key:
            from OTXv2 import OTXv2, IndicatorTypes

            otx = OTXv2(otx_key)

            data = otx.get_indicator_details_full(
                IndicatorTypes.FILE_HASH_SHA256,
                hash_value
            )

            pulses = data.get("pulse_info", {}).get("pulses", [])

            results.append(json.dumps({
                "pulse_count": len(pulses),
                "pulses": [
                    {
                        "name": p.get("name"),
                        "id": p.get("id"),
                        "created": p.get("created"),
                        "tags": p.get("tags", [])
                    }
                    for p in pulses[:10]
                ]
            }, indent=2))
        else:
            results.append("OTX API key not configured.")

    except Exception as e:
        results.append(f"OTX error: {e}")

    # MalwareBazaar
    try:
        import sys
        sys.path.insert(0, str(BASE_DIR))

        from integrations import threat_intel

        results.append("=== MalwareBazaar ===")
        results.append(
            threat_intel.malwarebazaar_lookup(hash_value)
        )

    except Exception as e:
        results.append(f"MalwareBazaar error: {e}")

    # VirusTotal
    try:
        vt_key = settings.get("virustotal_api_key", "").strip()

        if vt_key:
            results.append("=== VirusTotal ===")
            results.append(
                virustotal_hash_lookup(hash_value)
            )

    except Exception as e:
        results.append(f"VirusTotal error: {e}")

    return "\n\n".join(results)
def virustotal_file_lookup(path):
    if not is_real_file(path):
        return "No valid file selected."

    settings = load_settings()
    if not settings.get("virustotal_api_key", "").strip():
        return "VirusTotal API key missing. Add it in Settings."

    return virustotal_hash_lookup(sha256(str(Path(path))))


def list_incidents(limit=500):
    try:
        import sqlite3
        con = sqlite3.connect(str(BASE_DIR / "db" / "incidents.db"))
        cur = con.cursor()
        cur.execute("""
            SELECT id,created,severity,score,title,object,reasons,related_events,status
            FROM incidents
            ORDER BY id DESC
            LIMIT ?
        """, (limit,))
        rows = cur.fetchall()
        con.close()

        return [
            {
                "id": r[0],
                "created": r[1],
                "severity": r[2],
                "score": r[3],
                "title": r[4],
                "object": r[5],
                "reasons": json.loads(r[6]) if r[6] else [],
                "related_events": json.loads(r[7]) if r[7] else [],
                "status": r[8],
            }
            for r in rows
        ]
    except Exception as e:
        return [{"error": str(e)}]


def close_incident(incident_id):
    try:
        import sqlite3
        con = sqlite3.connect(str(BASE_DIR / "db" / "incidents.db"))
        cur = con.cursor()
        cur.execute("UPDATE incidents SET status='CLOSED' WHERE id=?", (incident_id,))
        con.commit()
        con.close()
        return f"Incident {incident_id} closed."
    except Exception as e:
        return str(e)


def reopen_incident(incident_id):
    try:
        import sqlite3
        con = sqlite3.connect(str(BASE_DIR / "db" / "incidents.db"))
        cur = con.cursor()
        cur.execute("UPDATE incidents SET status='OPEN' WHERE id=?", (incident_id,))
        con.commit()
        con.close()
        return f"Incident {incident_id} reopened."
    except Exception as e:
        return str(e)


# --- OTX-Sec Firewall Engine ---

NFT_TABLE = "otxsec"
NFT_SET = "blocked_ips"

def firewall_setup():
    out = []

    cmds = [
        ["nft", "add", "table", "inet", NFT_TABLE],
        ["nft", "add", "set", "inet", NFT_TABLE, NFT_SET, "{", "type", "ipv4_addr;", "flags", "interval;", "}"],
        ["nft", "add", "chain", "inet", NFT_TABLE, "output", "{", "type", "filter", "hook", "output", "priority", "0;", "policy", "accept;", "}"],
        ["nft", "add", "rule", "inet", NFT_TABLE, "output", "ip", "daddr", "@blocked_ips", "drop"],
    ]

    for cmd in cmds:
        result = run_cmd(cmd, 20)
        if "File exists" not in result:
            out.append("$ " + " ".join(cmd))
            out.append(result)

    return "\n".join(out) if out else "Firewall table ready."


def firewall_block_ip(ip):
    if not ip:
        return "No IP given."

    firewall_setup()

    result = run_cmd([
        "nft", "add", "element", "inet", NFT_TABLE, NFT_SET, "{", ip, "}"
    ], 20)

    if "File exists" in result:
        return f"{ip} is already blocked."

    return result or f"{ip} blocked."


def firewall_unblock_ip(ip):
    if not ip:
        return "No IP given."

    firewall_setup()

    result = run_cmd([
        "nft", "delete", "element", "inet", NFT_TABLE, NFT_SET, "{", ip, "}"
    ], 20)

    if "No such file" in result or "Could not process rule" in result:
        return f"{ip} was not blocked."

    return result or f"{ip} unblocked."


def firewall_list_blocked():
    firewall_setup()
    return run_cmd(["nft", "list", "set", "inet", NFT_TABLE, NFT_SET], 20)


# --- OTX-Sec Allowlist / Blocklist Center ---

ALLOW_IPS = CONFIG_DIR / "allow_ips.json"
BLOCK_IPS = CONFIG_DIR / "block_ips.json"
ALLOW_PROCESSES = CONFIG_DIR / "allow_processes.json"
BLOCK_PROCESSES = CONFIG_DIR / "block_processes.json"

RULE_FILES = {
    "allow_hash": ALLOWLIST,
    "block_hash": BLOCKLIST,
    "allow_ip": ALLOW_IPS,
    "block_ip": BLOCK_IPS,
    "allow_process": ALLOW_PROCESSES,
    "block_process": BLOCK_PROCESSES,
}

def normalize_rule_value(value):
    return str(value or "").strip()

def list_rules():
    ensure_dirs()
    out = {}
    for name, path in RULE_FILES.items():
        out[name] = _load_list(path)
    return out

def add_rule(rule_type, value):
    ensure_dirs()
    value = normalize_rule_value(value)

    if not value:
        return "Empty value."

    if rule_type not in RULE_FILES:
        return "Unknown rule type."

    path = RULE_FILES[rule_type]
    data = _load_list(path)

    if value not in data:
        data.append(value)
        _save_list(path, data)

    return f"Added to {rule_type}: {value}"

def remove_rule(rule_type, value):
    ensure_dirs()
    value = normalize_rule_value(value)

    if rule_type not in RULE_FILES:
        return "Unknown rule type."

    path = RULE_FILES[rule_type]
    data = _load_list(path)

    if value in data:
        data.remove(value)
        _save_list(path, data)
        return f"Removed from {rule_type}: {value}"

    return f"Not found in {rule_type}: {value}"

def _match_process(value, process_rules):
    value = str(value or "")
    for rule in process_rules:
        rule = str(rule or "").strip()
        if not rule:
            continue
        if value == rule or value.endswith("/" + rule) or rule in value:
            return True
    return False


def _safe_event_raw(row):
    if isinstance(row, dict):
        raw = row.get("raw", row)
        if isinstance(raw, dict):
            return raw
        if isinstance(raw, str):
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, dict):
                    return parsed
            except Exception:
                return {}
        return {}
    return {}

def _safe_event_value(row, key):
    if isinstance(row, dict):
        val = row.get(key)
        if val is not None:
            return val
    raw = _safe_event_raw(row)
    return raw.get(key)

def event_is_allowed(row):
    allow_hashes = set(_load_list(ALLOWLIST))
    allow_ips = set(_load_list(ALLOW_IPS))
    allow_processes = _load_list(ALLOW_PROCESSES)

    raw = _safe_event_raw(row)

    sha = str(_safe_event_value(row, "sha256") or raw.get("sha256") or "")
    ip = str(_safe_event_value(row, "remote_ip") or raw.get("remote_ip") or _safe_event_value(row, "object") or "")
    exe = str(_safe_event_value(row, "exe") or raw.get("exe") or "")
    proc = str(_safe_event_value(row, "process") or raw.get("process") or raw.get("name") or "")

    if sha and sha in allow_hashes:
        return True

    if ip.startswith("ip:"):
        ip = ip.split("ip:", 1)[1].strip()

    if ip and ip in allow_ips:
        return True

    if _match_process(exe, allow_processes) or _match_process(proc, allow_processes):
        return True

    return False


def event_is_blocked(row):
    block_hashes = set(_load_list(BLOCKLIST))
    block_ips = set(_load_list(BLOCK_IPS))
    block_processes = _load_list(BLOCK_PROCESSES)

    raw = _safe_event_raw(row)

    sha = str(_safe_event_value(row, "sha256") or raw.get("sha256") or "")
    ip = str(_safe_event_value(row, "remote_ip") or raw.get("remote_ip") or _safe_event_value(row, "object") or "")
    exe = str(_safe_event_value(row, "exe") or raw.get("exe") or "")
    proc = str(_safe_event_value(row, "process") or raw.get("process") or raw.get("name") or "")

    if sha and sha in block_hashes:
        return True

    if ip.startswith("ip:"):
        ip = ip.split("ip:", 1)[1].strip()

    if ip and ip in block_ips:
        return True

    if _match_process(exe, block_processes) or _match_process(proc, block_processes):
        return True

    return False


# Override classify with allow/block awareness.
def classify(row):
    if event_is_allowed(row):
        return "CLEAN"

    if event_is_blocked(row):
        return "HIGH"

    text = json.dumps(row).lower()

    threat_verdict = str(row.get("threat_verdict", row.get("status", ""))).upper()
    threat_score = 0

    try:
        threat_score = int(row.get("threat_score", row.get("risk_score", 0)) or 0)
    except Exception:
        threat_score = 0

    static = row.get("static_analysis") or {}
    static_score = 0

    if isinstance(static, dict):
        try:
            static_score = int(static.get("risk_score", 0) or 0)
        except Exception:
            static_score = 0

    max_score = max(threat_score, static_score)

    if threat_verdict in {"MALICIOUS", "CRITICAL"}:
        return "HIGH"

    if max_score >= 80:
        return "HIGH"

    if row.get("status") == "MALICIOUS" or "malicious" in text or "high_risk" in text or "blocked" in text:
        return "HIGH"

    try:
        if int(row.get("otx_hits", 0)) > 0:
            return "HIGH"
    except Exception:
        pass

    if threat_verdict in {"SUSPICIOUS", "UNKNOWN"}:
        return "SUSPICIOUS"

    if max_score >= 40:
        return "SUSPICIOUS"

    if "suspicious" in text or "new_persistence" in text or "changed" in text or "auditd_event" in text:
        return "SUSPICIOUS"

    if threat_verdict == "CLEAN":
        return "CLEAN"

    if "clean" in text or "ok" in text or "allowed" in text:
        return "CLEAN"

    return "INFO"

# Override network listing with allow/block awareness.
def list_network_connections():
    try:
        import psutil, ipaddress
    except Exception as e:
        return [{"error": f"missing module: {e}"}]

    rows = []

    allow_ips = set(_load_list(ALLOW_IPS))
    block_ips = set(_load_list(BLOCK_IPS))
    allow_processes = _load_list(ALLOW_PROCESSES)
    block_processes = _load_list(BLOCK_PROCESSES)

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
            allowed = False
            blocked = False

            if rip in allow_ips or _match_process(proc_exe, allow_processes) or _match_process(proc_name, allow_processes):
                allowed = True
                risk = "CLEAN"

            if rip in block_ips or _match_process(proc_exe, block_processes) or _match_process(proc_name, block_processes):
                blocked = True
                risk = "HIGH"

            if not allowed and not blocked:
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
                "allowed_by_rule": allowed,
                "blocked_by_rule": blocked,
            })

        except Exception:
            pass

    rows.sort(key=lambda x: (x["risk"] != "HIGH", x["risk"] != "SUSPICIOUS", x["risk"] != "CLEAN", x["process"] or ""))
    return rows
# Build a human-readable security summary for GUI display.
# The raw JSON event is still shown below this summary for debugging.
def format_event_summary(event):
    severity = classify(event)
    threat_verdict = event.get("threat_verdict", event.get("status", "UNKNOWN"))
    threat_score = event.get("threat_score", event.get("risk_score", 0))
    threat_reasons = event.get("threat_reasons", event.get("risk_reasons", []))

    static = event.get("static_analysis") or {}
    providers = event.get("threat_providers") or {}

    lines = []

    lines.append("OTX-Sec Event Summary")
    lines.append("=====================")
    lines.append(f"Severity: {severity}")
    lines.append(f"Event: {event.get('event', event.get('status', 'EVENT'))}")
    lines.append(f"Object: {event.get('file') or event.get('exe') or event.get('process') or event.get('remote_ip') or ''}")
    lines.append(f"Time: {event.get('time', '')}")
    lines.append("")

    lines.append("Threat Intelligence")
    lines.append("-------------------")
    lines.append(f"Verdict: {threat_verdict}")
    lines.append(f"Score: {threat_score}")

    if threat_reasons:
        lines.append("Reasons:")
        for reason in threat_reasons[:20]:
            lines.append(f" - {reason}")

    native_details = event.get("native_details") or {}

    if event.get("engine") or event.get("native_score") is not None or native_details:
        lines.append("")
        lines.append("Native Engine")
        lines.append("-------------------")
        lines.append(f"Engine: {event.get('engine', 'otx-native')}")
        lines.append(f"Output: {event.get('native_output', 'N/A')}")
        lines.append(f"Native Score: {event.get('native_score', 0)}")

        native_reasons = event.get("native_reasons", [])
        if native_reasons:
            lines.append("Native Reasons:")
            for reason in native_reasons[:20]:
                lines.append(f" - {reason}")

        if native_details:
            lines.append("Native Details:")
            lines.append(f" - Engine Version: {native_details.get('engine_version', 'N/A')}")
            lines.append(f" - Entropy: {native_details.get('entropy', 'N/A')}")
            lines.append(f" - File Extension: {native_details.get('file_extension', 'N/A')}")
            lines.append(f" - File Type: {native_details.get('file_type', 'unknown')}")
            lines.append(f" - Hidden: {native_details.get('is_hidden', False)}")
            lines.append(f" - Executable: {native_details.get('is_executable', False)}")
            lines.append(f" - Script: {native_details.get('is_script', False)}")

    if providers:
        lines.append("")
        lines.append("Providers:")

        otx = providers.get("otx") or {}
        if otx:
            lines.append(f" - OTX: hits={otx.get('hits', 'N/A')} error={otx.get('error')}")

        vt = providers.get("virustotal") or {}
        if vt:
            lines.append(
                " - VirusTotal: "
                f"malicious={vt.get('malicious', 0)} "
                f"suspicious={vt.get('suspicious', 0)} "
                f"error={vt.get('error')}"
            )

        mb = providers.get("malwarebazaar") or {}
        if mb:
            lines.append(
                " - MalwareBazaar: "
                f"found={mb.get('found', False)} "
                f"hits={mb.get('hits', 'N/A')} "
                f"error={mb.get('error')}"
            )

        urlhaus = providers.get("urlhaus") or {}
        if urlhaus:
            lines.append(
                " - URLHaus: "
                f"found={urlhaus.get('found', False)} "
                f"hits={urlhaus.get('hits', 'N/A')} "
                f"error={urlhaus.get('error')}"
            )

    if static:
        lines.append("")
        lines.append("Static Analysis")
        lines.append("-------------------")
        lines.append(f"File Type: {static.get('file_type', 'unknown')}")
        lines.append(f"Entropy: {static.get('entropy', 'N/A')}")
        lines.append(f"Risk Score: {static.get('risk_score', 0)}")
        lines.append(f"Packed Suspected: {static.get('packed_suspected', False)}")

        static_reasons = static.get("reasons", [])
        if static_reasons:
            lines.append("Reasons:")
            for reason in static_reasons[:20]:
                lines.append(f" - {reason}")

        suspicious = static.get("suspicious_strings", [])
        if suspicious:
            lines.append("Suspicious Strings:")
            for item in suspicious[:20]:
                lines.append(f" - {item}")

    yara_result = event.get("yara") or {}

    rust_result = event.get("rust") or {}

    if rust_result:
        lines.append("")
        lines.append("Rust Native Analysis")
        lines.append("-------------------")
        lines.append(f"Available: {rust_result.get('available', False)}")
        lines.append(f"Engine: {rust_result.get('engine', 'otx-rust')}")
        lines.append(f"Risk Score: {rust_result.get('risk_score', 0)}")
        lines.append(f"Entropy: {rust_result.get('entropy', 'N/A')}")
        lines.append(f"ELF: {rust_result.get('is_elf', False)}")
        lines.append(f"ELF Arch: {rust_result.get('elf_arch', 'unknown')}")
        lines.append(f"PE: {rust_result.get('is_pe', False)}")
        lines.append(f"PE Arch: {rust_result.get('pe_arch', 'unknown')}")
        lines.append(f"String Count: {rust_result.get('string_count', 0)}")

        if rust_result.get("error"):
            lines.append(f"Error: {rust_result.get('error')}")

        rust_reasons = rust_result.get("reasons", [])
        if rust_reasons:
            lines.append("Reasons:")
            for reason in rust_reasons[:20]:
                lines.append(f" - {reason}")

        rust_strings = rust_result.get("suspicious_strings", [])
        if rust_strings:
            lines.append("Suspicious Strings:")
            for item in rust_strings[:20]:
                lines.append(f" - {item}")

    if yara_result:
        lines.append("")
        lines.append("YARA Analysis")
        lines.append("-------------------")

        lines.append(
            f"Available: {yara_result.get('available', False)}"
        )

        lines.append(
            f"Risk Score: {yara_result.get('risk_score', 0)}"
        )
        lines.append(
            f"Match Count: {yara_result.get('match_count', len(yara_result.get('matches', [])))}"
        )
        lines.append(
            f"Highest Severity: {str(yara_result.get('highest_severity', 'none')).upper()}"
        )

        if yara_result.get("error"):
            lines.append(
                f"Error: {yara_result.get('error')}"
            )

        matches = yara_result.get("matches", [])

        if matches:
            lines.append("Matches:")

            for match in matches[:20]:
                lines.append(
                    f" - {match.get('rule', 'unknown')}"
                )

                meta = match.get("meta", {})

                if meta.get("description"):
                    lines.append(
                        f"   Description: {meta.get('description')}"
                    )

                if meta.get("severity"):
                    lines.append(
                        f"   Severity: {meta.get('severity')}"
                    )


    lines.append("")
    lines.append("Raw Event JSON")
    lines.append("--------------")
    lines.append(json.dumps(event, indent=2, ensure_ascii=False))

    return "\n".join(lines)
