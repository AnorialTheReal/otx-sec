#!/usr/bin/env python3

import os
import json
import time
import psutil
import ipaddress
from datetime import datetime
from pathlib import Path
import sys

BASE_DIR = Path(os.environ.get("OTX_SEC_BASE_DIR", Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(BASE_DIR))

from engines.threat_engine import ThreatEngine

CONFIG_FILE = Path(os.environ.get("OTX_SEC_CONFIG_FILE", BASE_DIR / "config" / "settings.json"))


def load_settings():
    try:
        data = json.loads(CONFIG_FILE.read_text())
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}

REPORT = str(Path(os.environ.get("OTX_SEC_NETWORK_REPORT", BASE_DIR / "data" / "logs" / "network_report.jsonl")))

SCAN_INTERVAL = 15

TRUSTED_PROCESSES = {
    "brave",
    "Discord",
    "spotify",
    "steam",
    "nordvpnd",
    "anydesk",
}

NORMAL_PORTS = {
    53,    # DNS
    80,    # HTTP
    123,   # NTP
    443,   # HTTPS
    853,   # DNS over TLS
    27015,
    27016,
    27017,
    27018,
    27019,
    27020,
}

SUSPICIOUS_PATHS = [
    "/tmp",
    "/dev/shm",
    "/var/tmp",
    str(Path.home() / ".cache"),
]

seen = set()


def now():
    return datetime.now().isoformat()


def write_report(entry):
    with open(REPORT, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def is_public_ip(ip):
    try:
        obj = ipaddress.ip_address(ip)
        return obj.is_global
    except Exception:
        return False


def is_suspicious_path(path):
    if not path:
        return False

    for bad in SUSPICIOUS_PATHS:
        if path.startswith(bad):
            return True

    return False



def risk_score(proc_name, proc_exe, user, remote_port, status):
    score = 0
    reasons = []

    if proc_name not in TRUSTED_PROCESSES:
        score += 30
        reasons.append("unknown_process")

    if user == "root" and proc_name not in {"nordvpnd", "anydesk"}:
        score += 25
        reasons.append("root_process_external_connection")

    if is_suspicious_path(proc_exe):
        score += 40
        reasons.append("process_running_from_suspicious_path")

    if remote_port not in NORMAL_PORTS:
        score += 20
        reasons.append("unusual_remote_port")

    if status not in {"ESTABLISHED", "NONE"}:
        score += 10
        reasons.append("unusual_connection_status")

    return score, reasons


def should_report(score, reasons, threat_score):
    if threat_score >= 40:
        return True

    if score >= 30:
        return True

    if "process_running_from_suspicious_path" in reasons:
        return True

    if "root_process_external_connection" in reasons:
        return True

    return False


def scan_connections():
    for conn in psutil.net_connections(kind="inet"):
        try:
            if not conn.raddr:
                continue

            remote_ip = conn.raddr.ip
            remote_port = conn.raddr.port

            if not is_public_ip(remote_ip):
                continue

            key = f"{conn.pid}:{remote_ip}:{remote_port}:{conn.status}"
            if key in seen:
                continue

            proc_name = None
            proc_exe = None
            proc_user = None
            proc_cmdline = None

            if conn.pid:
                try:
                    proc = psutil.Process(conn.pid)
                    proc_name = proc.name()
                    proc_exe = proc.exe()
                    proc_user = proc.username()
                    proc_cmdline = proc.cmdline()
                except Exception:
                    pass

            score, reasons = risk_score(
                proc_name,
                proc_exe,
                proc_user,
                remote_port,
                conn.status,
            )

            threat = {"score": 0, "verdict": "UNKNOWN", "reasons": [], "providers": {}}

            if score >= 30:
                threat = ThreatEngine(load_settings()).lookup_ip(remote_ip)

            threat_score = int(threat.get("score", 0))
            combined_score = min(100, score + threat_score)
            combined_reasons = list(reasons) + list(threat.get("reasons", []))

            if not should_report(score, combined_reasons, threat_score):
                seen.add(key)
                continue

            seen.add(key)

            if threat.get("verdict") == "MALICIOUS" or threat_score >= 80:
                verdict = "MALICIOUS_IP"
            elif combined_score >= 60:
                verdict = "HIGH_RISK_CONNECTION"
            elif combined_score >= 30:
                verdict = "SUSPICIOUS_CONNECTION"
            else:
                verdict = "INFO"

            entry = {
                "time": now(),
                "event": "NETWORK_CONNECTION",
                "verdict": verdict,
                "risk_score": combined_score,
                "risk_reasons": combined_reasons,
                "local_risk_score": score,
                "threat_score": threat_score,
                "threat_verdict": threat.get("verdict"),
                "threat_providers": threat.get("providers", {}),
                "pid": conn.pid,
                "process": proc_name,
                "exe": proc_exe,
                "user": proc_user,
                "cmdline": proc_cmdline,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "status": conn.status,
                "threat_reasons": threat.get("reasons", []),
                "recommendation": (
                    "Wenn unbekannt: Prozess prüfen, Hash berechnen, Datei quarantänen, IP manuell bei OTX/VirusTotal prüfen."
                ),
            }

            write_report(entry)

            print(
                f"[NET] {verdict} score={score} "
                f"{proc_name}({conn.pid}) -> {remote_ip}:{remote_port} "
                f"reasons={','.join(reasons)}",
                flush=True,
            )

        except Exception:
            pass


def main():
    print("[*] Network monitor with risk scoring started", flush=True)

    while True:
        scan_connections()
        time.sleep(SCAN_INTERVAL)


if __name__ == "__main__":
    main()
