#!/usr/bin/env python3

import os
import json
import time
import psutil
import ipaddress
from datetime import datetime
from pathlib import Path
from OTXv2 import OTXv2, IndicatorTypes

API_KEY = "dd070164c10914011a0717526f204287dc1f17b365121e6a3f3fac71cb84e635"

BASE_DIR = Path(os.environ.get("OTX_SEC_BASE_DIR", Path(__file__).resolve().parent))
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
otx = OTXv2(API_KEY)


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


def otx_ip_check(ip):
    try:
        data = otx.get_indicator_details_full(
            IndicatorTypes.IPv4,
            ip,
        )

        pulses = data.get("pulse_info", {}).get("pulses", [])

        clean_pulses = []
        for pulse in pulses[:10]:
            clean_pulses.append({
                "name": pulse.get("name"),
                "id": pulse.get("id"),
                "created": pulse.get("created"),
                "tags": pulse.get("tags"),
            })

        return len(pulses), clean_pulses, None

    except Exception as e:
        return -1, [], str(e)


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


def should_report(score, reasons, otx_hits):
    if otx_hits > 0:
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

            otx_hits = 0
            otx_pulses = []
            otx_error = None

            if score >= 30:
                otx_hits, otx_pulses, otx_error = otx_ip_check(remote_ip)

            if not should_report(score, reasons, otx_hits):
                seen.add(key)
                continue

            seen.add(key)

            if otx_hits > 0:
                verdict = "MALICIOUS_IP"
            elif score >= 60:
                verdict = "HIGH_RISK_CONNECTION"
            elif score >= 30:
                verdict = "SUSPICIOUS_CONNECTION"
            else:
                verdict = "INFO"

            entry = {
                "time": now(),
                "event": "NETWORK_CONNECTION",
                "verdict": verdict,
                "risk_score": score,
                "risk_reasons": reasons,
                "pid": conn.pid,
                "process": proc_name,
                "exe": proc_exe,
                "user": proc_user,
                "cmdline": proc_cmdline,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "status": conn.status,
                "otx_hits": otx_hits,
                "otx_error": otx_error,
                "otx_pulses": otx_pulses,
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
