#!/usr/bin/env python3

import json
import os
from datetime import datetime, timezone
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("OTX_SEC_DATA_DIR", BASE_DIR / "tools" / "data"))
LOG_DIR = DATA_DIR / "logs"
REPORT_FILE = LOG_DIR / "behavior_report.jsonl"


SUSPICIOUS_EXEC_PATHS = [
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/run/user/",
]


SUSPICIOUS_PROCESS_NAMES = [
    "xmrig",
    "kinsing",
    "kdevtmpfsi",
    "kthreaddk",
    "kinsing",
    "bash",
    "sh",
    "curl",
    "wget",
    "nc",
    "ncat",
    "socat",
    "python",
    "perl",
    "php",
]


SUSPICIOUS_CMD_MARKERS = [
    "curl ",
    "wget ",
    "bash -c",
    "sh -c",
    "base64",
    "chmod +x",
    "/dev/shm",
    "/tmp/",
    "/var/tmp/",
    "xmrig",
    "stratum+tcp",
    "LD_PRELOAD",
    "/etc/ld.so.preload",
    "authorized_keys",
    "crontab",
    "systemctl enable",
    "nohup",
    "setsid",
    "nc ",
    "ncat ",
    "socat ",
]


PROCESS_CHAIN_MARKERS = [
    ("bash", "curl"),
    ("bash", "wget"),
    ("sh", "curl"),
    ("sh", "wget"),
    ("python", "sh"),
    ("python", "bash"),
    ("php", "sh"),
    ("php", "bash"),
    ("cron", "sh"),
    ("systemd", "sh"),
]


def now():
    return datetime.now(timezone.utc).isoformat()


def read_text(path):
    try:
        return Path(path).read_text(errors="ignore")
    except Exception:
        return ""


def write_event(event):
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    with REPORT_FILE.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, ensure_ascii=False) + "\n")


def list_pids():
    pids = []

    try:
        for item in Path("/proc").iterdir():
            if item.name.isdigit():
                pids.append(int(item.name))
    except Exception:
        pass

    return sorted(pids)


def process_info(pid):
    base = Path(f"/proc/{pid}")

    cmdline_raw = read_text(base / "cmdline")
    cmdline = cmdline_raw.replace("\x00", " ").strip()

    comm = read_text(base / "comm").strip()

    status = read_text(base / "status")
    ppid = 0

    for line in status.splitlines():
        if line.startswith("PPid:"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                ppid = int(parts[1])
            break

    exe = ""

    try:
        exe = os.readlink(base / "exe")
    except Exception:
        pass

    return {
        "pid": pid,
        "ppid": ppid,
        "comm": comm,
        "cmdline": cmdline,
        "exe": exe,
    }


def collect_processes():
    processes = {}

    for pid in list_pids():
        info = process_info(pid)

        if info["comm"] or info["cmdline"] or info["exe"]:
            processes[pid] = info

    return processes


def score_process(info, processes):
    score = 0
    reasons = []

    comm = info.get("comm", "").lower()
    cmdline = info.get("cmdline", "")
    cmdline_lower = cmdline.lower()
    exe = info.get("exe", "")

    # Detect execution from writable or memory-backed directories.
    # Linux malware often runs from /tmp, /var/tmp or /dev/shm.
    for path in SUSPICIOUS_EXEC_PATHS:
        if exe.startswith(path):
            score += 35
            reasons.append(f"exec_from:{path.rstrip('/')}")

    # Detect suspicious command line markers.
    # These markers are common in droppers, miners, reverse shells and persistence scripts.
    for marker in SUSPICIOUS_CMD_MARKERS:
        if marker.lower() in cmdline_lower:
            score += 12
            reasons.append(f"cmd_marker:{marker}")

    # Detect suspicious process names.
    # Names alone are weak signals, so they add a small score only.
    for name in SUSPICIOUS_PROCESS_NAMES:
        if comm == name:
            score += 5
            reasons.append(f"suspicious_process_name:{name}")
            break

    parent = processes.get(info.get("ppid", 0))

    if parent:
        parent_comm = parent.get("comm", "").lower()

        # Detect suspicious parent-child chains.
        # Malware droppers often create shell, curl/wget and interpreter chains.
        for parent_marker, child_marker in PROCESS_CHAIN_MARKERS:
            if parent_marker in parent_comm and child_marker in comm:
                score += 30
                reasons.append(f"process_chain:{parent_marker}->{child_marker}")

    return min(score, 100), reasons


def severity_from_score(score):
    if score >= 80:
        return "HIGH"

    if score >= 45:
        return "SUSPICIOUS"

    if score >= 20:
        return "LOW"

    return "INFO"


def scan():
    processes = collect_processes()
    events = []

    for pid, info in processes.items():
        score, reasons = score_process(info, processes)

        if score < 20:
            continue

        event = {
            "time": now(),
            "engine": "otx-behavior-monitor",
            "version": "0.1.2-alpha",
            "event": "PROCESS_BEHAVIOR_SUSPICIOUS",
            "severity": severity_from_score(score),
            "score": score,
            "pid": pid,
            "ppid": info.get("ppid"),
            "process": info.get("comm"),
            "exe": info.get("exe"),
            "cmdline": info.get("cmdline"),
            "reasons": reasons,
            "recommendation": "Review process tree, executable path, command line and related network activity.",
        }

        events.append(event)
        write_event(event)

    return events


def main():
    events = scan()

    print(json.dumps({
        "engine": "otx-behavior-monitor",
        "version": "0.1.2-alpha",
        "event_count": len(events),
        "events": events,
    }, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
