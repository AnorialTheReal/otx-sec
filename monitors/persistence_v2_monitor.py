#!/usr/bin/env python3

import json
import os
from datetime import datetime, timezone
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("OTX_SEC_DATA_DIR", BASE_DIR / "tools" / "data"))
LOG_DIR = DATA_DIR / "logs"
REPORT_FILE = LOG_DIR / "persistence_v2_report.jsonl"


PERSISTENCE_PATHS = [
    "/etc/systemd/system",
    "/lib/systemd/system",
    "/usr/lib/systemd/system",
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
    "/var/spool/cron",
    "/var/spool/cron/crontabs",
    "/etc/profile",
    "/etc/bash.bashrc",
    "/etc/rc.local",
]


USER_PERSISTENCE_FILES = [
    ".bashrc",
    ".profile",
    ".bash_profile",
    ".zshrc",
    ".config/autostart",
    ".config/systemd/user",
]


SUSPICIOUS_MARKERS = [
    "curl ",
    "wget ",
    "bash -c",
    "sh -c",
    "base64",
    "chmod +x",
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "LD_PRELOAD",
    "/etc/ld.so.preload",
    "nohup",
    "setsid",
    "nc ",
    "ncat ",
    "socat ",
    "xmrig",
    "stratum+tcp",
    "authorized_keys",
]


def now():
    return datetime.now(timezone.utc).isoformat()


def write_event(event):
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    with REPORT_FILE.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, ensure_ascii=False) + "\n")


def read_file(path):
    try:
        return Path(path).read_text(errors="ignore")
    except Exception:
        return ""


def scan_text(path, text):
    score = 0
    reasons = []

    lowered = text.lower()

    # Detect suspicious persistence commands.
    # Linux malware commonly uses curl, wget, shell execution and temp paths.
    for marker in SUSPICIOUS_MARKERS:
        if marker.lower() in lowered:
            score += 15
            reasons.append(f"persistence_marker:{marker}")

    # Detect systemd services that run shell interpreters.
    if "[service]" in lowered and ("execstart=/bin/sh" in lowered or "execstart=/bin/bash" in lowered):
        score += 35
        reasons.append("systemd_shell_execstart")

    # Detect cron reboot persistence.
    if "@reboot" in lowered:
        score += 35
        reasons.append("cron_reboot_persistence")

    # Detect suspicious hidden file references.
    if "/." in lowered and ("sh" in lowered or "bash" in lowered):
        score += 15
        reasons.append("hidden_file_shell_reference")

    return min(score, 100), reasons


def iter_paths():
    paths = []

    for item in PERSISTENCE_PATHS:
        path = Path(item)

        if path.is_file():
            paths.append(path)

        if path.is_dir():
            try:
                for child in path.rglob("*"):
                    if child.is_file():
                        paths.append(child)
            except Exception:
                pass

    home_root = Path("/home")
    if home_root.exists():
        for user_home in home_root.iterdir():
            if not user_home.is_dir():
                continue

            for rel in USER_PERSISTENCE_FILES:
                target = user_home / rel

                if target.is_file():
                    paths.append(target)

                if target.is_dir():
                    try:
                        for child in target.rglob("*"):
                            if child.is_file():
                                paths.append(child)
                    except Exception:
                        pass

    return paths


def severity_from_score(score):
    if score >= 80:
        return "HIGH"

    if score >= 45:
        return "SUSPICIOUS"

    if score >= 20:
        return "LOW"

    return "INFO"


def scan():
    events = []

    for path in iter_paths():
        text = read_file(path)

        if not text:
            continue

        score, reasons = scan_text(path, text)

        if score < 20:
            continue

        event = {
            "time": now(),
            "engine": "otx-persistence-v2-monitor",
            "version": "0.1.2-alpha",
            "event": "PERSISTENCE_SUSPICIOUS",
            "severity": severity_from_score(score),
            "score": score,
            "path": str(path),
            "reasons": reasons,
            "recommendation": "Review persistence entry, command line, owner, file hash and package source.",
        }

        events.append(event)
        write_event(event)

    return events


def main():
    events = scan()

    print(json.dumps({
        "engine": "otx-persistence-v2-monitor",
        "version": "0.1.2-alpha",
        "event_count": len(events),
        "events": events,
    }, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
