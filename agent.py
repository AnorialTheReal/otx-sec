#!/opt/otx-sec/venv/bin/python

import os
import json
import time
import hashlib
import shutil
import subprocess
from pathlib import Path
from datetime import datetime
from OTXv2 import OTXv2, IndicatorTypes

CONFIG_FILE = Path("/opt/otx-sec/config/settings.json")
ALLOWLIST = Path("/opt/otx-sec/config/allowlist.json")
BLOCKLIST = Path("/opt/otx-sec/config/blocklist.json")

WATCH_PATHS = [
    "/home/anorial",
    "/root",
    "/etc",
    "/usr/local/bin",
    "/opt",
    "/boot",
]

EXCLUDE_DIRS = {
    "/proc",
    "/sys",
    "/dev",
    "/run",
    "/tmp",
    "/var/tmp",
    "/mnt",
    "/media",
    "/lost+found",
    "/var/log",
    "/var/cache",
    "/home/anorial/.cache",
    "/home/anorial/.config/BraveSoftware",
    "/home/anorial/.mozilla",
    "/home/anorial/.steam",
    "/home/anorial/.local/share/Steam",
    "/var/lib/clamav",
    "/var/quarantine",
    "/opt/otx-sec/venv",
}

SKIP_EXTENSIONS = {
    ".log",
    ".cache",
    ".tmp",
    ".db",
    ".sqlite",
    ".sqlite3",
    ".ldb",
    ".journal",
    ".wal",
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".mp4",
    ".mkv",
    ".webm",
    ".mp3",
    ".wav",
    ".iso",
}

MAX_FILE_SIZE = 50 * 1024 * 1024

QUARANTINE_DIR = "/var/quarantine/otx-sec"
REPORT_FILE = "/var/log/otx-sec/report.jsonl"
SCAN_INTERVAL = 300

os.makedirs(QUARANTINE_DIR, exist_ok=True)
os.makedirs(os.path.dirname(REPORT_FILE), exist_ok=True)
os.makedirs("/opt/otx-sec/config", exist_ok=True)

seen_hashes = set()


def now():
    return datetime.now().isoformat()


def load_settings():
    if not CONFIG_FILE.exists():
        return {
            "otx_api_key": "",
            "auto_quarantine": True,
        }

    try:
        return json.loads(CONFIG_FILE.read_text())
    except Exception:
        return {
            "otx_api_key": "",
            "auto_quarantine": True,
        }


def load_list(path):
    if not path.exists():
        path.write_text("[]")
        os.chmod(path, 0o600)

    try:
        return json.loads(path.read_text())
    except Exception:
        return []


def get_otx_client():
    settings = load_settings()
    api_key = settings.get("otx_api_key", "").strip()

    if not api_key:
        return None

    try:
        return OTXv2(api_key)
    except Exception:
        return None


def auto_quarantine_enabled():
    settings = load_settings()
    return bool(settings.get("auto_quarantine", True))


def notify(title, message):
    try:
        subprocess.Popen([
            "sudo",
            "-u",
            "anorial",
            "env",
            "DISPLAY=:0",
            "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus",
            "notify-send",
            title,
            message,
        ])
    except Exception:
        pass


def is_excluded(path):
    path = os.path.abspath(path)

    for excluded in EXCLUDE_DIRS:
        if path == excluded or path.startswith(excluded + "/"):
            return True

    return False


def should_skip_file(path):
    if is_excluded(path):
        return True

    if not os.path.isfile(path):
        return True

    if os.path.islink(path):
        return True

    ext = os.path.splitext(path)[1].lower()

    if ext in SKIP_EXTENSIONS:
        return True

    try:
        if os.path.getsize(path) > MAX_FILE_SIZE:
            return True
    except Exception:
        return True

    return False


def sha256(path):
    h = hashlib.sha256()

    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)

    return h.hexdigest()


def clam_scan(path):
    try:
        result = subprocess.run(
            ["clamscan", "--no-summary", path],
            capture_output=True,
            text=True,
            timeout=60,
        )

        output = (result.stdout + result.stderr).strip()
        return "FOUND" in output, output

    except Exception as e:
        return False, f"clamav_error: {e}"


def otx_check(file_hash):
    otx = get_otx_client()

    if not otx:
        return -1, [], "OTX API key missing or invalid"

    try:
        data = otx.get_indicator_details_full(
            IndicatorTypes.FILE_HASH_SHA256,
            file_hash,
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


def quarantine(path, file_hash):
    try:
        target = os.path.join(
            QUARANTINE_DIR,
            f"{file_hash}_{os.path.basename(path)}",
        )

        counter = 1
        original = target

        while os.path.exists(target):
            target = original + f".{counter}"
            counter += 1

        shutil.move(path, target)
        os.chmod(target, 0o000)

        return target, None

    except Exception as e:
        return None, str(e)


def write_report(entry):
    with open(REPORT_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def scan_file(path):
    if should_skip_file(path):
        return

    try:
        size = os.path.getsize(path)
        file_hash = sha256(path)

        allowlist = load_list(ALLOWLIST)
        blocklist = load_list(BLOCKLIST)

        if file_hash in seen_hashes:
            return

        seen_hashes.add(file_hash)

        if file_hash in allowlist:
            entry = {
                "time": now(),
                "file": path,
                "sha256": file_hash,
                "size": size,
                "status": "ALLOWED",
                "recommendation": "Hash is in allowlist.",
            }
            write_report(entry)
            print(f"[ALLOW] {path}", flush=True)
            return

        if file_hash in blocklist:
            quarantine_path = None
            quarantine_error = None

            if auto_quarantine_enabled():
                quarantine_path, quarantine_error = quarantine(path, file_hash)

            entry = {
                "time": now(),
                "file": path,
                "sha256": file_hash,
                "size": size,
                "status": "BLOCKED",
                "quarantine_path": quarantine_path,
                "quarantine_error": quarantine_error,
                "recommendation": "Hash is in blocklist.",
            }

            write_report(entry)
            notify("OTX-Sec Blocked File", f"{path}\n{file_hash}")
            print(f"[BLOCK] {path}", flush=True)
            return

        clam_hit, clam_output = clam_scan(path)

        otx_hits = 0
        otx_pulses = []
        otx_error = None

        if clam_hit:
            status = "MALICIOUS"
        else:
            otx_hits, otx_pulses, otx_error = otx_check(file_hash)
            status = "MALICIOUS" if otx_hits > 0 else "CLEAN"

        quarantine_path = None
        quarantine_error = None

        if status == "MALICIOUS" and auto_quarantine_enabled():
            quarantine_path, quarantine_error = quarantine(path, file_hash)

        entry = {
            "time": now(),
            "file": path,
            "sha256": file_hash,
            "size": size,
            "clamav_hit": clam_hit,
            "clamav_output": clam_output,
            "otx_hits": otx_hits,
            "otx_error": otx_error,
            "otx_pulses": otx_pulses,
            "status": status,
            "quarantine_path": quarantine_path,
            "quarantine_error": quarantine_error,
            "recommendation": (
                "QUARANTINE + VirusTotal prüfen"
                if status == "MALICIOUS"
                else "Keine bekannten Treffer"
            ),
        }

        write_report(entry)

        if status == "MALICIOUS":
            notify("OTX-Sec Malware Alert", f"{path}\n{file_hash}")
            print(f"[!] MALICIOUS: {path}", flush=True)
            print(f"    Quarantine: {quarantine_path}", flush=True)
        else:
            print(f"[OK] {path}", flush=True)

    except PermissionError:
        return
    except FileNotFoundError:
        return
    except Exception as e:
        write_report({
            "time": now(),
            "file": path,
            "status": "ERROR",
            "error": str(e),
        })


def collect_files():
    files = []

    for base in WATCH_PATHS:
        if not os.path.exists(base):
            continue

        for root, dirs, names in os.walk(base):
            dirs[:] = [
                d for d in dirs
                if not is_excluded(os.path.join(root, d))
            ]

            for name in names:
                path = os.path.join(root, name)

                if not should_skip_file(path):
                    try:
                        files.append((os.path.getmtime(path), path))
                    except Exception:
                        pass

    files.sort(reverse=True)
    return [path for _, path in files]


def full_scan():
    print("[*] Scan started: newest files first", flush=True)

    for path in collect_files():
        scan_file(path)

    print("[*] Scan finished", flush=True)


def main():
    while True:
        full_scan()
        print(f"[*] Sleeping {SCAN_INTERVAL}s", flush=True)
        time.sleep(SCAN_INTERVAL)


if __name__ == "__main__":
    main()
