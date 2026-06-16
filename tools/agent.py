#!/usr/bin/env python3

import os
import json
import time
import hashlib
import math
import shutil
import subprocess
from pathlib import Path
from datetime import datetime
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from engines.threat_engine import ThreatEngine
from engines.yara_engine import scan_file as yara_scan_file
from engines.static_analysis import analyze_file

BASE_DIR = Path(os.environ.get("OTX_SEC_BASE_DIR", Path(__file__).resolve().parent))
DATA_DIR = Path(os.environ.get("OTX_SEC_DATA_DIR", BASE_DIR / "data"))
CONFIG_DIR = Path(os.environ.get("OTX_SEC_CONFIG_DIR", BASE_DIR / "config"))

CONFIG_FILE = Path(os.environ.get("OTX_SEC_CONFIG_FILE", CONFIG_DIR / "settings.json"))
ALLOWLIST = Path(os.environ.get("OTX_SEC_ALLOWLIST", CONFIG_DIR / "allowlist.json"))
BLOCKLIST = Path(os.environ.get("OTX_SEC_BLOCKLIST", CONFIG_DIR / "blocklist.json"))

DEFAULT_HOME = str(Path.home())

WATCH_PATHS = [
    DEFAULT_HOME,
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
    str(Path.home() / ".cache"),
    str(Path.home() / ".config" / "BraveSoftware"),
    str(Path.home() / ".mozilla"),
    str(Path.home() / ".steam"),
    str(Path.home() / ".local" / "share" / "Steam"),
    "/var/quarantine",
    str(BASE_DIR / "venv"),
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

QUARANTINE_DIR = str(Path(os.environ.get("OTX_SEC_QUARANTINE_DIR", DATA_DIR / "quarantine")))
REPORT_FILE = str(Path(os.environ.get("OTX_SEC_REPORT_FILE", DATA_DIR / "logs" / "report.jsonl")))
SCAN_INTERVAL = int(os.environ.get("OTX_SEC_SCAN_INTERVAL", "300"))

os.makedirs(QUARANTINE_DIR, exist_ok=True)
os.makedirs(os.path.dirname(REPORT_FILE), exist_ok=True)
os.makedirs(CONFIG_DIR, exist_ok=True)

seen_hashes = set()


def now():
    return datetime.now().isoformat()


def load_settings():
    default = {
        "otx_api_key": "",
        "auto_quarantine": True,
        "watch_paths": WATCH_PATHS,
        "exclude_dirs": list(EXCLUDE_DIRS),
        "skip_extensions": list(SKIP_EXTENSIONS),
        "max_file_size_mb": MAX_FILE_SIZE // (1024 * 1024),
        "scan_interval": SCAN_INTERVAL,
    }

    if not CONFIG_FILE.exists():
        return default

    try:
        data = json.loads(CONFIG_FILE.read_text())
        if not isinstance(data, dict):
            return default
        for k, v in default.items():
            data.setdefault(k, v)
        return data
    except Exception:
        return default


def expand_path(value):
    return os.path.abspath(os.path.expanduser(str(value)))


def runtime_watch_paths():
    settings = load_settings()
    paths = settings.get("watch_paths", WATCH_PATHS)
    if not isinstance(paths, list):
        paths = WATCH_PATHS
    return [expand_path(p) for p in paths]


def runtime_exclude_dirs():
    settings = load_settings()
    dirs = settings.get("exclude_dirs", list(EXCLUDE_DIRS))
    if not isinstance(dirs, list):
        dirs = list(EXCLUDE_DIRS)
    return {expand_path(p) for p in dirs}


def runtime_skip_extensions():
    settings = load_settings()
    exts = settings.get("skip_extensions", list(SKIP_EXTENSIONS))
    if not isinstance(exts, list):
        exts = list(SKIP_EXTENSIONS)
    return {str(e).lower() for e in exts if str(e).startswith(".")}


def runtime_max_file_size():
    settings = load_settings()
    try:
        mb = int(settings.get("max_file_size_mb", MAX_FILE_SIZE // (1024 * 1024)))
        mb = max(1, min(mb, 2048))
        return mb * 1024 * 1024
    except Exception:
        return MAX_FILE_SIZE


def runtime_scan_interval():
    settings = load_settings()
    try:
        sec = int(settings.get("scan_interval", SCAN_INTERVAL))
        return max(30, min(sec, 86400))
    except Exception:
        return SCAN_INTERVAL


def load_list(path):
    if not path.exists():
        path.write_text("[]")
        os.chmod(path, 0o600)

    try:
        return json.loads(path.read_text())
    except Exception:
        return []



def auto_quarantine_enabled():
    settings = load_settings()
    return bool(settings.get("auto_quarantine", True))


def notify(title, message):
    cmd = [
        "notify-send",
        str(title)[:120],
        str(message)[:1000],
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
        print(f"[NOTIFY] {title}: {message}", flush=True)


def is_excluded(path):
    path = os.path.abspath(path)

    for excluded in runtime_exclude_dirs():
        if path == excluded or path.startswith(excluded + os.sep):
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

    if ext in runtime_skip_extensions():
        return True

    try:
        if os.path.getsize(path) > runtime_max_file_size():
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




def load_hash_list(name):
    path = BASE_DIR / "tools" / "config" / name
    try:
        data = json.loads(path.read_text())
        if isinstance(data, list):
            return set(str(x).lower() for x in data)
        if isinstance(data, dict):
            return set(str(x).lower() for x in data.get("hashes", []))
    except Exception:
        pass
    return set()


def otx_native_scan(path):
    # Native OTXv2 detection layer.
    # This is our own engine logic. YARA is a separate OTXv2 rule layer.
    reasons = []
    score = 0
    file_path = Path(path)

    details = {
        "engine_version": "0.1.1-alpha",
        "entropy": 0.0,
        "file_extension": file_path.suffix.lower(),
        "is_hidden": file_path.name.startswith("."),
        "is_executable": False,
        "is_script": False,
        "file_type": "unknown",
    }

    try:
        data = file_path.read_bytes()
    except Exception as e:
        return False, f"native_error: {e}", 0, ["read_error"], details

    size = len(data)
    if size == 0:
        return False, "CLEAN_NATIVE", 0, ["empty_file"], details

    try:
        mode = file_path.stat().st_mode
        details["is_executable"] = bool(mode & 0o111)
    except Exception:
        pass

    if data.startswith(b"#!"):
        details["is_script"] = True
        score += 8
        reasons.append("script_shebang")

    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1

    entropy = -sum((c / size) * math.log2(c / size) for c in freq.values())
    details["entropy"] = round(entropy, 4)

    if entropy >= 7.8:
        score += 40
        reasons.append("very_high_entropy")
    elif entropy >= 7.2:
        score += 25
        reasons.append("high_entropy")

    lowered = data.lower()
    markers = [
        b"/bin/sh", b"chmod +x", b"curl ", b"wget ",
        b"base64", b"eval(", b"exec(", b"system(",
        b"crontab", b"systemctl enable", b"ld_preload",
        b"reverse shell", b"cmd.exe", b"powershell",
        b"virtualalloc", b"createremotethread", b"writeprocessmemory",
    ]

    for marker in markers:
        if marker in lowered:
            score += 12
            reasons.append("native_marker:" + marker.decode(errors="ignore"))

    if data.startswith(b"\x7fELF"):
        details["file_type"] = "elf"
        reasons.append("elf_binary")
        if entropy >= 7.0:
            score += 15
            reasons.append("packed_like_elf")

    elif data.startswith(b"MZ"):
        details["file_type"] = "pe"
        reasons.append("pe_binary")
        if entropy >= 7.0:
            score += 15
            reasons.append("packed_like_pe")

    elif details["is_script"]:
        details["file_type"] = "script"

    suffix = details["file_extension"]

    suspicious_exts = {
        ".sh", ".py", ".pl", ".rb", ".php", ".js",
        ".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1"
    }

    if suffix in suspicious_exts:
        score += 8
        reasons.append("suspicious_extension:" + suffix)

    if details["is_hidden"] and suffix in suspicious_exts:
        score += 10
        reasons.append("hidden_executable_like_file")

    if details["is_executable"]:
        score += 8
        reasons.append("executable_permission")

    if score >= 70:
        return True, "MALICIOUS_NATIVE", score, reasons, details
    if score >= 40:
        return True, "SUSPICIOUS_NATIVE", score, reasons, details

    return False, "CLEAN_NATIVE", score, reasons, details


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

        native_hit, native_output, native_score, native_reasons, native_details = otx_native_scan(path)

        allowlist = load_hash_list("allowlist.json")
        blocklist = load_hash_list("blocklist.json")

        if file_hash.lower() in allowlist:
            print(f"[ALLOWLIST] {path}", flush=True)
            return

        threat = ThreatEngine(load_settings()).lookup_hash(file_hash)
        static = analyze_file(path)

        if file_hash.lower() in blocklist:
            threat["score"] = max(threat.get("score", 0), 100)
            threat["verdict"] = "MALICIOUS"
            threat.setdefault("reasons", []).append("blocklist_hash_match")


        # YARA is part of the OTXv2 rule layer.
        # It is not used as an external antivirus engine.
        # We keep it optional at runtime so the agent does not crash
        # if yara-python is missing on a test system.
        yara_result = yara_scan_file(path)

        status = threat.get("verdict", "UNKNOWN")
        score = max(
            int(threat.get("score", 0)),
            int(static.get("risk_score", 0)),
            int(yara_result.get("risk_score", 0)),
            int(native_score),
        )

        if static.get("risk_score", 0) >= 50 and status == "CLEAN":
            status = "SUSPICIOUS"

        if native_hit:
            status = "MALICIOUS" if native_score >= 70 else "SUSPICIOUS"
            score = max(score, native_score)
            threat.setdefault("reasons", []).append("otx_native_match")
            threat.setdefault("reasons", []).extend(native_reasons)

        quarantine_path = None
        quarantine_error = None

        if status == "MALICIOUS" and auto_quarantine_enabled():
            quarantine_path, quarantine_error = quarantine(path, file_hash)

        entry = {
            "time": now(),
            "file": path,
            "sha256": file_hash,
            "size": size,
            "engine": "otx-native",
            "native_hit": native_hit,
            "native_output": native_output,
            "native_score": native_score,
            "native_reasons": native_reasons,
            "native_details": native_details,
            "yara": yara_result,
            "threat_score": score,
            "threat_verdict": status,
            "threat_reasons": threat.get("reasons", []),
            "threat_providers": threat.get("providers", {}),
            "static_analysis": static,
            "status": status,
            "quarantine_path": quarantine_path,
            "quarantine_error": quarantine_error,
            "recommendation": (
                "QUARANTINE + verify threat intelligence results"
                if status == "MALICIOUS"
                else "Review if UNKNOWN/SUSPICIOUS. No known malicious result if CLEAN."
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

    for base in runtime_watch_paths():
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
        interval = runtime_scan_interval()
        print(f"[*] Sleeping {interval}s", flush=True)
        time.sleep(interval)


if __name__ == "__main__":
    main()
