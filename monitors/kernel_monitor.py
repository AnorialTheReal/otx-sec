#!/usr/bin/env python3

import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("OTX_SEC_DATA_DIR", BASE_DIR / "tools" / "data"))
LOG_DIR = DATA_DIR / "logs"
REPORT_FILE = LOG_DIR / "kernel_report.jsonl"


SUSPICIOUS_MODULE_MARKERS = [
    "rootkit",
    "diamorphine",
    "reptile",
    "suterusu",
    "adore",
    "hide",
    "hook",
    "syscall",
    "kprobe",
]


SUSPICIOUS_KERNEL_SYMBOLS = [
    "sys_call_table",
    "kallsyms_lookup_name",
    "commit_creds",
    "prepare_kernel_cred",
]


SUSPICIOUS_PATHS = [
    "/dev/shm",
    "/tmp",
    "/var/tmp",
]


def now():
    return datetime.now(timezone.utc).isoformat()


def run_cmd(cmd, timeout=5):
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except Exception as error:
        return "", str(error), -1


def write_event(event):
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    with REPORT_FILE.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, ensure_ascii=False) + "\n")


def list_kernel_modules():
    modules = []

    path = Path("/proc/modules")

    if not path.exists():
        return modules

    try:
        for line in path.read_text(errors="ignore").splitlines():
            parts = line.split()

            if not parts:
                continue

            modules.append({
                "name": parts[0],
                "size": int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0,
                "raw": line,
            })
    except Exception:
        pass

    return modules


def scan_kernel_modules():
    events = []

    for module in list_kernel_modules():
        name = module.get("name", "").lower()
        reasons = []

        # Detect suspicious module names.
        # Kernel rootkits often use names related to hiding, hooks or known rootkit families.
        for marker in SUSPICIOUS_MODULE_MARKERS:
            if marker in name:
                reasons.append(f"suspicious_module_name:{marker}")

        if reasons:
            events.append({
                "time": now(),
                "event": "KERNEL_MODULE_SUSPICIOUS",
                "module": module,
                "severity": "HIGH",
                "score": 80,
                "reasons": reasons,
                "recommendation": "Review loaded kernel module and verify package/source.",
            })

    return events


def scan_kernel_symbols():
    events = []

    stdout, stderr, code = run_cmd(["cat", "/proc/kallsyms"], timeout=5)

    if code != 0 or not stdout:
        events.append({
            "time": now(),
            "event": "KERNEL_SYMBOLS_UNAVAILABLE",
            "severity": "UNKNOWN",
            "score": 20,
            "reasons": ["cannot_read_proc_kallsyms"],
            "error": stderr,
            "recommendation": "Kernel symbol access may be restricted. This can be normal on hardened systems.",
        })
        return events

    found = []

    # Detect access to sensitive kernel symbols.
    # Rootkits often target credential and syscall related symbols.
    for symbol in SUSPICIOUS_KERNEL_SYMBOLS:
        if symbol in stdout:
            found.append(symbol)

    if found:
        events.append({
            "time": now(),
            "event": "KERNEL_SYMBOLS_PRESENT",
            "severity": "INFO",
            "score": 10,
            "reasons": [f"symbol_visible:{item}" for item in found],
            "recommendation": "Visible symbols are not malicious alone, but useful for rootkit context.",
        })

    return events


def list_proc_pids():
    pids = set()

    try:
        for item in Path("/proc").iterdir():
            if item.name.isdigit():
                pids.add(int(item.name))
    except Exception:
        pass

    return pids


def list_ps_pids():
    stdout, stderr, code = run_cmd(["ps", "-e", "-o", "pid="], timeout=5)

    pids = set()

    if code != 0:
        return pids

    for line in stdout.splitlines():
        line = line.strip()

        if line.isdigit():
            pids.add(int(line))

    return pids


def scan_hidden_processes():
    events = []

    proc_pids = list_proc_pids()
    ps_pids = list_ps_pids()

    if not proc_pids or not ps_pids:
        return events

    only_proc = sorted(proc_pids - ps_pids)
    only_ps = sorted(ps_pids - proc_pids)

    # Compare /proc and ps output.
    # Differences can indicate race conditions, permissions, or process hiding behavior.
    if only_proc:
        events.append({
            "time": now(),
            "event": "PROCESS_VISIBLE_IN_PROC_ONLY",
            "severity": "SUSPICIOUS",
            "score": 45,
            "pids": only_proc[:50],
            "reasons": ["pid_visible_in_proc_not_ps"],
            "recommendation": "Review PID visibility. Re-run scan to filter short-lived processes.",
        })

    if only_ps:
        events.append({
            "time": now(),
            "event": "PROCESS_VISIBLE_IN_PS_ONLY",
            "severity": "SUSPICIOUS",
            "score": 45,
            "pids": only_ps[:50],
            "reasons": ["pid_visible_in_ps_not_proc"],
            "recommendation": "Review PID visibility. This can indicate race conditions or hiding behavior.",
        })

    return events


def scan_suspicious_exec_paths():
    events = []

    for pid in list_proc_pids():
        exe = Path(f"/proc/{pid}/exe")

        try:
            target = os.readlink(exe)
        except Exception:
            continue

        # Detect processes executing from temporary memory-backed or writable paths.
        # Linux malware often runs from /tmp, /var/tmp or /dev/shm to avoid normal install paths.
        for suspicious_path in SUSPICIOUS_PATHS:
            if target.startswith(suspicious_path + "/"):
                events.append({
                    "time": now(),
                    "event": "PROCESS_FROM_SUSPICIOUS_PATH",
                    "severity": "HIGH",
                    "score": 75,
                    "pid": pid,
                    "exe": target,
                    "reasons": [f"exec_from:{suspicious_path}"],
                    "recommendation": "Inspect process, parent process, command line and file hash.",
                })

    return events


def scan():
    events = []

    events.extend(scan_kernel_modules())
    events.extend(scan_kernel_symbols())
    events.extend(scan_hidden_processes())
    events.extend(scan_suspicious_exec_paths())

    for event in events:
        write_event(event)

    return events


def main():
    events = scan()

    print(json.dumps({
        "engine": "otx-kernel-monitor",
        "version": "0.1.2-alpha",
        "events": events,
        "event_count": len(events),
    }, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
