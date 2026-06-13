import json
import math
import subprocess
from pathlib import Path

SUSPICIOUS_STRINGS = [
    "powershell", "cmd.exe", "/bin/sh", "/bin/bash",
    "nc ", "netcat", "wget ", "curl ", "chmod +x",
    "base64", "eval(", "exec(", "socket", "connect",
    "reverse", "payload", "mimikatz", "meterpreter",
]


def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0

    counts = [0] * 256
    for b in data:
        counts[b] += 1

    entropy = 0.0
    length = len(data)

    for count in counts:
        if count == 0:
            continue
        p = count / length
        entropy -= p * math.log2(p)

    return round(entropy, 3)


def extract_strings(path: str, limit: int = 200) -> list[str]:
    try:
        result = subprocess.run(
            ["strings", "-n", "6", path],
            capture_output=True,
            text=True,
            timeout=20,
        )
        return result.stdout.splitlines()[:limit]
    except Exception:
        return []


def detect_file_type(path: str) -> str:
    try:
        result = subprocess.run(
            ["file", "-b", path],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.stdout.strip() or "unknown"
    except Exception:
        return "unknown"


def analyze_file(path: str) -> dict:
    p = Path(path)

    result = {
        "path": str(p),
        "exists": p.exists(),
        "size": 0,
        "file_type": "unknown",
        "entropy": 0.0,
        "packed_suspected": False,
        "suspicious_strings": [],
        "risk_score": 0,
        "reasons": [],
    }

    if not p.exists() or not p.is_file() or p.is_symlink():
        result["reasons"].append("not_regular_file")
        return result

    try:
        size = p.stat().st_size
        result["size"] = size

        if size == 0:
            result["reasons"].append("empty_file")
            return result

        sample_size = min(size, 1024 * 1024)
        with p.open("rb") as f:
            data = f.read(sample_size)

        entropy = calculate_entropy(data)
        result["entropy"] = entropy
        result["file_type"] = detect_file_type(str(p))

        if entropy >= 7.4 and size > 4096:
            result["packed_suspected"] = True
            result["risk_score"] += 25
            result["reasons"].append("high_entropy_possible_packing")

        strings = extract_strings(str(p))
        lower_strings = [s.lower() for s in strings]
        suspicious = []

        for marker in SUSPICIOUS_STRINGS:
            marker_l = marker.lower()
            if any(marker_l in s for s in lower_strings):
                suspicious.append(marker)

        if suspicious:
            result["suspicious_strings"] = sorted(set(suspicious))
            result["risk_score"] += min(40, len(set(suspicious)) * 10)
            result["reasons"].append("suspicious_strings_found")

        file_type_lower = result["file_type"].lower()

        if "elf" in file_type_lower:
            result["reasons"].append("elf_binary")

        if "pe32" in file_type_lower or "ms-dos executable" in file_type_lower:
            result["reasons"].append("windows_pe_binary")

        result["risk_score"] = min(result["risk_score"], 100)
        return result

    except PermissionError:
        result["reasons"].append("permission_denied")
        return result
    except Exception as e:
        result["reasons"].append(f"analysis_error:{e}")
        return result


def main():
    import sys

    if len(sys.argv) != 2:
        print("Usage: python -m engines.static_analysis <file>")
        raise SystemExit(1)

    print(json.dumps(analyze_file(sys.argv[1]), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
