import os
from pathlib import Path


BASE_DIR = Path(os.environ.get("OTX_SEC_BASE_DIR", Path(__file__).resolve().parent.parent))
DEFAULT_RULE_DIR = Path(os.environ.get("OTX_SEC_YARA_RULES", BASE_DIR / "rules" / "yara"))


def yara_available() -> bool:
    # YARA is optional. OTX-Sec must continue working if yara-python is missing.
    try:
        import yara  # noqa: F401
        return True
    except Exception:
        return False


def scan_file(path: str, rule_dir: str | None = None) -> dict:
    # Scan one file with all .yar/.yara rules from the configured rule directory.
    result = {
        "available": False,
        "path": path,
        "rule_dir": str(rule_dir or DEFAULT_RULE_DIR),
        "matches": [],
        "error": None,
        "risk_score": 0,
    }

    try:
        import yara
    except Exception as e:
        result["error"] = f"yara-python missing: {e}"
        return result

    result["available"] = True

    target = Path(path)
    rules_path = Path(rule_dir or DEFAULT_RULE_DIR)

    if not target.exists() or not target.is_file() or target.is_symlink():
        result["error"] = "target is not a regular file"
        return result

    if not rules_path.exists():
        result["error"] = "rule directory does not exist"
        return result

    rule_files = []
    for pattern in ("*.yar", "*.yara"):
        rule_files.extend(rules_path.rglob(pattern))

    if not rule_files:
        result["error"] = "no yara rules found"
        return result

    for rule_file in rule_files:
        try:
            compiled = yara.compile(filepath=str(rule_file))
            matches = compiled.match(str(target))

            for match in matches:
                result["matches"].append({
                    "rule": str(match.rule),
                    "namespace": str(match.namespace),
                    "tags": list(match.tags),
                    "meta": dict(match.meta),
                    "rule_file": str(rule_file),
                })

        except Exception as e:
            result["matches"].append({
                "rule": "RULE_ERROR",
                "rule_file": str(rule_file),
                "error": str(e),
            })

    if result["matches"]:
        result["risk_score"] = min(100, len(result["matches"]) * 40)

    return result


def main():
    import json
    import sys

    if len(sys.argv) != 2:
        print("Usage: python -m engines.yara_engine <file>")
        raise SystemExit(1)

    print(json.dumps(scan_file(sys.argv[1]), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
