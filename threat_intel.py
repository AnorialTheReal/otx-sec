#!/usr/bin/env python3
import sys, json
from pathlib import Path

sys.path.insert(0, "/opt/otx-sec/app")
import backend

def vt_hash(hash_value):
    return backend.virustotal_hash_lookup(hash_value)

def vt_file(path):
    return backend.virustotal_file_lookup(path)

def abuseipdb_lookup(ip):
    try:
        import requests
    except Exception as e:
        return f"requests missing: {e}"

    key = backend.load_settings().get("abuseipdb_api_key", "").strip()
    if not key:
        return "AbuseIPDB API key missing."

    r = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": key, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90},
        timeout=30,
    )
    return json.dumps(r.json(), indent=2) if r.ok else f"{r.status_code}: {r.text[:2000]}"

def greynoise_lookup(ip):
    try:
        import requests
    except Exception as e:
        return f"requests missing: {e}"

    key = backend.load_settings().get("greynoise_api_key", "").strip()
    if not key:
        return "GreyNoise API key missing."

    r = requests.get(
        f"https://api.greynoise.io/v3/community/{ip}",
        headers={"key": key},
        timeout=30,
    )
    return json.dumps(r.json(), indent=2) if r.ok else f"{r.status_code}: {r.text[:2000]}"

def shodan_lookup(ip):
    try:
        import requests
    except Exception as e:
        return f"requests missing: {e}"

    key = backend.load_settings().get("shodan_api_key", "").strip()
    if not key:
        return "Shodan API key missing."

    r = requests.get(f"https://api.shodan.io/shodan/host/{ip}", params={"key": key}, timeout=30)
    return json.dumps(r.json(), indent=2) if r.ok else f"{r.status_code}: {r.text[:2000]}"

def malwarebazaar_lookup(hash_value):
    try:
        import requests
    except Exception as e:
        return f"requests missing: {e}"

    r = requests.post(
        "https://mb-api.abuse.ch/api/v1/",
        data={"query": "get_info", "hash": hash_value},
        timeout=30,
    )
    return json.dumps(r.json(), indent=2) if r.ok else f"{r.status_code}: {r.text[:2000]}"

if __name__ == "__main__":
    print("Use from backend/frontend.")
