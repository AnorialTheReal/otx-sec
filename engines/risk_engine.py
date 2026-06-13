#!/usr/bin/env python3
import json

def score_event(event):
    text = json.dumps(event).lower()
    score = 0
    reasons = []

    if "malicious" in text or "found" in text:
        score += 90
        reasons.append("malware signature/threat hit")

    if "/tmp/" in text or "/dev/shm/" in text or "/var/tmp/" in text:
        score += 35
        reasons.append("execution/temp path")

    if "new_persistence" in text or "autostart" in text or "systemd" in text:
        score += 40
        reasons.append("persistence indicator")

    if "external_connection" in text or "remote_ip" in text:
        score += 20
        reasons.append("external network activity")

    if "root" in text:
        score += 15
        reasons.append("root context")

    if "otx_hits" in event and isinstance(event.get("otx_hits"), int) and event.get("otx_hits") > 0:
        score += 80
        reasons.append("OTX pulse hit")

    severity = "INFO"
    if score >= 80:
        severity = "HIGH"
    elif score >= 40:
        severity = "SUSPICIOUS"
    elif score >= 10:
        severity = "LOW"

    return {
        "score": score,
        "severity": severity,
        "reasons": reasons,
    }
