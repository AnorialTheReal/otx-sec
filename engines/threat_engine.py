from integrations.otx import OTXProvider
from integrations.malwarebazaar import MalwareBazaarProvider
from integrations.virustotal import VirusTotalProvider
from integrations.urlhaus import URLHausProvider


class ThreatEngine:
    def __init__(self, settings: dict | None = None):
        self.settings = settings or {}
        self.otx = OTXProvider(self.settings.get("otx_api_key", ""))
        self.malwarebazaar = MalwareBazaarProvider()
        self.virustotal = VirusTotalProvider(self.settings.get("virustotal_api_key", ""))
        self.urlhaus = URLHausProvider()

    def score_hash_result(self, otx_result, mb_result, vt_result):
        score = 0
        reasons = []

        if otx_result.get("hits", 0) > 0:
            score += 50
            reasons.append("otx_pulse_match")

        if mb_result.get("found"):
            score += 70
            reasons.append("malwarebazaar_match")

        if vt_result.get("malicious", 0) > 0:
            score += min(70, 20 + vt_result.get("malicious", 0) * 5)
            reasons.append("virustotal_malicious_match")

        elif vt_result.get("suspicious", 0) > 0:
            score += 25
            reasons.append("virustotal_suspicious_match")

        if otx_result.get("error"):
            reasons.append("otx_unavailable_or_error")

        if mb_result.get("error") or mb_result.get("hits") == -1:
            reasons.append("malwarebazaar_unavailable_or_error")

        if vt_result.get("error") or vt_result.get("hits") == -1:
            reasons.append("virustotal_unavailable_or_error")

        score = min(score, 100)

        if score >= 80:
            verdict = "MALICIOUS"
        elif score >= 40:
            verdict = "SUSPICIOUS"
        elif reasons and score == 0:
            verdict = "UNKNOWN"
        else:
            verdict = "CLEAN"

        return score, verdict, reasons

    def lookup_hash(self, sha256: str):
        # Hash reputation layer.
        # Every file scan should include these providers in the report:
        # - OTX
        # - MalwareBazaar
        # - VirusTotal
        #
        # Missing API keys or provider errors must never crash the scanner.
        # Providers return structured error objects instead.
        otx_result = self.otx.hash_lookup(sha256)
        mb_result = self.malwarebazaar.hash_lookup(sha256)
        vt_result = self.virustotal.hash_lookup(sha256)

        score, verdict, reasons = self.score_hash_result(otx_result, mb_result, vt_result)

        return {
            "type": "hash",
            "indicator": sha256,
            "score": score,
            "verdict": verdict,
            "reasons": reasons,
            "providers": {
                "otx": otx_result,
                "malwarebazaar": mb_result,
                "virustotal": vt_result,
            },
        }

    def lookup_ip(self, ip: str):
        otx_result = self.otx.ip_lookup(ip)

        score = 50 if otx_result.get("hits", 0) > 0 else 0
        verdict = "SUSPICIOUS" if score else "CLEAN"

        return {
            "type": "ip",
            "indicator": ip,
            "score": score,
            "verdict": verdict,
            "reasons": ["otx_ip_match"] if score else [],
            "providers": {
                "otx": otx_result,
            },
        }

    def lookup_domain(self, domain: str):
        otx_result = self.otx.domain_lookup(domain)
        urlhaus_result = self.urlhaus.host_lookup(domain)

        score = 0
        reasons = []

        if otx_result.get("hits", 0) > 0:
            score += 50
            reasons.append("otx_domain_match")

        if urlhaus_result.get("found"):
            score += 70
            reasons.append("urlhaus_host_match")

        if otx_result.get("error"):
            reasons.append("otx_unavailable_or_error")

        if urlhaus_result.get("error") or urlhaus_result.get("hits") == -1:
            reasons.append("urlhaus_unavailable_or_error")

        score = min(score, 100)

        if score >= 80:
            verdict = "MALICIOUS"
        elif score >= 40:
            verdict = "SUSPICIOUS"
        elif reasons and score == 0:
            verdict = "UNKNOWN"
        else:
            verdict = "CLEAN"

        return {
            "type": "domain",
            "indicator": domain,
            "score": score,
            "verdict": verdict,
            "reasons": reasons,
            "providers": {
                "otx": otx_result,
                "urlhaus": urlhaus_result,
            },
        }

    def lookup_url(self, url: str):
        otx_result = self.otx.url_lookup(url)
        urlhaus_result = self.urlhaus.url_lookup(url)

        score = 0
        reasons = []

        if otx_result.get("hits", 0) > 0:
            score += 50
            reasons.append("otx_url_match")

        if urlhaus_result.get("found"):
            score += 80
            reasons.append("urlhaus_url_match")

        if otx_result.get("error"):
            reasons.append("otx_unavailable_or_error")

        if urlhaus_result.get("error") or urlhaus_result.get("hits") == -1:
            reasons.append("urlhaus_unavailable_or_error")

        score = min(score, 100)

        if score >= 80:
            verdict = "MALICIOUS"
        elif score >= 40:
            verdict = "SUSPICIOUS"
        elif reasons and score == 0:
            verdict = "UNKNOWN"
        else:
            verdict = "CLEAN"

        return {
            "type": "url",
            "indicator": url,
            "score": score,
            "verdict": verdict,
            "reasons": reasons,
            "providers": {
                "otx": otx_result,
                "urlhaus": urlhaus_result,
            },
        }


def _load_settings():
    import json
    import os
    from pathlib import Path

    base_dir = Path(os.environ.get("OTX_SEC_BASE_DIR", Path(__file__).resolve().parent.parent))
    config_file = Path(os.environ.get("OTX_SEC_CONFIG_FILE", base_dir / "config" / "settings.json"))

    try:
        data = json.loads(config_file.read_text())
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def main():
    import json
    import sys

    if len(sys.argv) < 3:
        print("Usage:")
        print("  python -m engines.threat_engine hash <sha256>")
        print("  python -m engines.threat_engine ip <ip>")
        print("  python -m engines.threat_engine domain <domain>")
        print("  python -m engines.threat_engine url <url>")
        raise SystemExit(1)

    kind = sys.argv[1].lower()
    value = sys.argv[2]

    engine = ThreatEngine(_load_settings())

    if kind == "hash":
        result = engine.lookup_hash(value)
    elif kind == "ip":
        result = engine.lookup_ip(value)
    elif kind == "domain":
        result = engine.lookup_domain(value)
    elif kind == "url":
        result = engine.lookup_url(value)
    else:
        print(f"Unknown lookup type: {kind}")
        raise SystemExit(1)

    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
