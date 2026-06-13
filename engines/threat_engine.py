from integrations.otx import OTXProvider
from integrations.malwarebazaar import MalwareBazaarProvider


class ThreatEngine:
    def __init__(self, settings: dict | None = None):
        self.settings = settings or {}
        self.otx = OTXProvider(self.settings.get("otx_api_key", ""))
        self.malwarebazaar = MalwareBazaarProvider()

    def score_hash_result(self, otx_result, mb_result):
        score = 0
        reasons = []

        if otx_result.get("hits", 0) > 0:
            score += 50
            reasons.append("otx_pulse_match")

        if mb_result.get("found"):
            score += 70
            reasons.append("malwarebazaar_match")

        if otx_result.get("error"):
            reasons.append("otx_unavailable_or_error")

        if mb_result.get("error") or mb_result.get("hits") == -1:
            reasons.append("malwarebazaar_unavailable_or_error")

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
        otx_result = self.otx.hash_lookup(sha256)
        mb_result = self.malwarebazaar.hash_lookup(sha256)

        score, verdict, reasons = self.score_hash_result(otx_result, mb_result)

        return {
            "type": "hash",
            "indicator": sha256,
            "score": score,
            "verdict": verdict,
            "reasons": reasons,
            "providers": {
                "otx": otx_result,
                "malwarebazaar": mb_result,
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

        score = 50 if otx_result.get("hits", 0) > 0 else 0
        verdict = "SUSPICIOUS" if score else "CLEAN"

        return {
            "type": "domain",
            "indicator": domain,
            "score": score,
            "verdict": verdict,
            "reasons": ["otx_domain_match"] if score else [],
            "providers": {
                "otx": otx_result,
            },
        }

    def lookup_url(self, url: str):
        otx_result = self.otx.url_lookup(url)

        score = 50 if otx_result.get("hits", 0) > 0 else 0
        verdict = "SUSPICIOUS" if score else "CLEAN"

        return {
            "type": "url",
            "indicator": url,
            "score": score,
            "verdict": verdict,
            "reasons": ["otx_url_match"] if score else [],
            "providers": {
                "otx": otx_result,
            },
        }
