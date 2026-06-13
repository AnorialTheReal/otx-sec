import requests


class VirusTotalProvider:
    API_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str = ""):
        self.api_key = (api_key or "").strip()

    def available(self) -> bool:
        return bool(self.api_key)

    def _headers(self):
        return {
            "x-apikey": self.api_key,
        }

    def hash_lookup(self, sha256: str):
        if not self.api_key:
            return {
                "provider": "virustotal",
                "available": False,
                "error": "VirusTotal API key missing",
                "hits": -1,
                "malicious": 0,
                "suspicious": 0,
                "undetected": 0,
            }

        try:
            r = requests.get(
                f"{self.API_URL}/files/{sha256}",
                headers=self._headers(),
                timeout=20,
            )

            if r.status_code == 404:
                return {
                    "provider": "virustotal",
                    "available": True,
                    "error": None,
                    "hits": 0,
                    "malicious": 0,
                    "suspicious": 0,
                    "undetected": 0,
                }

            if r.status_code != 200:
                return {
                    "provider": "virustotal",
                    "available": True,
                    "error": f"HTTP {r.status_code}",
                    "hits": -1,
                    "malicious": 0,
                    "suspicious": 0,
                    "undetected": 0,
                }

            data = r.json()
            stats = (
                data.get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
            )

            malicious = int(stats.get("malicious", 0))
            suspicious = int(stats.get("suspicious", 0))
            undetected = int(stats.get("undetected", 0))

            return {
                "provider": "virustotal",
                "available": True,
                "error": None,
                "hits": malicious + suspicious,
                "malicious": malicious,
                "suspicious": suspicious,
                "undetected": undetected,
            }

        except Exception as e:
            return {
                "provider": "virustotal",
                "available": False,
                "error": str(e),
                "hits": -1,
                "malicious": 0,
                "suspicious": 0,
                "undetected": 0,
            }
