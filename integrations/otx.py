from OTXv2 import OTXv2, IndicatorTypes


class OTXProvider:
    def __init__(self, api_key: str = ""):
        self.api_key = (api_key or "").strip()
        self.client = OTXv2(self.api_key) if self.api_key else None

    def available(self) -> bool:
        return self.client is not None

    def _lookup(self, indicator_type, value: str):
        if not self.client:
            return {
                "provider": "otx",
                "available": False,
                "error": "OTX API key missing",
                "hits": -1,
                "pulses": [],
            }

        try:
            data = self.client.get_indicator_details_full(indicator_type, value)
            pulses = data.get("pulse_info", {}).get("pulses", [])

            clean = []
            for pulse in pulses[:10]:
                clean.append({
                    "name": pulse.get("name"),
                    "id": pulse.get("id"),
                    "created": pulse.get("created"),
                    "tags": pulse.get("tags"),
                })

            return {
                "provider": "otx",
                "available": True,
                "error": None,
                "hits": len(pulses),
                "pulses": clean,
            }

        except Exception as e:
            return {
                "provider": "otx",
                "available": True,
                "error": str(e),
                "hits": -1,
                "pulses": [],
            }

    def hash_lookup(self, sha256: str):
        return self._lookup(IndicatorTypes.FILE_HASH_SHA256, sha256)

    def ip_lookup(self, ip: str):
        return self._lookup(IndicatorTypes.IPv4, ip)

    def domain_lookup(self, domain: str):
        return self._lookup(IndicatorTypes.DOMAIN, domain)

    def hostname_lookup(self, hostname: str):
        return self._lookup(IndicatorTypes.HOSTNAME, hostname)

    def url_lookup(self, url: str):
        return self._lookup(IndicatorTypes.URL, url)
