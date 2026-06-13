import requests


class URLHausProvider:
    API_URL = "https://urlhaus-api.abuse.ch/v1"

    def url_lookup(self, url: str):
        try:
            r = requests.post(
                f"{self.API_URL}/url/",
                data={"url": url},
                timeout=20,
            )

            data = r.json()
            status = data.get("query_status")

            if status == "no_results":
                return {
                    "provider": "urlhaus",
                    "available": True,
                    "error": None,
                    "found": False,
                    "hits": 0,
                    "threat": None,
                    "tags": [],
                }

            if status != "ok":
                return {
                    "provider": "urlhaus",
                    "available": True,
                    "error": status,
                    "found": False,
                    "hits": -1,
                    "threat": None,
                    "tags": [],
                }

            return {
                "provider": "urlhaus",
                "available": True,
                "error": None,
                "found": True,
                "hits": 1,
                "threat": data.get("threat"),
                "tags": data.get("tags") or [],
                "url_status": data.get("url_status"),
                "date_added": data.get("date_added"),
            }

        except Exception as e:
            return {
                "provider": "urlhaus",
                "available": False,
                "error": str(e),
                "found": False,
                "hits": -1,
                "threat": None,
                "tags": [],
            }

    def host_lookup(self, host: str):
        try:
            r = requests.post(
                f"{self.API_URL}/host/",
                data={"host": host},
                timeout=20,
            )

            data = r.json()
            status = data.get("query_status")

            if status == "no_results":
                return {
                    "provider": "urlhaus",
                    "available": True,
                    "error": None,
                    "found": False,
                    "hits": 0,
                    "urls": [],
                }

            if status != "ok":
                return {
                    "provider": "urlhaus",
                    "available": True,
                    "error": status,
                    "found": False,
                    "hits": -1,
                    "urls": [],
                }

            urls = data.get("urls") or []

            return {
                "provider": "urlhaus",
                "available": True,
                "error": None,
                "found": bool(urls),
                "hits": len(urls),
                "urls": urls[:10],
            }

        except Exception as e:
            return {
                "provider": "urlhaus",
                "available": False,
                "error": str(e),
                "found": False,
                "hits": -1,
                "urls": [],
            }
