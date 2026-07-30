import json, os, ssl, time, urllib.request, urllib.error

class GoPhishAPI:
    def __init__(self, api_host: str = "https://127.0.0.1", api_port: int = 3333, api_key: str = None):
        self.base = f"{api_host}:{api_port}/api"
        self.api_key = api_key or os.environ.get("GOPHISH_API_KEY", "")
        self._available = bool(self.api_key)
        self._ctx = ssl.create_default_context()
        self._ctx.check_hostname = False
        self._ctx.verify_mode = ssl.CERT_NONE

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}

    def _api(self, method: str, path: str, data: dict = None) -> dict:
        if not self._available:
            return {"success": False, "error": "API key not set"}
        body = json.dumps(data).encode() if data else None
        req = urllib.request.Request(
            f"{self.base}{path}",
            data=body,
            headers=self._headers(),
            method=method,
        )
        try:
            with urllib.request.urlopen(req, timeout=10, context=self._ctx) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            return {"success": False, "error": f"HTTP {e.code}: {e.read().decode()}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def status(self) -> dict:
        r = self._api("GET", "/users/")
        if isinstance(r, dict) and r.get("success") is False:
            return {"available": False, "error": r.get("error")}
        if isinstance(r, list):
            return {"available": True, "users": len(r)}
        return {"available": True, "response": r}

    def create_campaign(self, name: str, target_group: list, template: dict,
                        url: str, send_by_date: str = None) -> dict:
        if not self._available:
            return {
                "status": "simulated",
                "note": "GoPhish not available",
                "campaign": {
                    "name": name,
                    "targets": len(target_group),
                    "url": url,
                    "template": template.get("subject", "Security Notice"),
                },
            }
        payload = {
            "name": name,
            "template": template,
            "url": url,
            "targets": [{"email": t} if isinstance(t, str) else t for t in target_group],
        }
        if send_by_date:
            payload["send_by_date"] = send_by_date
        return self._api("POST", "/campaigns/", payload)

    def create_smtp_profile(self, host: str, port: int, username: str, password: str,
                            from_address: str, use_tls: bool = True) -> dict:
        if not self._available:
            return {"smtp_host": host, "smtp_port": port, "from_address": from_address, "configured": True}
        payload = {
            "host": host,
            "port": port,
            "username": username,
            "password": password,
            "from_address": from_address,
            "interface_type": "SMTP",
            "ignore_cert_errors": True,
        }
        return self._api("POST", "/smtp/", payload)

    def launch(self, campaign_id: int) -> dict:
        if not self._available:
            return {"status": "simulated", "campaign_id": campaign_id}
        return self._api("PUT", f"/campaigns/{campaign_id}/launch")
