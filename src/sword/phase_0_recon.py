import sys, os, subprocess, json, re, asyncio, socket
from pathlib import Path

_parent = str(Path(__file__).resolve().parent.parent)
if _parent not in sys.path:
    sys.path.insert(0, _parent)


class Phase0Recon:
    def __init__(self, target: str, api_keys: dict = None):
        self.target = target
        self.api_keys = api_keys or {}

    async def run(self) -> dict:
        osint_task = asyncio.create_task(self._osint())
        crt_task = asyncio.create_task(self._crt_sh())
        shodan_task = asyncio.create_task(self._shodan())
        sub_task = asyncio.create_task(self._subdomains())
        dns_task = asyncio.create_task(self._dns())
        tech_task = asyncio.create_task(self._tech_fingerprint())

        _ok = lambda v, d: v if not isinstance(v, Exception) else d

        osint_res, crt_res, shodan_res, sub_res, dns_res, tech_res = await asyncio.gather(
            osint_task, crt_task, shodan_task, sub_task, dns_task, tech_task,
            return_exceptions=True
        )

        dns_records = _ok(dns_res, {})
        return {
            "target": self.target,
            "subdomains": _ok(sub_res, []),
            "ips": self._extract_ips(dns_records),
            "tech_stack": _ok(tech_res, {}),
            "emails": self._emails(self.target),
            "dns_records": dns_records,
            "osint": _ok(osint_res, {}),
            "shodan": _ok(shodan_res, {}),
            "crt_sh_data": _ok(crt_res, []),
        }

    def _extract_ips(self, dns_records: dict) -> list:
        ips = []
        for qt in ("A", "AAAA"):
            ips.extend(dns_records.get(qt, []))
        return list(set(ips))

    async def _osint(self) -> dict:
        from orchestrator.spiderfoot_wrapper import SpiderFootWrapper
        from orchestrator.karma_wrapper import KarmaV2Wrapper
        sf = SpiderFootWrapper()
        karma = KarmaV2Wrapper()
        sf_res = await asyncio.to_thread(sf.scan, self.target)
        karma_res = await asyncio.to_thread(karma.scan, self.target)
        return {"spiderfoot": sf_res, "karma_v2": karma_res}

    async def _crt_sh(self) -> list:
        import httpx
        url = f"https://crt.sh/?q=%25.{self.target}&output=json"
        try:
            async with httpx.AsyncClient(timeout=30, verify=False) as c:
                r = await c.get(url, headers={"User-Agent": "Mozilla/5.0"})
                if r.status_code == 200:
                    return r.json() if isinstance(r.json(), list) else []
        except Exception:
            pass
        return []

    async def _shodan(self) -> dict:
        key = self.api_keys.get("shodan") or os.environ.get("SHODAN_API_KEY")
        if not key:
            return {}
        import httpx
        try:
            async with httpx.AsyncClient(timeout=15) as c:
                r = await c.get(
                    f"https://api.shodan.io/shodan/host/{self.target}",
                    params={"key": key}
                )
                if r.status_code == 200:
                    return r.json()
        except Exception:
            pass
        return {}

    async def _subdomains(self) -> list:
        try:
            proc = await asyncio.create_subprocess_exec(
                "subfinder", "-d", self.target, "-oJ",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
            subs = []
            for line in stdout.decode().strip().split("\n"):
                line = line.strip()
                if line:
                    try:
                        subs.append(json.loads(line))
                    except json.JSONDecodeError:
                        subs.append(line)
            return subs
        except (FileNotFoundError, asyncio.TimeoutError, subprocess.TimeoutExpired):
            return []

    async def _dns(self) -> dict:
        records = {}
        for qt in ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"):
            try:
                r = await self._resolve_type(qt)
                if r:
                    records[qt] = r
            except Exception:
                pass
        return records

    async def _resolve_type(self, qtype: str) -> list:
        if qtype in ("A", "AAAA"):
            family = socket.AF_INET if qtype == "A" else socket.AF_INET6
            try:
                info = socket.getaddrinfo(self.target, None, family)
                return list(set(i[4][0] for i in info))[:20]
            except socket.gaierror:
                return []
        try:
            proc = await asyncio.create_subprocess_exec(
                "dig", "+short", qtype, self.target,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            return [l.strip() for l in stdout.decode().strip().split("\n") if l.strip()][:20]
        except (FileNotFoundError, asyncio.TimeoutError):
            return []

    def _emails(self, target: str) -> list:
        import httpx
        found = set()
        try:
            r = httpx.get(
                f"https://crt.sh/?q=%25.{target}&output=json",
                timeout=30, verify=False
            )
            if r.status_code == 200:
                for cert in r.json():
                    for field in ("name_value", "common_name", "issuer_name"):
                        val = cert.get(field, "")
                        found.update(re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+", str(val)))
        except Exception:
            pass
        for scheme in ("https", "http"):
            try:
                r = httpx.get(
                    f"{scheme}://{target}", timeout=15, verify=False,
                    headers={"User-Agent": "Mozilla/5.0"}
                )
                found.update(re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+", r.text))
            except Exception:
                continue
        return sorted(set(e for e in found if target.lower() in e.lower()))[:30]

    async def _tech_fingerprint(self) -> dict:
        url = self.target if self.target.startswith(("http://", "https://")) else f"https://{self.target}"
        try:
            proc = await asyncio.create_subprocess_exec(
                "whatweb", url, "--log-json", "/dev/stdout",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            data = stdout.decode().strip()
            if data:
                results = []
                for line in data.split("\n"):
                    line = line.strip()
                    if line:
                        try:
                            results.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
                if results:
                    result = results[0] if len(results) == 1 else results
                    if isinstance(result, dict) and result.get("http_status"):
                        return result
                    return {"results": results}
        except (FileNotFoundError, asyncio.TimeoutError):
            pass
        try:
            from orchestrator.scanners.whatweb_scanner import WhatwebScanner
            return await asyncio.to_thread(WhatwebScanner().scan, self.target)
        except Exception:
            return {}
