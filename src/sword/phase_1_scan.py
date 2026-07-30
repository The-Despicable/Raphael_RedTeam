import sys
import httpx
from typing import Optional, List, Dict, Any

sys.path.insert(0, "/raphael")

from orchestrator.scanners.nmap_scanner import NmapScanner
from orchestrator.scanners.nuclei_scanner import NucleiScanner
from orchestrator.scanners.whatweb_scanner import WhatwebScanner


WAF_SIGNATURES = {
    "Cloudflare": ["cf-ray", "__cfduid"],
    "AWS WAF": ["x-amzn-RequestId", "x-amzn-ErrorType"],
    "ModSecurity": ["ModSecurity", "NOYB"],
    "Akamai": ["akamai", "x-akamai-transformed"],
    "F5 BIG-IP": ["BigIP", "F5"],
    "Sucuri": ["Sucuri", "x-sucuri"],
    "Barracuda": ["barracuda"],
    "Imperva": ["Incapsula", "X-Iinfo"],
}


class Phase1Scan:
    def __init__(self, target: str, ports: str = "1-1000", nuclei_severity: str = None):
        self.target = target
        self.ports = ports
        self.nuclei_severity = nuclei_severity
        self.nmap = NmapScanner()
        self.nuclei = NucleiScanner()
        self.whatweb = WhatwebScanner()

    async def run(self) -> dict:
        port_data = self._port_scan()
        open_ports = [p["port"] for p in port_data.get("ports", [])]
        services = [
            {"port": p["port"], "service": p.get("service", "unknown"), "state": "open"}
            for p in port_data.get("ports", [])
        ]
        vulns = self._vuln_scan(open_ports)
        fingerprint = self._fingerprint()
        waf = await self._detect_waf()
        summary = self._summarize(open_ports, vulns, fingerprint, waf)
        return {
            "target": self.target,
            "open_ports": open_ports,
            "services": services,
            "vulnerabilities": vulns,
            "tech_stack": fingerprint.get("technologies", {}),
            "waf": waf,
            "summary": summary,
        }

    def _port_scan(self) -> dict:
        try:
            return self.nmap.scan_ports(self.target, ports=self.ports)
        except Exception as e:
            return {"error": str(e), "ports": [], "port_count": 0, "target": self.target}

    def _vuln_scan(self, open_ports: List[int]) -> dict:
        if not open_ports:
            return {"findings": [], "findings_count": 0, "target": self.target}
        try:
            return self.nuclei.scan(self.target, severity=self.nuclei_severity)
        except Exception as e:
            return {"error": str(e), "findings": [], "findings_count": 0, "target": self.target}

    def _fingerprint(self) -> dict:
        try:
            return self.whatweb.scan(self.target)
        except Exception as e:
            return {"error": str(e), "technologies": {}, "tech_count": 0, "target": self.target}

    async def _detect_waf(self) -> dict:
        for scheme in ("https", "http"):
            url = f"{scheme}://{self.target}"
            try:
                async with httpx.AsyncClient(verify=False, timeout=10) as client:
                    r = await client.get(
                        url,
                        headers={
                            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0 Safari/537.36"
                        },
                    )
                    for waf_name, sigs in WAF_SIGNATURES.items():
                        for sig in sigs:
                            if (
                                sig.lower() in str(r.headers).lower()
                                or sig.lower() in r.text[:5000].lower()
                            ):
                                return {"detected": True, "wafs": {waf_name: f"matched: {sig}"}}
                    return {"detected": False, "wafs": {}}
            except Exception:
                continue
        return {"detected": False, "wafs": {}}

    def _summarize(self, open_ports: List[int], vulns: dict, fingerprint: dict, waf: dict) -> str:
        parts = [
            f"Open ports: {len(open_ports)}",
            f"Vulnerabilities: {vulns.get('findings_count', 0)}",
            f"Technologies: {fingerprint.get('tech_count', 0)}",
            f"WAF: {'Yes' if waf.get('detected') else 'No'}",
        ]
        return " | ".join(parts)
