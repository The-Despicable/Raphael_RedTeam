import asyncio, json, sys, os, logging
from datetime import datetime

sys.path.insert(0, "/raphael")
sys.path.insert(0, "/app")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [SWORD] %(levelname)s %(message)s")
log = logging.getLogger("sword")

class SwordPipeline:
    def __init__(self, target: str, api_keys: dict = None, config: dict = None):
        self.target = target
        self.api_keys = api_keys or {}
        self.config = config or {}
        self.results = {"target": target, "started_at": datetime.utcnow().isoformat()}
        self.phases = {}

    async def run(self, phases: list = None):
        if phases is None:
            phases = ["recon", "scan", "exploit", "postex", "exfil", "phish"]

        phase_map = {
            "recon": self._phase_0_recon,
            "scan": self._phase_1_scan,
            "exploit": self._phase_2_exploit,
            "postex": self._phase_3_postex,
            "exfil": self._phase_4_exfil,
            "phish": self._phase_5_phish,
        }

        for phase_name in phases:
            handler = phase_map.get(phase_name)
            if not handler:
                log.warning("Unknown phase: %s, skipping", phase_name)
                continue
            log.info("=== PHASE %s ===", phase_name.upper())
            try:
                phase_result = await handler()
                self.phases[phase_name] = phase_result
                self.results[phase_name] = phase_result
                log.info("Phase %s complete: %s", phase_name, phase_result.get("summary", {}))
            except Exception as e:
                log.error("Phase %s failed: %s", phase_name, e)
                self.phases[phase_name] = {"error": str(e)}
                self.results[phase_name] = {"error": str(e)}

        self.results["phases_completed"] = list(self.phases.keys())
        self.results["finished_at"] = datetime.utcnow().isoformat()
        self.results["summary"] = self._global_summary()
        return self.results

    async def _phase_0_recon(self):
        from sword.phase_0_recon import Phase0Recon
        p = Phase0Recon(self.target, self.api_keys)
        result = await p.run()
        return result

    async def _phase_1_scan(self):
        ports = self.config.get("ports", "1-1000")
        sev = self.config.get("nuclei_severity")
        from sword.phase_1_scan import Phase1Scan
        p = Phase1Scan(self.target, ports, sev)
        return await p.run()

    async def _phase_2_exploit(self):
        url = self.config.get("url")
        ports = self.results.get("scan", {}).get("open_ports", [])
        from sword.phase_2_exploit import Phase2Exploit
        p = Phase2Exploit(self.target, url, ports)
        return await p.run()

    async def _phase_3_postex(self):
        target_ip = self.results.get("recon", {}).get("ips", [self.target])[0]
        domain = self.config.get("domain")
        username = self.config.get("username")
        password = self.config.get("password")
        hash_val = self.config.get("hash")
        network = self.config.get("network")
        from sword.phase_3_postex import Phase3PostEx
        p = Phase3PostEx(target_ip, domain, username, password, hash_val, network)
        return await p.run()

    async def _phase_4_exfil(self):
        data = self.config.get("exfil_data", json.dumps(self.results, indent=2))
        method = self.config.get("exfil_method", "dns")
        dns_domain = self.config.get("dns_domain")
        smtp_server = self.config.get("smtp_server")
        http_endpoint = self.config.get("http_endpoint")
        recipient = self.config.get("recipient")
        from sword.phase_4_exfil import Phase4Exfil
        p = Phase4Exfil(data, method, dns_domain, smtp_server, http_endpoint, recipient)
        return await p.run()

    async def _phase_5_phish(self):
        target_email = self.config.get("target_email")
        target_url = self.config.get("target_url")
        phishing_domain = self.config.get("phishing_domain")
        campaign_name = self.config.get("campaign_name", "Sword-Phish")
        from sword.phase_5_phish import Phase5Phish
        p = Phase5Phish(target_email, target_url, phishing_domain, campaign_name)
        return await p.run()

    def _global_summary(self):
        summary_parts = []
        for name, result in self.phases.items():
            s = result.get("summary", {})
            if isinstance(s, dict):
                items = [f"{k}={v}" for k, v in s.items()]
                summary_parts.append(f"{name}: {', '.join(items)}")
            else:
                summary_parts.append(f"{name}: {s}")
        return "; ".join(summary_parts)

async def run_sword(target: str, api_keys: dict = None, config: dict = None, phases: list = None):
    sword = SwordPipeline(target, api_keys, config)
    return await sword.run(phases)

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    result = asyncio.run(run_sword(target))
    print(json.dumps(result, indent=2, default=str))
