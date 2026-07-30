from __future__ import annotations
from typing import TYPE_CHECKING, Optional
if TYPE_CHECKING:
    from ..runtime.session_manager import SandboxSession

from ..proxy_guard import ProxyGuard
from ..skills_bridge import SkillsBridge
from .nmap_scanner import NmapScanner
from .nuclei_scanner import NucleiScanner
from .whatweb_scanner import WhatwebScanner


class ScanPipeline:
    def __init__(self, pg: ProxyGuard = None, sandbox: Optional[SandboxSession] = None):
        self.pg = pg
        self.sandbox = sandbox
        self.nmap = NmapScanner(pg)
        self.nuclei = NucleiScanner(pg)
        self.whatweb = WhatwebScanner(pg)
        self.skills = SkillsBridge()

    def _sandboxed_exec(self, cmd: list[str], timeout: int = 120) -> dict:
        if self.sandbox and self.sandbox.running:
            return self.sandbox.exec(cmd, timeout=timeout)
        return {"error": "no sandbox", "exit_code": -1}

    async def run(self, target: str, ports: str = "1-1000",
                  nuclei_severity: str = None,
                  use_skills: bool = True, use_sandbox: bool = False) -> dict:
        results = {
            "target": target,
            "nmap": {},
            "nuclei": {},
            "whatweb": {},
            "skills_used": [],
            "sandboxed": False,
            "summary": {"open_ports": 0, "vulnerabilities": 0, "technologies": 0},
        }

        if self.pg:
            self.pg.new_circuit(target)

        targets = [target]
        if not target.startswith(("http://", "https://")):
            targets = [f"http://{target}", f"https://{target}"]

        sandbox_active = use_sandbox and self.sandbox and self.sandbox.running
        results["sandboxed"] = sandbox_active

        if sandbox_active:
            sb_nmap = self._sandboxed_exec(["nmap", "-p", ports, target], timeout=300)
            results["nmap"] = {
                "sandbox_stdout": sb_nmap.get("stdout", "")[:3000],
                "sandbox_stderr": sb_nmap.get("stderr", "")[:1000],
            }
            sb_nuclei = self._sandboxed_exec(["nuclei", "-u", target, "-json"], timeout=300)
            results["nuclei"] = {
                "sandbox_result": sb_nuclei.get("stdout", "")[:3000],
            }
        elif use_skills:
            skill_result = self.skills.execute_skill(
                "performing-network-scanning-with-nmap", targets
            )
            if skill_result and "error" not in skill_result:
                results["nmap"] = {"skill_result": skill_result, "skill_used": "performing-network-scanning-with-nmap"}
                results["skills_used"].append("performing-network-scanning-with-nmap")
            else:
                nmap_result = self.nmap.scan_ports(target, ports=ports)
                results["nmap"] = nmap_result
        else:
            nmap_result = self.nmap.scan_ports(target, ports=ports)
            results["nmap"] = nmap_result

        if "ports" in results.get("nmap", {}):
            results["summary"]["open_ports"] = len(results["nmap"]["ports"])

        if not sandbox_active:
            for t in targets:
                try:
                    ww = self.whatweb.scan(t, aggression=1)
                    if ww.get("tech_count", 0) > 0:
                        results["whatweb"] = ww
                        results["summary"]["technologies"] = ww["tech_count"]
                        break
                except Exception:
                    continue
            if not results["whatweb"]:
                try:
                    results["whatweb"] = self.whatweb.scan(target, aggression=1)
                    results["summary"]["technologies"] = results["whatweb"].get("tech_count", 0)
                except Exception:
                    results["whatweb"] = {"error": "all scan attempts failed"}

        if not sandbox_active:
            nu = await self.nuclei.scan(target, severity=nuclei_severity)
            results["nuclei"] = nu
            if "findings" in nu:
                results["summary"]["vulnerabilities"] = nu["findings_count"]

        results["summary"]["skills_available"] = len(results["skills_used"])

        return results
