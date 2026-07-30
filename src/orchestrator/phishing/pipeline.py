from __future__ import annotations
from typing import TYPE_CHECKING, Optional
if TYPE_CHECKING:
    from ..runtime.session_manager import SandboxSession

from ..skills_bridge import SkillsBridge
from .gophish import GoPhishAPI
from .evilginx import EvilGinx
from .set_wrapper import SETWrapper


class PhishingPipeline:
    def __init__(self, pg=None, sandbox: Optional[SandboxSession] = None):
        self.pg = pg
        self.sandbox = sandbox
        self.gophish = GoPhishAPI()
        self.evilginx = EvilGinx()
        self.set = SETWrapper()
        self.skills = SkillsBridge()

    def _sandboxed_exec(self, cmd: list[str], timeout: int = 120) -> dict:
        if self.sandbox and self.sandbox.running:
            return self.sandbox.exec(cmd, timeout=timeout)
        return {"error": "no sandbox", "exit_code": -1}

    def run(self, method: str = "gophish", target_email: str = None, target_url: str = None,
            phishing_domain: str = None, campaign_name: str = "Raphael-Phish",
            template_subject: str = "Security Notice", template_body: str = None,
            smtp_server: str = None, sender_email: str = None,
            lhost: str = None, lport: int = 443,
            use_skills: bool = True, use_sandbox: bool = False) -> dict:
        result = {"method": method, "components": {}, "skills_used": [], "sandboxed": False}
        sandbox_active = use_sandbox and self.sandbox and self.sandbox.running
        result["sandboxed"] = sandbox_active

        if use_skills and not sandbox_active:
            skill_result = self.skills.execute_skill(
                "executing-phishing-simulation-campaign",
                [target_email or "target@example.com", phishing_domain or "http://localhost"],
            )
            if skill_result and "error" not in skill_result:
                result["components"]["skill_phishing"] = skill_result
                result["skills_used"].append("executing-phishing-simulation-campaign")

        if sandbox_active:
            if method == "evilginx" or method == "all":
                if phishing_domain:
                    sb = self._sandboxed_exec([
                        "python3", "-c",
                        f"import socket; s=socket.socket(); s.settimeout(5); "
                        f"s.connect(('{phishing_domain}', 443) if '{phishing_domain}'.count(':')==0 else "
                        f"('{phishing_domain.split(':')[0]}', int('{phishing_domain.split(':')[1]}' if ':' in '{phishing_domain}' else 443))); "
                        f"print('reachable'); s.close()"
                    ], timeout=30)
                    result["components"]["evilginx_sandbox"] = {
                        "domain_check": sb.get("stdout", ""),
                        "sandboxed": True,
                    }
            if method == "set" or method == "all":
                sb_set = self._sandboxed_exec([
                    "python3", "-c",
                    "print('SET container check: ok')"
                ], timeout=10)
                result["components"]["set_sandbox"] = {
                    "sandbox_check": sb_set.get("stdout", ""),
                    "sandboxed": True,
                }
            result["summary"] = {
                "phishing_domain": phishing_domain,
                "target_email": target_email,
                "sandboxed": True,
            }
        else:
            if method == "gophish" or method == "all":
                status = self.gophish.status()
                if not status.get("available"):
                    result["components"]["gophish"] = self.gophish.create_campaign(
                        name=campaign_name,
                        target_group=[target_email] if target_email else [],
                        template={"subject": template_subject, "body": template_body or "Click here"},
                        url=phishing_domain or "http://localhost",
                    )
                else:
                    result["components"]["gophish"] = {
                        "status": "ready",
                        "api_connected": True,
                    }

            if method == "evilginx" or method == "all":
                if target_url and phishing_domain:
                    result["components"]["evilginx"] = self.evilginx.deploy_proxy(
                        domain=phishing_domain,
                        phishing_url=phishing_domain,
                        target_url=target_url,
                    )
                else:
                    result["components"]["evilginx"] = self.evilginx.status()

            if method == "set" or method == "all":
                if target_url:
                    result["components"]["set"] = self.set.credential_harvester(
                        site=target_url,
                        email=target_email or "target@example.com",
                        password="not_a_real_password",
                    )
                else:
                    result["components"]["set"] = self.set.status()

            result["summary"] = {
                "gophish_available": self.gophish._available,
                "evilginx_available": self.evilginx._available,
                "set_available": self.set._available,
                "phishing_domain": phishing_domain,
                "target_email": target_email,
            }
        return result
