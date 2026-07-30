import re
import shlex

from orchestrator.kali_tools_client import kali


class Enum4linuxWrapper:
    async def enum(self, target: str, timeout: int = 120) -> dict:
        args = f"-a {shlex.quote(target)} 2>/dev/null"
        result = await kali.run("enum4linux", args, timeout=timeout)
        stdout = (result.get("stdout") or "") + (result.get("stderr") or "")
        users = re.findall(r'user:\[(\S+)\]', stdout)
        shares = re.findall(r'//\S+/(\S+)', stdout)
        os_info = re.search(r'OS info[:\s]+(.+)', stdout)
        return {
            "success": bool(users or shares),
            "users": list(set(users)),
            "shares": list(set(shares)),
            "os_info": os_info.group(1).strip() if os_info else "",
            "raw": stdout[:3000],
        }


class SmbmapWrapper:
    async def scan(self, target: str, username: str = "", password: str = "",
                   timeout: int = 120) -> dict:
        args = f"-H {shlex.quote(target)}"
        if username:
            args += f" -u {shlex.quote(username)}"
        if password:
            args += f" -p {shlex.quote(password)}"
        args += " 2>/dev/null"
        result = await kali.run("smbmap", args, timeout=timeout)
        stdout = (result.get("stdout") or "") + (result.get("stderr") or "")
        shares = re.findall(r'(\S+)\s+', stdout)
        writable = re.findall(r'(\S+)\s+.*WRITE', stdout, re.IGNORECASE)
        return {
            "success": True,
            "shares": list(set(shares)),
            "writable": list(set(writable)),
            "raw": stdout[:3000],
        }
