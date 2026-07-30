import re

from orchestrator.kali_tools_client import kali


class GobusterWrapper:
    def __init__(self, wordlist: str = "/usr/share/wordlists/dirb/common.txt"):
        self._wordlist = wordlist

    async def dirs(self, url: str, extensions: str = "php,txt,zip,html,asp,aspx",
                   timeout: int = 120) -> dict:
        args = f"dir -u {url} -w {self._wordlist} -x {extensions} -q -t 10"
        result = await kali.run("gobuster", args, timeout=timeout)
        stdout = (result.get("stdout") or "") + (result.get("stderr") or "")
        paths = re.findall(r'^/(\S+)', stdout, re.MULTILINE)
        return {
            "success": True,
            "paths": paths,
            "count": len(paths),
            "raw": stdout[:3000],
        }

    async def dns(self, domain: str, timeout: int = 120) -> dict:
        args = f"dns -d {domain} -w {self._wordlist} -q -t 10"
        result = await kali.run("gobuster", args, timeout=timeout)
        stdout = (result.get("stdout") or "") + (result.get("stderr") or "")
        subdomains = re.findall(r'Found:\s*(\S+)', stdout)
        return {
            "success": True,
            "subdomains": subdomains,
            "count": len(subdomains),
            "raw": stdout[:3000],
        }

    async def vhost(self, url: str, domain: str, timeout: int = 120) -> dict:
        args = f"vhost -u {url} -w {self._wordlist} --domain {domain} -q -t 10"
        result = await kali.run("gobuster", args, timeout=timeout)
        stdout = (result.get("stdout") or "") + (result.get("stderr") or "")
        vhosts = re.findall(r'Found:\s*(\S+)', stdout)
        return {
            "success": True,
            "vhosts": vhosts,
            "count": len(vhosts),
            "raw": stdout[:3000],
        }
