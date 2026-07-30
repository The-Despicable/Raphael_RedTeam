import re
import shlex

from orchestrator.kali_tools_client import kali


class NiktoWrapper:
    async def scan(self, url: str, timeout: int = 300) -> dict:
        result = await kali.run("nikto", f"-h {shlex.quote(url)} -nointeractive -q", timeout=timeout)
        stdout = (result.get("stdout") or "") + (result.get("stderr") or "")
        vulns = re.findall(r'\+ (.+)', stdout)
        return {"success": len(vulns) > 0, "vulnerabilities": vulns, "count": len(vulns), "raw": stdout[:5000]}


class WfuzzWrapper:
    async def fuzz(self, url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt",
                   timeout: int = 120) -> dict:
        result = await kali.run("wfuzz", f"-w {shlex.quote(wordlist)} --hc 404 {shlex.quote(url)}", timeout=timeout)
        stdout = (result.get("stdout") or "") + (result.get("stderr") or "")
        findings = re.findall(r'(\S+)\s+(\d+)\s+(\d+)', stdout)
        return {"success": len(findings) > 0, "findings": findings[:50], "count": len(findings), "raw": stdout[:3000]}


class JohnWrapper:
    async def crack(self, hash_file: str, format: str = "nt",
                    wordlist: str = "/usr/share/wordlists/rockyou.txt.gz",
                    timeout: int = 600) -> dict:
        args = f"--format={format} --wordlist={wordlist} {hash_file}"
        result = await kali.run("john", args, timeout=timeout)
        stdout = (result.get("stdout") or "") + (result.get("stderr") or "")
        cracked = re.findall(r'(\S+):(\S+)', stdout)
        return {"success": len(cracked) > 0, "cracked": [{"hash": h, "plaintext": p} for h, p in cracked],
                "count": len(cracked), "raw": stdout[:3000]}

    async def crack_hash(self, hash_str: str, format: str = "nt",
                         wordlist: str = "/usr/share/wordlists/rockyou.txt.gz",
                         timeout: int = 600) -> dict:
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".hash", delete=False) as f:
            f.write(hash_str)
            fpath = f.name
        result = await self.crack(fpath, format=format, wordlist=wordlist, timeout=timeout)
        return result


class KerberoastWrapper:
    async def roast(self, target: str, username: str, password: str,
                    domain: str = "", timeout: int = 120) -> dict:
        args = f"-spn"
        if domain:
            args += f" -d {shlex.quote(domain)}"
        args += f" -u {shlex.quote(username)} -p {shlex.quote(password)}"
        args += f" -dc-ip {shlex.quote(target)}"
        result = await kali.run("kerberoast", args, timeout=timeout)
        stdout = (result.get("stdout") or "") + (result.get("stderr") or "")
        hashes = re.findall(r'\$krb5tgs\$[^\s]+', stdout)
        return {"success": len(hashes) > 0, "hashes": hashes, "count": len(hashes), "raw": stdout[:3000]}
