import re
import shlex

from orchestrator.kali_tools_client import kali


class DNSWrapper:
    async def zone_transfer(self, domain: str, nameserver: str = "", timeout: int = 60) -> dict:
        ns_arg = f"@{shlex.quote(nameserver)}" if nameserver else ""
        result = await kali.run("dig", f"axfr {shlex.quote(domain)} {ns_arg}", timeout=timeout)
        stdout = (result.get("stdout") or "") + (result.get("stderr") or "")
        records = [l.strip() for l in stdout.split("\n") if l.strip() and not l.startswith(";") and "IN" in l]
        return {"success": len(records) > 0, "records": records[:50], "count": len(records), "raw": stdout[:3000]}

    async def srv_records(self, domain: str, timeout: int = 60) -> dict:
        types = ["_ldap._tcp", "_kerberos._tcp", "_kerberos._udp", "_gc._tcp", "_kpasswd._tcp"]
        all_records = []
        for t in types:
            result = await kali.run("dig", f"{shlex.quote(t)}.{shlex.quote(domain)} SRV", timeout=timeout)
            stdout = (result.get("stdout") or "") + (result.get("stderr") or "")
            for line in stdout.split("\n"):
                if "SRV" in line and "IN" in line:
                    parts = line.strip().split()
                    if len(parts) >= 5:
                        all_records.append(f"{t}: {parts[-1]} (port {parts[-2].split('.')[0] if '.' not in parts[-2] else parts[-2]})")
        return {"success": len(all_records) > 0, "records": all_records, "count": len(all_records)}

    async def ns_lookup(self, domain: str, timeout: int = 60) -> dict:
        result = await kali.run("nslookup", f"-type=any {shlex.quote(domain)}", timeout=timeout)
        stdout = (result.get("stdout") or "") + (result.get("stderr") or "")
        lines = [l.strip() for l in stdout.split("\n") if l.strip()]
        return {"success": True, "lines": lines[:30], "raw": stdout[:3000]}


class WhoIsWrapper:
    async def lookup(self, domain: str, timeout: int = 60) -> dict:
        result = await kali.run("whois", shlex.quote(domain), timeout=timeout)
        stdout = (result.get("stdout") or "") + (result.get("stderr") or "")
        lines = [l.strip() for l in stdout.split("\n") if l.strip() and not l.startswith("#")]
        registrant = [l for l in lines if "Registrant" in l or "OrgName" in l or "org-name" in l]
        nameservers = [l.split(":")[1].strip() for l in lines if "Name Server" in l]
        return {
            "success": True,
            "registrant": registrant[:5],
            "nameservers": nameservers,
            "lines": lines[:50],
            "raw": stdout[:3000],
        }


class LdapDomainDumpWrapper:
    async def dump(self, target: str, username: str = "", password: str = "",
                   domain: str = "", timeout: int = 120) -> dict:
        args = f"-u {shlex.quote(domain)}\\{shlex.quote(username)}" if domain and username else f"-u {shlex.quote(username)}" if username else ""
        if password:
            args += f" -p {shlex.quote(password)}"
        args += f" {shlex.quote(target)}"
        result = await kali.run("ldapdomaindump", args, timeout=timeout)
        stdout = (result.get("stdout") or "") + (result.get("stderr") or "")
        files = re.findall(r'(domain_users\.json|domain_computers\.json|domain_groups\.json|domain_trusts\.json)', stdout)
        return {"success": len(files) > 0, "files": files, "raw": stdout[:3000]}
