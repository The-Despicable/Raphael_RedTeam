"""Executor — runs one technique, parses result, updates models."""
from __future__ import annotations
import asyncio
import json
import time
import logging
import re
from typing import Optional, Callable

from raphael.models.target_model import ConstraintDelta, TargetModel, FailureRecord, DomainState
from raphael.models.capability_model import CapabilityModel
from raphael.models.engagement_state import EngagementState
from raphael.techniques import get_technique, TECHNIQUE_REGISTRY
from raphael.executor.kali_bridge import KaliBridge
from raphael.circulatory.event_bus import EventBus
from raphael.circulatory.blackboard import Blackboard
from raphael.cerebellum.error_diagnoser import get_diagnoser, Diagnosis
from raphael.models.target_model import FailureRecord
from raphael.cognitive.protocol_inference import ProtocolInferenceEngine
from raphael.cognitive.ontology_expander import OntologyExpander

logger = logging.getLogger("raphael.executor")

# Parser registry — maps parser names to functions
PARSER_REGISTRY: dict[str, Callable[[str, str], ConstraintDelta]] = {}

def register_parser(name: str, fn: Callable[[str, str], ConstraintDelta]):
    PARSER_REGISTRY[name] = fn


class Executor:
    """
    Runs techniques via the Kali tools bridge, parses results into
    ConstraintDeltas, updates the target model, and publishes events.
    """

    def __init__(self, event_bus: EventBus, blackboard: Blackboard,
                 kali_bridge: Optional[KaliBridge] = None,
                 tool_runner: Optional[Callable] = None):
        self._event_bus = event_bus
        self._blackboard = blackboard
        self._kali_bridge = kali_bridge or KaliBridge()
        self._tool_runner = tool_runner or self._subprocess_fallback
        self._paused = False
        self._pause_reason: Optional[str] = None
        self._current_task: Optional[asyncio.Task] = None
        self._protocol_inference = ProtocolInferenceEngine(None)  # No target_model needed for static methods

    @property
    def paused(self) -> bool:
        return self._paused

    @property
    def pause_reason(self) -> Optional[str]:
        return self._pause_reason

    def pause(self, reason: str):
        self._paused = True
        self._pause_reason = reason
        logger.warning(f"Executor paused: {reason}")

    def resume(self):
        self._paused = False
        self._pause_reason = None
        logger.info("Executor resumed")

    async def _subprocess_fallback(self, tool: str, args: str, timeout: int) -> dict:
        """Run a tool via subprocess (fallback when no API available)."""
        import shlex, asyncio
        cmd = f"{tool} {args}"
        try:
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
            return {
                "returncode": proc.returncode,
                "stdout": stdout.decode(errors="replace"),
                "stderr": stderr.decode(errors="replace"),
            }
        except asyncio.TimeoutError:
            return {"error": "timeout", "returncode": -1, "stdout": "", "stderr": ""}
        except Exception as e:
            return {"error": str(e), "returncode": -1, "stdout": "", "stderr": ""}

    async def execute(self, state: EngagementState,
                       technique_name: str) -> tuple[ConstraintDelta, bool]:
        """Execute a technique by name, return the ConstraintDelta."""
        if self._paused:
            logger.warning(f"Executor paused ({self._pause_reason}), skipping {technique_name}")
            return ConstraintDelta.empty(), False

        technique = get_technique(technique_name)
        if not technique:
            logger.error(f"Unknown technique: {technique_name}")
            return ConstraintDelta.empty(), False

        logger.info(f"Executing: {technique.name} on {state.target_address}")
        start = time.time()

        # Build dynamic port list from discovered affordances
        ports = None
        for aff in state.target.domains.get("network", DomainState()).affordances:
            if aff.startswith("port_list:"):
                ports = aff.split(":", 1)[1]
                break
        if ports is None:
            port_nums = []
            for aff in state.target.domains.get("network", DomainState()).affordances:
                if aff.startswith("port_") and aff.endswith("_open"):
                    p = aff.split("_")[1]
                    if p.isdigit():
                        port_nums.append(p)
            if port_nums:
                ports = ",".join(port_nums)

        args = technique.tool_args_template.format(
            target=state.target_address,
            ports=ports or "80,443,22,445,139,3389,8080,8443"
        )

        # Run
        result = await self._kali_bridge.run(technique.tool, args, technique.timeout)
        latency = (time.time() - start) * 1000

        # Parse
        parser_fn = PARSER_REGISTRY.get(technique.parser, parse_raw)
        delta = parser_fn(result.get("stdout", ""), state.target_address)

        # Add technique's declared affordances (e.g., vhosts_discovered from vhost_enum)
        if technique.provides_affordances:
            delta.new_affordances.update(technique.provides_affordances)

        # Check for failure
        success = result.get("returncode", -1) == 0 or not delta.is_empty()
        diagnosis = None
        if not success:
            diagnoser = get_diagnoser()
            diagnosis = diagnoser.diagnose(
                technique_name,
                result.get("returncode", -1),
                result.get("stdout", ""),
                result.get("stderr", ""),
            )

        # Update target model
        produced_new = state.target.absorb(delta, state.current_cycle)

        # OntologyExpander — mint ephemeral affordances from blind_probe
        if technique and technique.name == "blind_probe":
            try:
                stdout = result.get("stdout", "")
                oe_delta = OntologyExpander.mint_affordances(stdout, state.target.domains.get("network"))
                if not oe_delta.is_empty():
                    logger.info(f"OntologyExpander: minted {len(oe_delta.new_affordances)} ephemeral affordances")
                    state.target.absorb(oe_delta, state.current_cycle)
            except Exception as e:
                logger.debug(f"OntologyExpander failed: {e}")

        # Protocol inference: enrich with inferred affordances from discovered services/ports
        self._run_protocol_inference(state, delta, technique_name)

        # Failed technique tracking
        if diagnosis:
            state.target.failed_techniques[technique_name] = FailureRecord(
                cycle=state.current_cycle,
                reason_class=diagnosis.failure_class,
                is_permanent=diagnosis.is_permanent,
            )
            # If diagnosis suggests a blocker, add it as a constraint
            if diagnosis.suggests_blocker:
                domain = state.target.domains.get("network")
                if domain:
                    domain.constraints.add(diagnosis.suggests_blocker)

        # Log to blackboard
        await self._blackboard.write_execution_log(
            state.engagement_id, state.current_cycle,
            technique_name, success, diagnosis.failure_class if diagnosis else None,
            f"delta: {len(delta.new_affordances)} affordances, {len(delta.new_constraints)} constraints",
            latency
        )

        # Publish events
        if success:
            await self._event_bus.publish("technique_succeeded", {
                "technique": technique_name, "cycle": state.current_cycle,
                "delta": delta.to_dict(), "latency_ms": latency
            })
            if delta.new_affordances:
                await self._event_bus.publish("new_affordance", {
                    "affordances": list(delta.new_affordances),
                    "domain": delta.domain
                })
        else:
            await self._event_bus.publish("technique_failed", {
                "technique": technique_name, "cycle": state.current_cycle,
                "failure_class": diagnosis.failure_class if diagnosis else "unknown"
            })

        logger.info(f"  Result: {'SUCCESS' if success else 'FAIL'} "
                     f"({latency:.0f}ms) "
                     f"affordances={delta.new_affordances} "
                     f"constraints={delta.new_constraints}")
        return delta, produced_new


# ---------------------------------------------------------------------------
    def _run_protocol_inference(self, state: EngagementState, delta: ConstraintDelta, technique_name: str):
        """Run protocol inference on discovered ports/services to add inferred affordances."""
        network_domain = state.target.domains.get("network")
        if not network_domain:
            return

        # Extract port and service info from delta affordances
        ports_to_infer = set()
        service_banner_map = {}  # port -> (service, version, banner)

        for aff in delta.new_affordances:
            # port_8080_open -> port 8080
            if aff.startswith("port_") and aff.endswith("_open"):
                try:
                    port = int(aff.split("_")[1])
                    ports_to_infer.add(port)
                except (IndexError, ValueError):
                    pass
            # service_nginx_detected -> service nginx
            elif aff.startswith("service_") and aff.endswith("_detected"):
                service_name = aff[8:-9]  # remove "service_" and "_detected"
                # We don't know the port from this alone, but we can infer
                # If we also have version_X_Y, use that
                ports_to_infer.add(0)  # special marker for service-only
                service_banner_map[0] = (service_name, "", "")

        # Also check evidence for banner info
        evidence = delta.evidence
        for port in ports_to_infer:
            if port == 0:
                # Service-only inference
                for svc_port, (svc, ver, ban) in service_banner_map.items():
                    if svc:
                        ProtocolInferenceEngine.infer_affordances_for_domain_state(
                            network_domain, port, banner=ban, service=svc, version=ver
                        )
            else:
                # Port-based inference with any service info we can extract
                service = ""
                version = ""
                banner = ""
                # Try to extract service from evidence
                for line in evidence.split('\n'):
                    if f"{port}/" in line or f"{port} " in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            service = parts[2] if len(parts) > 2 else ""
                            version = " ".join(parts[3:]) if len(parts) > 3 else ""
                            banner = line
                            break
                
                ProtocolInferenceEngine.infer_affordances_for_domain_state(
                    network_domain, port, banner=banner, service=service, version=version
                )

# Parsers — convert raw tool output to ConstraintDelta
# ---------------------------------------------------------------------------

def parse_raw(stdout: str, target: str) -> ConstraintDelta:
    """Default parser — just stores raw output."""
    if not stdout.strip():
        return ConstraintDelta.empty()
    return ConstraintDelta(
        new_affordances={"raw_output_available"},
        evidence=stdout[:1000],
    )

def parse_nmap_port_list(stdout: str, target: str) -> ConstraintDelta:
    """Parse nmap -p- output for open ports."""
    affordances = set()
    constraints = set()
    unknowns = set()
    open_ports = []

    for line in stdout.splitlines():
        if "/tcp" in line or "/udp" in line:
            parts = line.split()
            if len(parts) >= 2:
                port_str = parts[0]
                state = parts[1]
                if state == "open":
                    open_ports.append(port_str)
                    affordances.add(f"port_{port_str.split('/')[0]}_open")
                elif state == "filtered":
                    constraints.add("ports_filtered")

    if open_ports:
        affordances.add("open_ports")
        affordances.add(f"port_list:{','.join(open_ports)}")
        # Generate service-specific affordances
        for p in open_ports:
            port_num = p.split("/")[0]
            if port_num == "80":
                affordances.add("port_80_open")
                affordances.add("http_service")
            elif port_num == "443":
                affordances.add("port_443_open")
                affordances.add("https_service")
                affordances.add("http_service")
            elif port_num == "22":
                affordances.add("port_22_open")
                affordances.add("ssh_service")
            elif port_num == "445":
                affordances.add("port_445_open")
                affordances.add("smb_service")
            elif port_num == "139":
                affordances.add("port_139_open")
                affordances.add("netbios_service")
            elif port_num == "3389":
                affordances.add("port_3389_open")
                affordances.add("rdp_service")
            elif port_num == "8080":
                affordances.add("port_8080_open")
                affordances.add("http_service")
            elif port_num == "8443":
                affordances.add("port_8443_open")
                affordances.add("https_service")
                affordances.add("http_service")
    else:
        constraints.add("no_open_ports")
        unknowns.add("ports_blocked_by_firewall")

    evidence = "\n".join(stdout.splitlines()[:30])
    return ConstraintDelta(
        new_affordances=affordances,
        new_constraints=constraints,
        resolved_unknowns={"open_ports_unknown"},
        new_unknowns=unknowns,
        evidence=evidence,
    )

def parse_nmap_service_version(stdout: str, target: str) -> ConstraintDelta:
    """Parse nmap -sV output for service versions."""
    affordances = set()
    constraints = set()
    services_found = []

    for line in stdout.splitlines():
        if "/tcp" in line:
            parts = line.split()
            if len(parts) >= 4 and parts[1] == "open":
                port = parts[0].split("/")[0]
                service = parts[2]
                version = " ".join(parts[3:]) if len(parts) > 3 else ""
                services_found.append(f"{port}/{service} {version}")
                affordances.add(f"service_{service}_detected")
                affordances.add(f"version_{service}_{version[:30]}")

    if services_found:
        affordances.add("service_versions")

    # OS detection
    for line in stdout.splitlines():
        if "OS details:" in line or "Aggressive OS guesses:" in line:
            affordances.add("os_detected")
            affordances.add(f"os_hint:{line.strip()}")

    if not services_found:
        constraints.add("no_detectable_services")
        # Remove empty affordances that might not have been set
        affordances.discard("service_versions")

    evidence = "\n".join(stdout.splitlines()[:30])
    return ConstraintDelta(
        new_affordances=affordances,
        new_constraints=constraints,
        resolved_unknowns={"service_versions_unknown"},
        evidence=evidence,
    )

def parse_dns_raw(stdout: str, target: str) -> ConstraintDelta:
    """Parse dig output. Adds constraint if target is IP with no DNS records."""
    import re
    affordances = set()
    constraints = set()
    for line in stdout.splitlines():
        line = line.strip()
        if line:
            affordances.add(f"dns_record:{line[:100]}")
    if stdout.strip():
        affordances.add("dns_records_resolved")
    else:
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', target):
            constraints.add("no_dns_for_ip_target")
        else:
            constraints.add("dns_lookup_returned_nothing")
    return ConstraintDelta(
        new_affordances=affordances,
        new_constraints=constraints,
        resolved_unknowns={"dns_records_unknown"},
        evidence=stdout[:1000],
    )

def parse_smb_share_list(stdout: str, target: str) -> ConstraintDelta:
    """Parse smbclient -L output."""
    affordances = set()
    for line in stdout.splitlines():
        if line.startswith("	") and not line.startswith("		"):
            share = line.strip().split()[0] if line.strip() else ""
            if share:
                affordances.add(f"smb_share:{share}")
    if stdout.strip():
        affordances.add("smb_null_session_works")
        affordances.add("smb_enumerated")
    return ConstraintDelta(
        new_affordances=affordances,
        resolved_unknowns={"smb_null_session_unknown"},
        evidence=stdout[:1000],
    )

def parse_gobuster_raw(stdout: str, target: str) -> ConstraintDelta:
    """Parse gobuster output."""
    affordances = set()
    for line in stdout.splitlines():
        if line.startswith("/"):
            path = line.split()[0] if line.split() else line
            affordances.add(f"discovered_path:{path}")
    if stdout.strip():
        affordances.add("discovered_paths")
    return ConstraintDelta(
        new_affordances=affordances,
        evidence=stdout[:1000],
    )

def parse_sqlmap_result(stdout: str, target: str) -> ConstraintDelta:
    """Parse sqlmap output for vulnerable parameters."""
    affordances = set()
    if "Parameter:" in stdout and "GET" or "POST" in stdout:
        affordances.add("sqli_vulnerable")
    if "Database:" in stdout:
        affordances.add("sqli_confirmed")
        affordances.add("dbms_identified")
    return ConstraintDelta(
        new_affordances=affordances,
        evidence=stdout[:1000],
    )


# ===== WAVE 2 PARSERS =====

def parse_waf_detect(stdout: str, target: str) -> ConstraintDelta:
    """Parse wafw00f output."""
    affordances = set()
    constraints = set()
    for line in stdout.splitlines():
        if "WAF" in line and "detected" in line.lower():
            waf_type = line.strip()
            affordances.add(f"waf_type:{waf_type[:60]}")
    if stdout.strip() and not affordances:
        constraints.add("no_waf_detected")
    elif affordances:
        affordances.add("waf_detected")
    return ConstraintDelta(
        new_affordances=affordances,
        new_constraints=constraints,
        resolved_unknowns={"waf_unknown"},
        evidence=stdout[:1000],
    )

def parse_tech_fingerprint(stdout: str, target: str) -> ConstraintDelta:
    """Parse whatweb output."""
    affordances = set()
    constraints = set()
    import re
    # whatweb outputs JSON with --log-json
    for line in stdout.splitlines():
        m = re.search(r'\{.*\}', line)
        if m:
            try:
                import json
                data = json.loads(m.group())
                for plugin in data.get('plugins', {}):
                    affordances.add(f"tech:{plugin.lower()}")
                    affordances.add("tech_stack")
            except (json.JSONDecodeError, AttributeError):
                pass
        # Plain text format
        if '[' in line and ']' in line:
            parts = line.split('[')
            for p in parts[1:]:
                tech = p.split(']')[0].strip()
                if tech:
                    affordances.add(f"tech:{tech.lower()}")
                    affordances.add("tech_stack")
    if not affordances:
        constraints.add("no_tech_detected")
    return ConstraintDelta(
        new_affordances=affordances,
        new_constraints=constraints,
        resolved_unknowns={"tech_stack_unknown"},
        evidence=stdout[:1000],
    )

def parse_subdomain_list(stdout: str, target: str) -> ConstraintDelta:
    """Parse subfinder output."""
    affordances = set()
    for line in stdout.splitlines():
        sub = line.strip()
        if sub:
            affordances.add(f"subdomain:{sub}")
    if affordances:
        affordances.add("subdomains")
    return ConstraintDelta(
        new_affordances=affordances,
        resolved_unknowns={"subdomains_unknown"},
        evidence=stdout[:1000],
    )

def parse_whois_raw(stdout: str, target: str) -> ConstraintDelta:
    """Parse whois output."""
    import re
    affordances = set()
    org = re.search(r'OrgName:\s*(.*)', stdout)
    if org:
        affordances.add(f"whois_org:{org.group(1).strip()[:60]}")
    registrar = re.search(r'Registrar:\s*(.*)', stdout)
    if registrar:
        affordances.add(f"whois_registrar:{registrar.group(1).strip()[:60]}")
    abuse = re.search(r'Abuse Contact:\s*(.*)', stdout)
    if abuse:
        affordances.add(f"whois_abuse:{abuse.group(1).strip()[:60]}")
    if any(k in stdout.lower() for k in ['orgname', 'registrar', 'abuse']):
        affordances.add("whois_available")
    return ConstraintDelta(
        new_affordances=affordances,
        evidence=stdout[:1000],
    )

def parse_ldap_root_dse(stdout: str, target: str) -> ConstraintDelta:
    """Parse ldapsearch root DSE output."""
    affordances = set()
    constraints = set()
    for line in stdout.splitlines():
        if ':' in line:
            key, val = line.split(':', 1)
            key = key.strip().lower()
            val = val.strip()
            if key.startswith('namingcontexts') or key.startswith('defaultnamingcontext'):
                affordances.add(f"ldap_naming_context:{val}")
                affordances.add("ldap_naming_contexts")
            if key == 'rootdomainnamingcontext':
                affordances.add(f"ldap_domain:{val}")
                affordances.add("ldap_domain_found")
            if key == 'dnsroot':
                affordances.add(f"ldap_dns_root:{val}")
    if "ldap_naming_contexts" in affordances:
        affordances.add("ldap_anonymous_bind_works")
    elif "refused" in stdout.lower() or "error" in stdout.lower():
        constraints.add("ldap_anonymous_bind_blocked")
    return ConstraintDelta(
        new_affordances=affordances,
        new_constraints=constraints,
        resolved_unknowns={"ldap_anonymous_bind_unknown"},
        evidence=stdout[:1000],
    )

def parse_snmp_raw(stdout: str, target: str) -> ConstraintDelta:
    """Parse snmpwalk output."""
    affordances = set()
    constraints = set()
    lines = [l for l in stdout.splitlines() if l.strip() and 'timeout' not in l.lower()]
    if lines:
        affordances.add("snmp_public_string")
        affordances.add("snmp_sysinfo")
        for line in lines[:5]:
            affordances.add(f"snmp_data:{line.strip()[:80]}")
    else:
        constraints.add("snmp_community_blocked")
    return ConstraintDelta(
        new_affordances=affordances,
        new_constraints=constraints,
        resolved_unknowns={"snmp_unknown"},
        evidence=stdout[:1000],
    )

def parse_rpc_enum_users(stdout: str, target: str) -> ConstraintDelta:
    """Parse rpcclient enumdomusers output."""
    affordances = set()
    constraints = set()
    import re
    users = re.findall(r'\[.*?\]\s+(\w+)', stdout)
    for user in users:
        if user and user != 'found':
            affordances.add(f"smb_user:{user}")
    if users:
        affordances.add("smb_users")
        affordances.add("smb_rpc_works")
    elif "access denied" in stdout.lower() or "refused" in stdout.lower():
        constraints.add("smb_rpc_blocked")
    else:
        constraints.add("smb_no_users_found")
    return ConstraintDelta(
        new_affordances=affordances,
        new_constraints=constraints,
        resolved_unknowns={"smb_users_unknown"},
        evidence=stdout[:1000],
    )

def parse_smb_guest_check(stdout: str, target: str) -> ConstraintDelta:
    """Parse smbclient guest access check."""
    affordances = set()
    constraints = set()
    if "tree connect failed" in stdout.lower():
        constraints.add("smb_guest_blocked")
    elif "NT_STATUS" in stdout:
        constraints.add("smb_guest_failed")
    elif stdout.strip():
        affordances.add("smb_guest_accessible")
    return ConstraintDelta(
        new_affordances=affordances,
        new_constraints=constraints,
        resolved_unknowns={"smb_guest_unknown"},
        evidence=stdout[:1000],
    )

def parse_hydra_simple(stdout: str, target: str) -> ConstraintDelta:
    """Parse hydra output for discovered credentials."""
    affordances = set()
    constraints = set()
    import re
    creds = re.findall(r'login:\s*(\S+)\s+password:\s*(\S+)', stdout)
    for user, pwd in creds:
        affordances.add(f"cred:{user}:{pwd}")
    if creds:
        affordances.add("default_creds_found")
    elif "target" in stdout.lower() or "error" in stdout.lower():
        constraints.add("no_default_creds_found")
    return ConstraintDelta(
        new_affordances=affordances,
        new_constraints=constraints,
        evidence=stdout[:1000],
    )

def parse_nfs_export_list(stdout: str, target: str) -> ConstraintDelta:
    """Parse showmount -e output."""
    affordances = set()
    constraints = set()
    import re
    exports = re.findall(r'^(\S+)', stdout, re.MULTILINE)
    for export in exports:
        if export and export != '/':
            affordances.add(f"nfs_export:{export}")
    if exports:
        affordances.add("nfs_exports")
    elif "mount" in stdout.lower() or "clnt" in stdout.lower():
        constraints.add("nfs_restricted")
    return ConstraintDelta(
        new_affordances=affordances,
        new_constraints=constraints,
        resolved_unknowns={"nfs_exports_unknown"},
        evidence=stdout[:1000],
    )

def parse_mysql_basic(stdout: str, target: str) -> ConstraintDelta:
    """Parse mysql anonymous login output."""
    affordances = set()
    constraints = set()
    if "ERROR" in stdout and "Access denied" in stdout:
        constraints.add("mysql_auth_required")
    elif "version" in stdout.lower() or "mysql" in stdout.lower():
        affordances.add("mysql_no_auth")
        affordances.add("mysql_accessible")
    return ConstraintDelta(
        new_affordances=affordances,
        new_constraints=constraints,
        resolved_unknowns={"mysql_anonymous_unknown"},
        evidence=stdout[:1000],
    )

def parse_redis_info(stdout: str, target: str) -> ConstraintDelta:
    """Parse redis-cli INFO output."""
    affordances = set()
    constraints = set()
    if "# Server" in stdout or "redis_version" in stdout:
        affordances.add("redis_no_auth")
        affordances.add("redis_accessible")
        for line in stdout.splitlines():
            if "redis_version" in line:
                ver = line.split(":")[-1].strip() if ":" in line else ""
                if ver:
                    affordances.add(f"redis_version:{ver}")
    elif "DENIED" in stdout or "NOAUTH" in stdout or "refused" in stdout.lower():
        constraints.add("redis_auth_required")
    return ConstraintDelta(
        new_affordances=affordances,
        new_constraints=constraints,
        resolved_unknowns={"redis_noauth_unknown"},
        evidence=stdout[:1000],
    )

def parse_mongo_basic(stdout: str, target: str) -> ConstraintDelta:
    """Parse mongo anonymous access output."""
    affordances = set()
    constraints = set()
    if "databases" in stdout.lower() or "ok" in stdout.lower():
        affordances.add("mongo_no_auth")
        affordances.add("mongo_accessible")
    elif "Authentication failed" in stdout or "unauthorized" in stdout.lower():
        constraints.add("mongo_auth_required")
    return ConstraintDelta(
        new_affordances=affordances,
        new_constraints=constraints,
        resolved_unknowns={"mongo_noauth_unknown"},
        evidence=stdout[:1000],
    )

def parse_rpcinfo_parse(stdout: str, target: str) -> ConstraintDelta:
    """Parse rpcinfo -p output."""
    affordances = set()
    constraints = set()
    for line in stdout.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[0].isdigit():
            prog = parts[0]
            vers = parts[1]
            proto = parts[2]
            service = parts[3] if len(parts) > 3 else ""
            affordances.add(f"rpc:{service.lower()}:{prog}:{vers}")
            affordances.add("rpc_endpoints")
    if not affordances and "No remote" in stdout:
        constraints.add("rpc_no_endpoints")
    return ConstraintDelta(
        new_affordances=affordances,
        new_constraints=constraints,
        resolved_unknowns={"rpc_endpoints_unknown"},
        evidence=stdout[:1000],
    )

# ===== END WAVE 2 PARSERS =====

# ===== WAVE 3 PARSERS =====

def parse_vhost_enum(stdout: str, target: str) -> ConstraintDelta:
    """Parse vhost_enum JSON output."""
    import json
    affordances = set()
    try:
        data = json.loads(stdout)
        if data.get("discovered_count", 0) > 0:
            affordances.add("vhosts_discovered")
            affordances.add(f"vhost_count:{data['discovered_count']}")
            for h in data.get("hosts", []):
                affordances.add(f"vhost:{h['host']}")
        else:
            affordances.add("no_vhosts_found")
        affordances.add("vhost_enum_complete")
    except json.JSONDecodeError:
        affordances.add("vhost_enum_output")
    return ConstraintDelta(new_affordances=affordances, evidence=stdout[:1000])


def parse_exploit_factory(stdout: str, target: str) -> ConstraintDelta:
    """Parse exploit_factory JSON output."""
    import json
    affordances = set()
    try:
        data = json.loads(stdout)
        count = data.get("deliveries_generated", 0)
        if count > 0:
            affordances.add("exploit_payloads")
            affordances.add("exploit_deliveries")
            affordances.add(f"exploit_count:{count}")
            for d in data.get("deliveries", []):
                affordances.add(f"exploit:{d['cve_id']}")
                affordances.add(f"exploit_delivered:{d['cve_id']}")
        else:
            affordances.add("no_exploits_generated")
        affordances.add("exploit_factory_complete")
    except json.JSONDecodeError:
        affordances.add("exploit_factory_output")
    return ConstraintDelta(new_affordances=affordances, evidence=stdout[:1000])


def parse_verification_loop(stdout: str, target: str) -> ConstraintDelta:
    """Parse verification_loop JSON output."""
    import json
    affordances = set()
    try:
        data = json.loads(stdout)
        if data.get("overall_result") == "success":
            affordances.add("exploit_verified")
            affordances.add("shell_access")
            affordances.add("flag_captured")
        elif data.get("overall_result") in ("partial", "blind_rce"):
            affordances.add("exploit_partial")
        else:
            affordances.add("exploit_failed")
        affordances.add("verification_complete")
    except json.JSONDecodeError:
        affordances.add("verification_output")
    return ConstraintDelta(new_affordances=affordances, evidence=stdout[:1000])


# ---------------------------------------------------------------------------
# Wave 3b parsers: HTTP POST capability
# ---------------------------------------------------------------------------

def parse_http_method_parse(stdout: str, target: str) -> ConstraintDelta:
    """Parse OPTIONS response to detect POST capability."""
    from raphael.models.target_model import ConstraintDelta
    affordances = set()
    constraints = set()
    for line in stdout.splitlines():
        if line.lower().startswith("allow:"):
            if "post" in line.lower():
                affordances.add("CAN_HTTP_POST")
                affordances.add("http_post_enabled")
            if "put" in line.lower():
                affordances.add("CAN_HTTP_PUT")
            if "delete" in line.lower():
                affordances.add("CAN_HTTP_DELETE")
    if "CAN_HTTP_POST" not in affordances:
        constraints.add("http_post_disabled")
    return ConstraintDelta(
        new_affordances=affordances,
        new_constraints=constraints,
        resolved_unknowns={"http_post_unknown"},
        evidence=stdout[:1000],
    )


def parse_auth_bypass_parse(stdout: str, target: str) -> ConstraintDelta:
    """Parse POST login response to detect auth bypass."""
    from raphael.models.target_model import ConstraintDelta
    affordances = set()
    status_code = 0
    for line in stdout.splitlines():
        if line.startswith("HTTP/"):
            parts = line.split()
            if len(parts) > 1:
                try:
                    status_code = int(parts[1])
                except ValueError:
                    pass
            break
    if status_code in (200, 201, 204):
        affordances.add("AUTH_BYPASS_SUCCESS")
        if "Set-Cookie" in stdout or "set-cookie" in stdout.lower():
            affordances.add("SESSION_COOKIE_ISSUED")
    elif status_code == 302:
        affordances.add("AUTH_BYPASS_SUCCESS")
        affordances.add("AUTH_REDIRECT_DETECTED")
        if "Set-Cookie" in stdout or "set-cookie" in stdout.lower():
            affordances.add("SESSION_COOKIE_ISSUED")
    elif status_code == 401:
        affordances.add("AUTH_REQUIRED")
    elif status_code == 403:
        affordances.add("AUTH_FORBIDDEN")
    if "SQL syntax" in stdout or "mysql_fetch" in stdout:
        affordances.add("SQLI_VULNERABLE")
    return ConstraintDelta(
        new_affordances=affordances,
        resolved_unknowns={"login_auth_unknown"},
        evidence=stdout[:2000],
    )


def parse_js_deobfuscate_parse(stdout: str, target: str) -> ConstraintDelta:
    """Parse deobfuscated JS output."""
    from raphael.models.target_model import ConstraintDelta
    affordances = set()
    s = stdout.lower()
    if "http" in s or "function" in s:
        affordances.add("JS_DEOBFUSCATED")
    if "xhr" in s or "xmlhttp" in s:
        affordances.add("js_xhr_detected")
    if "chrome" in s or "browser" in s:
        affordances.add("js_extension_api_detected")
    if "eval" in s:
        affordances.add("js_eval_remnant")
    if not affordances:
        affordances.add("js_still_obfuscated")
    return ConstraintDelta(
        new_affordances=affordances,
        new_constraints={"deobfuscated_output": stdout[:5000]},
        resolved_unknowns={"js_obfuscation_unknown"},
        evidence=stdout[:2000],
    )


def parse_leveldb_data_parse(stdout: str, target: str) -> ConstraintDelta:
    """Parse LevelDB hex dump for encrypted payloads."""
    from raphael.models.target_model import ConstraintDelta
    affordances = set()
    constraints = {}
    lines = [l for l in stdout.splitlines() if l.strip()]
    if not lines:
        affordances.add("leveldb_empty")
        return ConstraintDelta(
            new_affordances=affordances,
            resolved_unknowns={"leveldb_data_unknown"},
            evidence=stdout[:1000],
        )
    affordances.add("LEVELDB_RECORDS_EXTRACTED")
    affordances.add(f"leveldb_record_count:{len(lines)}")
    for line in lines:
        if ":" in line:
            hex_data = line.split(":", 1)[1]
            try:
                raw = bytes.fromhex(hex_data)
                if b"HTB{" in raw:
                    affordances.add("flag_encrypted_detected")
            except (ValueError, AttributeError):
                pass
    return ConstraintDelta(
        new_affordances=affordances,
        new_constraints=constraints,
        resolved_unknowns={"leveldb_data_unknown"},
        evidence=stdout[:2000],
    )


def parse_xor_crack_parse(stdout: str, target: str) -> ConstraintDelta:
    """Parse XOR sweep output for decrypted flags."""
    import re
    from raphael.models.target_model import ConstraintDelta
    affordances = set()
    constraints = {}
    match = re.search(r'HTB\{[^}]{3,80}\}', stdout)
    if match:
        affordances.add("FLAG_DECRYPTED")
        constraints["flag"] = match.group(0)
        affordances.add("flag_captured")
    elif "flag" in stdout.lower() and "not" in stdout.lower():
        affordances.add("xor_sweep_no_flag")
    else:
        affordances.add("xor_sweep_incomplete")
    return ConstraintDelta(
        new_affordances=affordances,
        new_constraints=constraints,
        resolved_unknowns={"xor_decrypt_unknown"},
        evidence=stdout[:2000],
    )


# Wave 3c — Blind probe parser

def parse_BlindProbeParser(stdout: str, target: str) -> ConstraintDelta:
    """Parse blind_probe JSON output into structural affordances."""
    from raphael.models.target_model import ConstraintDelta
    import json
    affordances = set()
    evidence = stdout[:2000]

    try:
        results = json.loads(stdout)
    except json.JSONDecodeError:
        affordances.add("blind_probe_output_raw")
        return ConstraintDelta(new_affordances=affordances, evidence=evidence)

    for vec_name, response in results.items():
        if response not in ("EMPTY_ACK", "CONN_REFUSED", "CONN_TIMEOUT") and not response.startswith("SOCKET_ERR"):
            affordances.add(f"VECTOR_RESPONDED:{vec_name}")
            affordances.add("SIGNATURE_ACQUIRED")

            if "HTTP/" in response or "Server:" in response:
                affordances.add("http_service")
                affordances.add("SIG:HTTP_DETECTED")
            if "SSH-" in response:
                affordances.add("ssh_service")
                affordances.add("SIG:SSH_DETECTED")

    return ConstraintDelta(new_affordances=affordances, evidence=evidence)


# ── Wave 3d: mass_payload_parse — PayloadFabric injection point parser ──
def parse_mass_payload_parse(stdout: str, target: str) -> ConstraintDelta:
    if not stdout.strip():
        return ConstraintDelta.empty()
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return ConstraintDelta.empty()
    if not isinstance(data, list):
        return ConstraintDelta.empty()
    delta = ConstraintDelta()
    injection_found = False
    for item in data:
        ptype = item.get("type", "")
        if ptype in ("sqli", "xss", "ssti", "nosqli"):
            injection_found = True
            delta.new_affordances.add(f"{ptype}_payload_generated")
            delta.new_affordances.add(f"INJECTION_CANDIDATE_{ptype.upper()}")
    if injection_found:
        delta.new_affordances.add("INJECTION_POINTS_FOUND")
        delta.evidence = json.dumps(data[:5])
    return delta


# ── Wave 3d: fast_port_parse — fast_port_scan results parser ──
def parse_fast_port_parse(stdout: str, target: str) -> ConstraintDelta:
    if not stdout.strip():
        return ConstraintDelta.empty()
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return ConstraintDelta.empty()
    delta = ConstraintDelta()
    for port in data.get("open_ports", []):
        delta.new_affordances.add(f"port_{port}_open")
        delta.new_affordances.add(f"PORT_{port}_TCP")
    for port in data.get("closed_ports", []):
        delta.new_constraints.add(f"port_{port}_closed")
    if data.get("open_ports"):
        port_list = ",".join(str(p) for p in data["open_ports"])
        delta.new_affordances.add(f"port_list:{port_list}")
        delta.new_affordances.add("open_ports")
        delta.evidence = json.dumps({
            "open": data["open_ports"],
            "closed_count": len(data["closed_ports"]),
        })
    return delta


# ── Wave 3e: directory_brute — gobuster dir output ──────────────────
def parse_directory_brute(stdout: str, target: str) -> ConstraintDelta:
    affordances = set()
    import re
    # gobuster dir output: "/path (Status: NNN) [Size: NNN]"
    for line in stdout.splitlines():
        m = re.match(r'^(\/[\w\-./]+)\s+\(Status:\s*(\d+)\)', line)
        if m:
            path = m.group(1)
            status = m.group(2)
            affordances.add(f"dir:{path}")
            affordances.add(f"dir_status:{path}:{status}")
            if status.startswith("2"):
                affordances.add("discovered_accessible_paths")
    if affordances:
        affordances.add("directories_found")
    return ConstraintDelta(
        new_affordances=affordances,
        resolved_unknowns={"directories_unknown"},
        evidence=stdout[:2000],
    )


# ── Wave 3e: nuclei_vuln — generic nuclei JSON findings parser ──────
def parse_nuclei_vuln(stdout: str, target: str) -> ConstraintDelta:
    affordances = set()
    constraints = set()
    import json as _json
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = _json.loads(line)
        except _json.JSONDecodeError:
            continue
        tid = data.get("template-id", "")
        matched = data.get("matched-at", "")
        severity = data.get("info", {}).get("severity", "unknown")
        if tid:
            affordances.add(f"vuln:{tid}")
            affordances.add(f"vuln_severity:{severity}")
            if matched:
                affordances.add(f"vuln_match:{matched}")
            affordances.add("vulnerability_found")
    if not affordances:
        constraints.add("no_vulnerability_found")
    return ConstraintDelta(
        new_affordances=affordances,
        new_constraints=constraints,
        resolved_unknowns={"vulnerability_unknown"},
        evidence=stdout[:2000],
    )


# ===== END WAVE 3 PARSERS =====

# Register all parsers
register_parser("raw", parse_raw)
register_parser("nmap_port_list", parse_nmap_port_list)
register_parser("nmap_service_version", parse_nmap_service_version)
register_parser("dns_raw", parse_dns_raw)
register_parser("smb_share_list", parse_smb_share_list)
register_parser("gobuster_raw", parse_gobuster_raw)
register_parser("sqlmap_result", parse_sqlmap_result)

# Wave 2 parser registrations
register_parser("waf_detect", parse_waf_detect)
register_parser("tech_fingerprint", parse_tech_fingerprint)
register_parser("subdomain_list", parse_subdomain_list)
register_parser("whois_raw", parse_whois_raw)
register_parser("ldap_root_dse", parse_ldap_root_dse)
register_parser("snmp_raw", parse_snmp_raw)
register_parser("rpc_enum_users", parse_rpc_enum_users)
register_parser("smb_guest_check", parse_smb_guest_check)
register_parser("hydra_simple", parse_hydra_simple)
register_parser("nfs_export_list", parse_nfs_export_list)
register_parser("mysql_basic", parse_mysql_basic)
register_parser("redis_info", parse_redis_info)
register_parser("mongo_basic", parse_mongo_basic)
register_parser("rpcinfo_parse", parse_rpcinfo_parse)

# Wave 3 parser registrations
register_parser("vhost_enum", parse_vhost_enum)
register_parser("exploit_factory", parse_exploit_factory)
register_parser("verification_loop", parse_verification_loop)

# Wave 3b — HTTP POST + Forensics parsers
register_parser("http_method_parse", parse_http_method_parse)
register_parser("auth_bypass_parse", parse_auth_bypass_parse)
register_parser("js_deobfuscate_parse", parse_js_deobfuscate_parse)
register_parser("leveldb_data_parse", parse_leveldb_data_parse)
register_parser("xor_crack_parse", parse_xor_crack_parse)

# Wave 3c — Blind probe parser
register_parser("BlindProbeParser", parse_BlindProbeParser)

# Wave 3d — Hellfire extractions
register_parser("mass_payload_parse", parse_mass_payload_parse)
register_parser("fast_port_parse", parse_fast_port_parse)

# Wave 3e — Directory brute + nuclei vuln parsers
register_parser("directory_brute", parse_directory_brute)
register_parser("nuclei_vuln", parse_nuclei_vuln)
