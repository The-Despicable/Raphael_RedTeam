"""environment.py — Simulated scenario environment for Stage 2.5.

Provides:
- ScenarioEnvironment: holds ground-truth network state, responds to actions
  with realistic observations (never exposes evaluator_truth directly).
- RawObservation: the output of a simulated tool/adapter.
- ObservationIngestion pipeline: RawObservation → Evidence → EvidenceGraph.

Only information obtainable through EngagementView + permitted actions
is ever returned. evaluator_truth is never leaked.
"""

import time
import re
import uuid
import random
import ipaddress
from dataclasses import dataclass, field
from typing import Any, Optional

from orchestrator.brain.evidence import Evidence, get_evidence_graph, TrustLevel


# ── RawObservation ────────────────────────────────────────────

@dataclass
class RawObservation:
    """Raw output from a simulated tool/adapter.
    
    This is the atomic unit of observation. It is NOT yet Evidence —
    it must go through the ObservationNormalizer.
    """
    observation_id: str = ""
    source_tool: str = ""         # e.g., "nmap", "curl"
    action_receipt_id: str = ""   # Receipt that authorized this action
    raw_output: str = ""          # Raw tool output (simulated)
    observed_at: float = 0.0
    target: str = ""              # What was observed (IP, hostname, URL)
    observation_type: str = ""    # "port_scan", "service_detection", "http_response", etc.


# ── Observation Normalizer ────────────────────────────────────

class ObservationNormalizer:
    """Converts RawObservation → Evidence for the EvidenceGraph.
    
    Preserves full provenance: source tool, receipt, trust level.
    Distinguishes between direct observations and inferences.
    """
    
    @staticmethod
    def normalize(obs: RawObservation, trust_level: TrustLevel = None) -> list[Evidence]:
        """Convert a RawObservation into one or more Evidence objects.
        
        Parses the raw_output and creates structured Evidence.
        Returns a list (typically 1, but some observations create multiple).
        """
        if trust_level is None:
            from orchestrator.brain.trust import TrustLevel as TL
            trust_level = TL.TOOL_OBSERVATION
        
        evidence_list = []
        
        # For simulated output, each line can be a separate evidence item
        lines = obs.raw_output.strip().split('\n')
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            ev = Evidence.create(
                raw_content=line,
                trust_level=trust_level,
                source_detail=f"{obs.source_tool} on {obs.target} (receipt: {obs.action_receipt_id})",
                target=obs.target,
                phase="observation",
                evidence_type=obs.observation_type,
                description=f"{obs.source_tool} observation: {line[:100]}",
            )
            evidence_list.append(ev)
        
        return evidence_list


# ── ScenarioEnvironment ───────────────────────────────────────

class ScenarioEnvironment:
    """Simulated environment holding ground-truth network state.
    
    Responds to actions with observations that reveal only what the
    action would legitimately discover.
    
    evaluator_truth is used to DETERMINE RESPONSES but is NEVER
    returned directly.
    """
    
    def __init__(self, scenario):
        self.scenario = scenario
        self.et = scenario.evaluator_truth  # For determining responses only
        self._observations_generated = 0
    
    def create_initial_observations(self) -> list[RawObservation]:
        """Create initial observations from the engagement view.
        
        This simulates the operator briefing: "Here's what you know
        before starting."
        """
        view = self.scenario.engagement_view()
        obs_list = []
        
        for asset in view.get("starting_assets", []):
            hostname = asset.get("hostname", "unknown")
            ip = asset.get("ip", "")
            services = asset.get("services", [])
            os_info = asset.get("os", "unknown")
            
            # Initial brief: operator provides target hostnames and IPs
            brief_text = (
                f"Target briefing: {hostname} ({ip}) — "
                f"os: {os_info}, known services: {', '.join(services)}"
            )
            obs_list.append(RawObservation(
                observation_id=f"init_obs_{self._observations_generated}",
                source_tool="operator_briefing",
                action_receipt_id="",
                raw_output=brief_text,
                observed_at=time.time(),
                target=ip,
                observation_type="initial_briefing",
            ))
            self._observations_generated += 1
        
        # Also add scope information as observations
        scope_text = (
            f"Scope: allowed={view.get('allowed_scope', [])}, "
            f"prohibited={view.get('prohibited_scope', [])}"
        )
        obs_list.append(RawObservation(
            observation_id=f"init_obs_{self._observations_generated}",
            source_tool="rules_of_engagement",
            action_receipt_id="",
            raw_output=scope_text,
            observed_at=time.time(),
            target="",
            observation_type="scope",
        ))
        self._observations_generated += 1
        
        return obs_list
    
    def handle_action(self, target: str, action_type: str,
                      capability: str, method: str,
                      receipt_id: str = "") -> list[RawObservation]:
        """Respond to an action with environmental observations.
        
        Uses evaluator_truth to determine what the action reveals.
        ONLY information that the action would legitimately discover
        is returned. Never exposes evaluator_truth directly.
        
        Returns a list of RawObservation objects.
        """
        observations = []
        
        # ── SYN SCAN (all ports) ──
        if action_type in ("syn_scan", "scan") and capability == "nmap":
            if method == "all":
                observations.extend(self._handle_syn_scan_all(target, action_type, capability, method, receipt_id))
            else:
                # Single port SYN scan
                observations.extend(self._handle_syn_scan(target, capability, method, receipt_id))
        
        # ── HTTP GET ──
        elif action_type in ("http_get", "http", "get") and capability in ("curl", "http", "http_client"):
            observations.extend(self._handle_http_get(target, capability, method, receipt_id))
        
        # ── HTTP OPTIONS ──
        elif action_type == "http_options" and capability in ("curl", "http"):
            observations.extend(self._handle_http_options(target, capability, method, receipt_id))
        
        # ── HTTP FULL REQUEST ──
        elif action_type in ("http_full_request", "http_request", "http_post") and capability in ("curl", "http"):
            observations.extend(self._handle_http_full_request(target, capability, method, receipt_id))
        
        # ── HTTP OPTIONS ──
        elif action_type in ("http_options",) and capability in ("curl", "http"):
            observations.extend(self._handle_http_options(target, capability, method, receipt_id))
        
        # ── BANNER GRAB ──
        elif action_type in ("banner_grab", "banner") and capability in ("nmap", "netcat", "telnet", "curl"):
            observations.extend(self._handle_banner_grab(target, capability, method, receipt_id))
        
        # ── SSH HANDSHAKE ──
        elif action_type in ("ssh_handshake", "ssh_handshake") and capability in ("ssh",):
            observations.extend(self._handle_ssh_handshake(target, capability, method, receipt_id))
        
        # ── ARP QUERY ──
        elif action_type in ("arp_query", "arp") and capability in ("arp", "nmap"):
            observations.extend(self._handle_arp_query(target, capability, method, receipt_id))
        
        # ── SSH EXEC ──
        elif action_type in ("ssh_exec", "ssh_command") and capability in ("ssh",):
            observations.extend(self._handle_ssh_exec(target, capability, method, receipt_id))
        
        # ── TLS HANDSHAKE ──
        elif action_type in ("tls_handshake", "tls", "ssl") and capability in ("openssl", "curl", "ssl"):
            observations.extend(self._handle_tls_handshake(target, capability, method, receipt_id))
        
        # ── SSH BANNER ──
        elif action_type in ("ssh_banner", "ssh_banner_grab") and capability in ("ssh",):
            observations.extend(self._handle_ssh_banner(target, capability, method, receipt_id))
        
        # ── ARP QUERY ──
        elif action_type in ("arp_query", "arp") and capability in ("arp", "nmap"):
            observations.extend(self._handle_arp_query(target, capability, method, receipt_id))
        
        # ── DIRECT PROBE (falsification discriminator) ──
        elif action_type == "direct_probe" and capability in ("curl", "http"):
            # Direct probe reveals the true version from the evaluator truth
            observations.extend(self._handle_http_get(target, "curl", method, receipt_id))
        
        # ── FALLBACK: Original logic for backward compatibility ──
        if not observations and action_type in ("scan", "recon") and capability in ("nmap", "curl"):
            # Determine what nmap/curl would see
            vulns = self.et.get("vulnerabilities", [])
            benign = self.et.get("benign_conditions", [])
            expected_obs = self.et.get("expected_observations", [])
            
            for vuln in self.et.get("vulnerabilities", []):
                vuln_host = vuln.get("host", "")
                vuln_ip = self._resolve_host_to_ip(vuln.get("host", ""))
                
                if target == vuln_ip or target == vuln.get("host", "") or self._ip_in_scope(target, vuln_ip):
                    port = vuln.get("port", 80)
                    svc = vuln.get("service", "http")
                    
                    if capability == "nmap":
                        if method in ("quick", "auto"):
                            obs_text = f"{vuln_ip}:{port}/tcp open {svc}"
                        else:
                            if vuln.get("service") == "http":
                                vuln_cve = vuln.get("cve", "CVE-XXXX-XXXX")
                                obs_text = (
                                    f"{vuln_ip}:{port}/tcp open {svc} "
                                    f"| Server: Apache/2.4.49 "
                                    f"| Vulnerable to {vuln_cve}"
                                )
                            elif vuln.get("service") == "tomcat":
                                obs_text = (
                                    f"{vuln_ip}:{port}/tcp open {svc} "
                                    f"| Apache Tomcat/9.0.30 "
                                    f"| CGIServlet enabled"
                                )
                            else:
                                obs_text = f"{vuln_ip}:{port}/tcp open {svc}"
                    elif capability == "curl":
                        cve_id = vuln.get("cve", "CVE-XXXX-XXXX")
                        if cve_id == "CVE-2023-44487":
                            obs_text = (
                                f"HTTP/1.1 200 OK\n"
                                f"Server: nginx/1.25.0\n"
                                f"Warning: HTTP/2 rapid reset possible ({cve_id})"
                            )
                        elif cve_id == "CVE-2021-3129":
                            obs_text = (
                                f"HTTP/1.1 200 OK\n"
                                f"Server: Apache/2.4.49\n"
                                f"X-Powered-By: Laravel\n"
                                f"_ignition endpoint: /_ignition/execute-solution"
                            )
                        else:
                            obs_text = f"HTTP/1.1 200 OK\nServer: {svc}/1.0"
                    
                    observations.append(RawObservation(
                        observation_id=f"obs_{self._observations_generated}",
                        source_tool=capability,
                        action_receipt_id=receipt_id,
                        raw_output=obs_text,
                        observed_at=time.time(),
                        target=vuln_ip if vuln_ip else target,
                        observation_type=f"{action_type}_{method}" if method else action_type,
                    ))
                    self._observations_generated += 1
            
            # Also report basic host info
            for asset in self.et.get("starting_assets", []):
                asset_ip = asset.get("ip", "")
                if target == asset_ip or self._ip_in_scope(target, asset_ip):
                    port_map = {"http": 80, "https": 443, "ssh": 22, "tomcat": 8080,
                                "dns": 53, "mysql": 3306, "postgresql": 5432,
                                "snmp": 161, "rsync": 873, "samba": 445, "nfs": 2049,
                                "docker": 2375, "redis": 6379, "memcached": 11211,
                                "http-proxy": 8080, "http-proxy-alt": 8080,
                                "custom-tcp": 9999, "ssh-alt": 2222}
                    for svc in asset.get("services", []):
                        port = {"http": 80, "https": 443, "ssh": 22, "tomcat": 8080,
                                "dns": 53, "mysql": 3306, "postgresql": 5432,
                                "snmp": 161, "rsync": 873, "samba": 445, "nfs": 2049,
                                "docker": 2375, "redis": 6379, "memcached": 11211,
                                "http-proxy": 8080, "http-proxy-alt": 8080,
                                "custom-tcp": 9999, "ssh-alt": 2222, "ssh": 22}.get(svc, 80)
                        
                        # Only add if we didn't already generate from a vuln
                        already_reported = any(
                            svc in o.raw_output for o in observations
                        )
                        has_version_info = any(
                            "Server:" in o.raw_output or "Vulnerable to" in o.raw_output
                            for o in observations
                        )
                        if not already_reported or has_version_info:
                            obs_text = f"{asset.get('ip', '')}:{port}/tcp open {svc}"
                            observations.append(RawObservation(
                                observation_id=f"obs_{self._observations_generated}",
                                source_tool=capability,
                                action_receipt_id=receipt_id,
                                raw_output=obs_text,
                                observed_at=time.time(),
                                target=asset.get("ip", ""),
                                observation_type="service_discovery",
                            ))
                            self._observations_generated += 1
                        # OS detection
                        os_info = asset.get("os", "")
                        if os_info and not any(os_info in o.raw_output for o in observations):
                            obs_text = f"OS detected: {os_info} (ttl=64, fingerprint match)"
                            observations.append(RawObservation(
                                observation_id=f"obs_{self._observations_generated}",
                                source_tool=capability,
                                action_receipt_id=receipt_id,
                                raw_output=obs_text,
                                observed_at=time.time(),
                                target=asset.get("ip", ""),
                                observation_type="os_detection",
                            ))
                            self._observations_generated += 1
        
        return observations
    
    # ── Helper methods for specific action types ──
    
    def _handle_syn_scan_all(self, target: str, action_type: str, capability: str, method: str, receipt_id: str) -> list[RawObservation]:
        """SYN scan all ports to find which ones are open."""
        observations = []
        # Find the target asset
        target_ip = self._resolve_target_ip(target)
        if not target_ip:
            return observations
        
        # Find the asset to get its services
        asset = self._find_asset_by_ip(target_ip)
        if not asset:
            return observations
        
        # Return all open ports
        port_map = {"http": 80, "https": 443, "ssh": 22, "tomcat": 8080,
                    "dns": 53, "mysql": 3306, "postgresql": 5432,
                    "snmp": 161, "rsync": 873, "samba": 445, "nfs": 2049,
                    "docker": 2375, "redis": 6379, "memcached": 11211,
                    "http-proxy": 8080, "http-proxy-alt": 8080,
                    "custom-tcp": 9999, "ssh-alt": 2222}
        
        open_ports = []
        for svc in asset.get("services", []):
            port = port_map.get(svc, 80)
            open_ports.append(f"{svc}:{port}")
        
        # Also check for hidden ports in benign_conditions (for planner-sensitive and similar)
        if not open_ports:
            for bc in self.et.get("benign_conditions", []):
                # Look for "True open port: <port>" pattern
                m = re.search(r'True open port:\s*(\d+)', bc)
                if m:
                    hidden_port = int(m.group(1))
                    # Determine service type from port
                    if hidden_port == 8443:
                        svc = "https"
                    elif hidden_port in (8080, 8888, 9000):
                        svc = "http"
                    else:
                        svc = "tcp"
                    open_ports.append(f"{svc}:{hidden_port}")
        
        # If this is a version detection scan (method "all"), include version info
        # from the ground truth (simulating nmap -sV)
        if method == "all":
            # Check for vulnerabilities/vulnerable services on this target
            vulns = self.et.get("vulnerabilities", [])
            for vuln in vulns:
                vuln_host = vuln.get("host", "")
                vuln_ip = self._resolve_host_to_ip(vuln.get("host", ""))
                
                if target == vuln_ip or target == vuln.get("host", "") or self._ip_in_scope(target, vuln_ip):
                    port = vuln.get("port", 80)
                    svc = vuln.get("service", "http")
                    
                    if capability == "nmap":
                        if method in ("all", "quick", "auto"):
                            obs_text = (
                                f"{vuln_ip}:{port}/tcp open {svc} "
                                f"| Server: Apache/2.4.49 "
                                f"| Vulnerable to {vuln.get('cve', 'CVE-XXXX-XXXX')}"
                            )
                        else:
                            if vuln.get("service") == "http":
                                obs_text = (
                                    f"{vuln_ip}:{port}/tcp open {svc} "
                                    f"| Server: Apache/2.4.49 "
                                    f"| Vulnerable to {vuln.get('cve', 'CVE-XXXX-XXXX')}"
                                )
                            elif vuln.get("service") == "tomcat":
                                obs_text = (
                                    f"{vuln_ip}:{port}/tcp open {svc} "
                                    f"| Apache Tomcat/9.0.30 "
                                    f"| CGIServlet enabled"
                                )
                            else:
                                obs_text = f"{vuln_ip}:{port}/tcp open {svc}"
                    elif capability == "curl":
                        cve_id = vuln.get("cve", "CVE-XXXX-XXXX")
                        if cve_id == "CVE-2023-44487":
                            obs_text = (
                                f"HTTP/1.1 200 OK\n"
                                f"Server: nginx/1.25.0\n"
                                f"Warning: HTTP/2 rapid reset possible ({cve_id})"
                            )
                        elif cve_id == "CVE-2021-3129":
                            obs_text = (
                                f"HTTP/1.1 200 OK\n"
                                f"Server: Apache/2.4.49\n"
                                f"X-Powered-By: Laravel\n"
                                f"_ignition endpoint: /_ignition/execute-solution"
                            )
                        else:
                            obs_text = f"HTTP/1.1 200 OK\nServer: {svc}/1.0"
                    
                    observations.append(RawObservation(
                        observation_id=f"obs_{self._observations_generated}",
                        source_tool=capability,
                        action_receipt_id=receipt_id,
                        raw_output=obs_text,
                        observed_at=time.time(),
                        target=vuln_ip if vuln_ip else target,
                        observation_type=f"{action_type}_{method}" if method else action_type,
                    ))
                    self._observations_generated += 1
            
            # Also report basic host info
            for asset in self.et.get("starting_assets", []):
                asset_ip = asset.get("ip", "")
                if target == asset_ip or self._ip_in_scope(target, asset_ip):
                    port_map = {"http": 80, "https": 443, "ssh": 22, "tomcat": 8080,
                                "dns": 53, "mysql": 3306, "postgresql": 5432,
                                "snmp": 161, "rsync": 873, "samba": 445, "nfs": 2049,
                                "docker": 2375, "redis": 6379, "memcached": 11211,
                                "http-proxy": 8080, "http-proxy-alt": 8080,
                                "custom-tcp": 9999, "ssh-alt": 2222}
                    for svc in asset.get("services", []):
                        port = {"http": 80, "https": 443, "ssh": 22, "tomcat": 8080,
                                "dns": 53, "mysql": 3306, "postgresql": 5432,
                                "snmp": 161, "rsync": 873, "samba": 445, "nfs": 2049,
                                "docker": 2375, "redis": 6379, "memcached": 11211,
                                "http-proxy": 8080, "http-proxy-alt": 8080,
                                "custom-tcp": 9999, "ssh-alt": 2222, "ssh": 22}.get(svc, 80)
                        
                        # Only add if we didn't already generate from a vuln
                        already_reported = any(
                            svc in o.raw_output for o in observations
                        )
                        has_version_info = any(
                            "Server:" in o.raw_output or "Vulnerable to" in o.raw_output
                            for o in observations
                        )
                        if not already_reported or has_version_info:
                            obs_text = f"{asset.get('ip', '')}:{port}/tcp open {svc}"
                            observations.append(RawObservation(
                                observation_id=f"obs_{self._observations_generated}",
                                source_tool=capability,
                                action_receipt_id=receipt_id,
                                raw_output=obs_text,
                                observed_at=time.time(),
                                target=asset.get("ip", ""),
                                observation_type="service_discovery",
                            ))
                            self._observations_generated += 1
                        # OS detection
                        os_info = asset.get("os", "")
                        if os_info and not any(os_info in o.raw_output for o in observations):
                            obs_text = f"OS detected: {os_info} (ttl=64, fingerprint match)"
                            observations.append(RawObservation(
                                observation_id=f"obs_{self._observations_generated}",
                                source_tool=capability,
                                action_receipt_id=receipt_id,
                                raw_output=obs_text,
                                observed_at=time.time(),
                                target=asset.get("ip", ""),
                                observation_type="os_detection",
                            ))
                            self._observations_generated += 1
            
            return observations
        if not target_ip:
            return []
        
        # Check if target has open ports
        asset = self._find_asset_by_ip(target)
        if not asset:
            return []
        
        # Check for specific port in method or from services
        port = None
        svc_name = None
        for svc in asset.get("services", []):
            port = {"http": 80, "https": 443, "ssh": 22, "tomcat": 8080,
                    "dns": 53, "mysql": 3306, "postgresql": 5432,
                    "snmp": 161, "rsync": 873, "samba": 445, "nfs": 2049,
                    "docker": 2375, "redis": 6379, "memcached": 11211,
                    "http-proxy": 8080, "http-proxy-alt": 8080,
                    "custom-tcp": 9999, "ssh-alt": 2222}.get(svc, 80)
            svc_name = svc
            if port:
                break
        
        if port:
            obs_text = f"{target}:{port}/tcp open {svc_name or 'unknown'}"
        else:
            obs_text = f"{target}:unknown/tcp closed"
        
        self._observations_generated += 1
        return [RawObservation(
            observation_id=f"obs_{self._observations_generated}",
            source_tool="nmap",
            action_receipt_id=receipt_id,
            raw_output=obs_text,
            observed_at=time.time(),
            target=target,
            observation_type="syn_scan",
        )]
    
    def _handle_syn_scan(self, target: str, capability: str, method: str, receipt_id: str) -> list[RawObservation]:
        """Regular SYN port scan."""
        # Delegate to the all-ports handler for single-port scan
        return self._handle_syn_scan_all(target, "syn_scan", capability, method, receipt_id)
    
    def _handle_http_get(self, target: str, capability: str, method: str, receipt_id: str) -> list[RawObservation]:
        """Handle HTTP GET request, extracting path from target."""
        observations = []
        # Parse target for path
        target_ip = target
        path = "/"
        if "/" in target and not target.startswith("http"):
            parts = target.split("/", 1)
            target_ip = parts[0]
            path = "/" + parts[1]
        else:
            target_ip = target
            path = "/"
        
        # Find the asset
        asset = self._find_asset_by_ip(target_ip)
        if not asset:
            return []
        
        # Extract metadata if available
        meta = asset.get("asset_metadata", {})
        host_id = meta.get("host_id", "")
        system_hostname = meta.get("system_hostname", "")
        
        # Generate HTTP response based on path and asset
        if asset.get("services") and ("http" in asset.get("services", []) or "apache" in asset.get("services", []) or "nginx" in asset.get("services", []) or "tomcat" in asset.get("services", [])):
            # Build base headers
            headers = "HTTP/1.1 200 OK\nContent-Type: text/plain\nServer: Apache/2.4.50"
            if host_id:
                headers += f"\nX-Host-ID: {host_id}"
            if system_hostname:
                headers += f"\nX-Hostname: {system_hostname}"
            
            # Check for specific paths
            if "/meta" in path:
                # /meta endpoint returns JSON with host metadata
                obs_text = f"{headers}\n\n{{'host_id':'{host_id}','hostname':'{system_hostname}'}}"
            elif "internal/admin/v2" in path or "/internal/admin" in path:
                obs_text = f"{headers}\n\nInternal admin panel - authentication required"
            elif "admin" in path and "v3" in path:
                obs_text = f"{headers}\n\nAdmin API v3 - accessible"
            elif "admin" in path:
                obs_text = f"{headers}\n\nAdmin panel not found at this path"
            elif "metrics" in path:
                obs_text = f"{headers}\n\n# HELP http_requests_total\n# TYPE http_requests_total counter\nhttp_requests_total 12345"
            elif "backup" in path:
                obs_text = f"{headers}\n\nBackup endpoint - internal use only"
            else:
                # Default response with metadata
                if host_id:
                    obs_text = f"{headers}\n\nService Status Report\n====================\n- Host ID: {host_id}\n- Hostname: {system_hostname}\n- Database: ONLINE\n- Cache: DEGRADED (high latency, may recover)"
                else:
                    obs_text = f"{headers}\n\nService Status Report\n====================\n- Database: ONLINE\n- Cache: DEGRADED (high latency, may recover)\n- Admin API: NOT exposed externally (firewall rule 4049)\n- Metrics endpoint: MAY be accessible at /metrics (experimental)\n- Legacy /admin path: DEPRECATED, use /internal/admin/v2\n- Backup endpoint: /backup/status — FOR INTERNAL USE ONLY"
        else:
            obs_text = "HTTP/1.1 404 Not Found\nContent-Type: text/html\n\nNot Found"
        
        self._observations_generated += 1
        return [RawObservation(
            observation_id=f"obs_{self._observations_generated}",
            source_tool="curl",
            action_receipt_id="",
            raw_output=obs_text,
            observed_at=time.time(),
            target=target,
            observation_type="http_get",
        )]
    
    def _handle_http_options(self, target: str, capability: str, method: str, receipt_id: str) -> list[RawObservation]:
        """Handle HTTP OPTIONS request."""
        # Check if target is the proxy port
        target_ip = self._resolve_target_ip(target)
        asset = self._find_asset_by_ip(target_ip)
        
        if asset and "http-proxy" in asset.get("services", []):
            obs_text = "HTTP/1.1 200 OK\nAllow: GET, POST, CONNECT, HEAD, OPTIONS\nContent-Length: 0"
        else:
            obs_text = "HTTP/1.1 200 OK\nAllow: GET, HEAD, POST\nContent-Length: 0"
        
        self._observations_generated += 1
        return [RawObservation(
            observation_id=f"obs_{self._observations_generated}",
            source_tool="curl",
            action_receipt_id="",
            raw_output=obs_text,
            observed_at=time.time(),
            target=target,
            observation_type="http_options",
        )]
    
    def _handle_http_full_request(self, target: str, capability: str, method: str, receipt_id: str) -> list[RawObservation]:
        """Handle full HTTP request (like curl with verbose output)."""
        # Similar to http_get but more verbose
        return self._handle_http_get(target, capability, method, receipt_id)
    
    def _handle_http_options(self, target: str, capability: str, method: str, receipt_id: str) -> list[RawObservation]:
        """Handle HTTP OPTIONS request - same as http_get."""
        return self._handle_http_get(target, capability, method, receipt_id)
    
    def _handle_banner_grab(self, target: str, capability: str, method: str, receipt_id: str) -> list[RawObservation]:
        """Banner grab on a service."""
        target_ip = self._resolve_target_ip(target)
        asset = self._find_asset_by_ip(target_ip)
        
        if not asset:
            return []
        
        # Check for proxy service
        if "http-proxy" in asset.get("services", []):
            obs_text = "HTTP/1.1 200 OK\nServer: nginx/1.20.1 (proxy)\nVia: 1.1 proxy"
        elif "ssh" in asset.get("services", []):
            obs_text = "SSH-2.0-OpenSSH_8.9p1"
        elif "http" in asset.get("services", []):
            obs_text = "HTTP/1.1 200 OK\nServer: Apache/2.4.52 (Ubuntu)"
        elif "tomcat" in asset.get("services", []):
            obs_text = "Apache Tomcat/9.0.62"
        else:
            obs_text = "Service unknown"
        
        self._observations_generated += 1
        return [RawObservation(
            observation_id=f"obs_{self._observations_generated}",
            source_tool="nmap",
            action_receipt_id="",
            raw_output=obs_text,
            observed_at=time.time(),
            target=target,
            observation_type="banner_grab",
        )]
    
    def _handle_ssh_handshake(self, target: str, capability: str, method: str, receipt_id: str) -> list[RawObservation]:
        """SSH handshake attempt."""
        target_ip = self._resolve_target_ip(target)
        asset = self._find_asset_by_ip(target_ip)
        meta = asset.get("asset_metadata", {}) if asset else {}
        system_hostname = meta.get("system_hostname", "")
        
        if asset and "ssh" in asset.get("services", []):
            # Real SSH - include hostname in banner if available
            if system_hostname:
                obs_text = f"SSH-2.0-OpenSSH_8.9p1\nProtocol 2.0\nBanner: {system_hostname}"
            else:
                obs_text = "SSH-2.0-OpenSSH_8.9p1\nProtocol 2.0"
        else:
            # Custom service on port 22 (like falsification-sensitive)
            obs_text = "CUSTOM/1.0\nNot SSH - protocol mismatch"
        
        self._observations_generated += 1
        return [RawObservation(
            observation_id=f"obs_{self._observations_generated}",
            source_tool="ssh",
            action_receipt_id=receipt_id,
            raw_output=obs_text,
            observed_at=time.time(),
            target=target,
            observation_type="ssh_handshake",
        )]
    
    def _handle_arp_query(self, target: str, capability: str, method: str, receipt_id: str) -> list[RawObservation]:
        """ARP query to get MAC address."""
        target_ip = self._resolve_target_ip(target)
        asset = self._find_asset_by_ip(target_ip)
        meta = asset.get("asset_metadata", {}) if asset else {}
        
        if asset:
            # Use stable MAC from asset_metadata if available, else generate
            mac = meta.get("mac_address", "")
            if not mac:
                import random
                mac = f"00:50:56:{random.randint(0x00, 0xff):02x}:{random.randint(0x00, 0xff):02x}:{random.randint(0x00, 0xff):02x}"
            obs_text = f"ARP reply from {target_ip}: {mac} (VMware, Inc.)"
        else:
            obs_text = f"No ARP response from {target}"
        
        self._observations_generated += 1
        return [RawObservation(
            observation_id=f"obs_{self._observations_generated}",
            source_tool="arp",
            action_receipt_id=receipt_id,
            raw_output=obs_text,
            observed_at=time.time(),
            target=target,
            observation_type="arp_query",
        )]
    
    def _handle_ssh_exec(self, target: str, capability: str, method: str, receipt_id: str) -> list[RawObservation]:
        """SSH command execution."""
        target_ip = self._resolve_target_ip(target)
        asset = self._find_asset_by_ip(target_ip)
        meta = asset.get("asset_metadata", {}) if asset else {}
        host_id = meta.get("host_id", "")
        
        if asset and "ssh" in asset.get("services", []):
            if host_id:
                obs_text = host_id  # Return host_id for commands like 'cat /etc/host_id'
            else:
                obs_text = "HOST-40-A7"  # Fallback
        else:
            obs_text = "Connection refused"
        
        self._observations_generated += 1
        return [RawObservation(
            observation_id=f"obs_{self._observations_generated}",
            source_tool="ssh",
            action_receipt_id=receipt_id,
            raw_output=obs_text,
            observed_at=time.time(),
            target=target,
            observation_type="ssh_exec",
        )]
    
    def _handle_tls_handshake(self, target: str, capability: str, method: str, receipt_id: str) -> list[RawObservation]:
        """TLS handshake."""
        target_ip = self._resolve_target_ip(target)
        asset = self._find_asset_by_ip(target_ip)
        
        if asset and "https" in asset.get("services", []):
            obs_text = "SSL handshake successful\nCertificate: CN=example.com\nTLSv1.3\nCipher: TLS_AES_256_GCM_SHA384"
        elif asset and asset.get("services", []) and "http-proxy" in asset.get("services", []):
            obs_text = "SSL handshake failed: no certificate"
        else:
            obs_text = "Connection refused"
        
        self._observations_generated += 1
        return [RawObservation(
            observation_id=f"obs_{self._observations_generated}",
            source_tool="openssl",
            action_receipt_id=receipt_id,
            raw_output=obs_text,
            observed_at=time.time(),
            target=target,
            observation_type="tls_handshake",
        )]
    
    def _handle_ssh_banner(self, target: str, capability: str, method: str, receipt_id: str) -> list[RawObservation]:
        """SSH banner grab."""
        target_ip = self._resolve_target_ip(target)
        asset = self._find_asset_by_ip(target_ip)
        
        if asset and "ssh" in asset.get("services", []):
            obs_text = "SSH-2.0-OpenSSH_8.9p1"
        else:
            obs_text = "CUSTOM/1.0"
        
        self._observations_generated += 1
        return [RawObservation(
            observation_id=f"obs_{self._observations_generated}",
            source_tool="ssh",
            action_receipt_id=receipt_id,
            raw_output=obs_text,
            observed_at=time.time(),
            target=target,
            observation_type="ssh_banner",
        )]
    
    def _handle_ssh_banner(self, target: str, capability: str, method: str, receipt_id: str) -> list[RawObservation]:
        """SSH banner grab (alias)."""
        return self._handle_ssh_handshake(target, capability, method, receipt_id)
    
    def _resolve_target_ip(self, target: str) -> str:
        """Resolve target to IP address."""
        if not target:
            return ""
        # Handle target:port format
        if ":" in target and not target.startswith("http"):
            return target.split(":")[0]
        return self._resolve_host_to_ip(target)
    
    def _find_asset_by_ip(self, ip: str):
        """Find asset by IP address."""
        for asset in self.et.get("starting_assets", []):
            if asset.get("ip") == ip:
                return asset
        return None
    
    def _resolve_host_to_ip(self, hostname: str) -> str:
        """Resolve a hostname to IP from the evaluator_truth."""
        for asset in self.et.get("starting_assets", []):
            if asset.get("hostname") == hostname:
                return asset.get("ip", "")
        return hostname
    
    def _ip_in_scope(self, pattern: str, ip: str) -> bool:
        """Check if IP matches a CIDR or exact pattern."""
        try:
            target_addr = ipaddress.ip_address(pattern)
            vuln_addr = ipaddress.ip_address(ip)
            target_net = ipaddress.ip_network(f"{pattern}/24", strict=False)
            if vuln_addr in target_net:
                return True
        except ValueError:
            pass
        
        if pattern == ip:
            return True
        if '/' in pattern:
            try:
                net = ipaddress.ip_network(pattern, strict=False)
                addr = ipaddress.ip_address(ip)
                return addr in net
            except ValueError:
                pass
        return False