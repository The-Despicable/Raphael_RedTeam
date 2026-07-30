"""
ChainSynthesizer — Attack-Unit Methodology (v2)

Based on "An Automated Framework for Extracting Reachable Attack Chains
from Cyber Threat Intelligence" (arXiv 2607.19742, ingested via Sci-Hub).

Each attack step is modeled as:
  AttackUnit = { preconditions, attack_behavior, postconditions }

Chaining = finding sequences where postconditions(A) ⊆ preconditions(B).

Preserves existing 6 chain templates + novel synthesis from v1.
Adds BFS chain finder, next-step suggestion, and Datalog rule generation.
"""

import json
import logging
import time
from typing import Any, Optional

logger = logging.getLogger("student.chain_synthesizer")


# ═══════════════════════════════════════════════════════════════
# ATTACK UNIT MODEL
# ═══════════════════════════════════════════════════════════════

class AttackUnit:
    """
    A single step in an attack chain.

    preconditions:  Conditions that must be true before this step can execute.
                    e.g. {"network_access", "unauthenticated_endpoint"}
    behavior:       The actual attack action.
                    e.g. "ssrf_to_internal_service(169.254.169.254)"
    postconditions: Conditions true after this step succeeds.
                    e.g. {"imds_credentials_obtained", "cloud_instance_identified"}

    Chaining rule: Unit B can follow Unit A iff A.postconditions ⊆ B.preconditions
    (i.e., A's outputs satisfy B's requirements).
    """

    def __init__(self, technique_id: str, name: str, behavior: str,
                 preconditions: set, postconditions: set,
                 impact: float = 5.0, detection: Optional[list] = None):
        self.technique_id = technique_id
        self.name = name
        self.behavior = behavior
        self.preconditions = set(preconditions)
        self.postconditions = set(postconditions)
        self.impact = impact
        self.detection = detection or []

    def can_follow(self, other: 'AttackUnit') -> bool:
        """Can this unit execute after 'other'?"""
        return self.preconditions.issubset(other.postconditions)

    def __repr__(self):
        return f"AttackUnit({self.name}: {self.preconditions} → {self.postconditions})"


# ═══════════════════════════════════════════════════════════════
# PREDEFINED ATTACK UNITS (Seed from known techniques + templates)
# ═══════════════════════════════════════════════════════════════

ATTACK_UNIT_LIBRARY: dict[str, AttackUnit] = {}


def _seed_units():
    """Seed the attack unit library from all known chain templates."""
    units = [
        # ── SSRF → Cloud ──────────────────────────────────────
        AttackUnit(
            "ssrf_discovery",
            "SSRF — discover URL-based proxy functionality",
            "inject_url_parameter(url=http://169.254.169.254/)",
            preconditions={"http_endpoint", "url_parameter_exists"},
            postconditions={"ssrf_confirmed", "internal_resource_access"},
            impact=7.0,
            detection=["?url=http://internal/", "?page=http://169.254.169.254/"],
        ),
        AttackUnit(
            "ssrf_imds_aws",
            "SSRF to AWS IMDS — retrieve IAM credentials",
            "ssrf_get(169.254.169.254/latest/meta-data/iam/security-credentials/)",
            preconditions={"ssrf_confirmed", "internal_resource_access", "aws_environment"},
            postconditions={"imds_credentials_obtained", "aws_iam_keys_acquired"},
            impact=9.5,
            detection=[
                "169.254.169.254",
                "iam/security-credentials/",
            ],
        ),
        AttackUnit(
            "cloud_cred_exfil",
            "Extract IAM/instance credentials from cloud metadata",
            "extract_cloud_credentials()",
            preconditions={"imds_credentials_obtained"},
            postconditions={"cloud_credentials_exfiltrated"},
            impact=9.0,
            detection=["iam/security-credentials/", "computeMetadata/v1/"],
        ),
        AttackUnit(
            "cloud_resource_enum",
            "Enumerate accessible cloud resources using stolen creds",
            "cloud_resource_enumerate()",
            preconditions={"cloud_credentials_exfiltrated"},
            postconditions={"cloud_resources_enumerated", "sensitive_data_located"},
            impact=8.0,
            detection=["s3 ls", "gcloud storage ls", "az storage blob list"],
        ),

        # ── Authentication Bypass → GraphQL ───────────────────
        AttackUnit(
            "auth_bypass",
            "Authentication bypass via JWT manipulation or missing auth",
            "bypass_auth()",
            preconditions={"authenticated_endpoint", "jwt_auth_present"},
            postconditions={"auth_bypassed", "admin_access_granted"},
            impact=8.5,
        ),
        AttackUnit(
            "graphql_introspection",
            "Query GraphQL schema via introspection",
            "{__schema{types{name}}}",
            preconditions={"auth_bypassed", "graphql_endpoint_detected"},
            postconditions={"graphql_schema_obtained"},
            impact=7.5,
            detection=["{__schema{types{name}}}"],
        ),
        AttackUnit(
            "graphql_data_exfil",
            "Extract data via exposed GraphQL queries",
            "graphql_data_extract()",
            preconditions={"graphql_schema_obtained"},
            postconditions={"data_exfiltrated"},
            impact=8.0,
            detection=["query { ... }"],
        ),

        # ── SQL Injection → RCE ───────────────────────────────
        AttackUnit(
            "sqli_discovery",
            "SQL Injection — discover injectable parameter",
            "inject_sql_trigger(' OR 1=1--)",
            preconditions={"http_endpoint", "parameterized_query"},
            postconditions={"sqli_confirmed", "injectable_parameter_found"},
            impact=5.0,
            detection=["' OR 1=1--", "' AND 1=0 UNION SELECT"],
        ),
        AttackUnit(
            "sqli_data_exfil",
            "SQL Injection — extract data via UNION SELECT",
            "union_select_extract(schema, table, columns)",
            preconditions={"sqli_confirmed", "injectable_parameter_found"},
            postconditions={"database_data_obtained", "credentials_extracted"},
            impact=8.0,
        ),
        AttackUnit(
            "sqli_file_write",
            "Write webshell via INTO OUTFILE / COPY",
            "write_webshell_via_sqli()",
            preconditions={"sqli_confirmed", "file_write_privilege"},
            postconditions={"webshell_deployed", "file_system_access"},
            impact=9.0,
            detection=["INTO OUTFILE", "COPY (SELECT) TO"],
        ),
        AttackUnit(
            "webshell_exec",
            "Execute commands via uploaded webshell",
            "execute_command_via_webshell()",
            preconditions={"webshell_deployed"},
            postconditions={"rce_achieved", "os_command_execution"},
            impact=10.0,
            detection=["?cmd=id"],
        ),

        # ── LFI → RCE (Log Poisoning) ─────────────────────────
        AttackUnit(
            "lfi_discovery",
            "LFI — discover file inclusion parameter",
            "include_file(/etc/passwd)",
            preconditions={"http_endpoint", "file_parameter_exists"},
            postconditions={"lfi_confirmed", "file_read_capability"},
            impact=6.0,
        ),
        AttackUnit(
            "lfi_log_poison",
            "Inject PHP code into access/error logs",
            "inject_log_entry(<?php system($_GET['c']); ?>)",
            preconditions={"lfi_confirmed", "php_environment"},
            postconditions={"log_poisoned", "php_code_injected"},
            impact=8.5,
            detection=["<?php system($_GET['c']); ?>"],
        ),
        AttackUnit(
            "lfi_include_log",
            "Include poisoned log file via LFI to execute PHP",
            "include_file(/var/log/apache2/access.log&cmd=id)",
            preconditions={"log_poisoned", "lfi_confirmed"},
            postconditions={"rce_achieved", "os_command_execution"},
            impact=10.0,
            detection=["/var/log/apache2/access.log"],
        ),

        # ── Open Redirect → OAuth ─────────────────────────────
        AttackUnit(
            "open_redirect",
            "Open redirect discovered",
            "verify_redirect(url=https://evil.com)",
            preconditions={"http_endpoint", "redirect_parameter"},
            postconditions={"open_redirect_confirmed"},
            impact=3.0,
        ),
        AttackUnit(
            "oauth_redirect_chain",
            "Chain open redirect with OAuth callback URL",
            "craft_oauth_redirect(redirect_uri=https://app.com/redirect?url=https://evil.com)",
            preconditions={"open_redirect_confirmed", "oauth_flow_present"},
            postconditions={"oauth_code_intercepted"},
            impact=8.5,
            detection=[
                "redirect_uri=https://app.com/redirect?url=https://evil.com"
            ],
        ),
        AttackUnit(
            "oauth_token_intercept",
            "Intercept OAuth authorization code via redirect",
            "capture_oauth_code()",
            preconditions={"oauth_code_intercepted"},
            postconditions={"oauth_token_obtained", "account_takeover_possible"},
            impact=9.0,
        ),

        # ── AD → Cloud ────────────────────────────────────────
        AttackUnit(
            "ad_connect_sync",
            "Extract Azure AD Connect credentials from on-prem AD",
            "extract_adsync_credentials()",
            preconditions={"domain_admin_access", "azure_ad_connect_detected"},
            postconditions={"adsync_credentials_extracted"},
            impact=9.5,
            detection=["ADSync", "MSOL_Host MSOL_User"],
        ),
        AttackUnit(
            "cloud_sync_takeover",
            "Use sync account for cloud global admin",
            "escalate_to_cloud_global_admin()",
            preconditions={"adsync_credentials_extracted"},
            postconditions={"cloud_global_admin_obtained", "full_tenant_control"},
            impact=10.0,
            detection=["Azure AD Global Admin via sync account"],
        ),

        # ── General / Cross-cutting ───────────────────────────
        AttackUnit(
            "idor_discovery",
            "IDOR — discover object reference manipulation",
            "increment_sequential_id(/api/user/1 → /api/user/2)",
            preconditions={"authenticated_session", "sequential_identifier_pattern"},
            postconditions={"idor_confirmed", "unauthorized_data_access"},
            impact=7.5,
            detection=["GET /api/users/1", "GET /api/invoices/INV-001"],
        ),
        AttackUnit(
            "privesc_linux_kernel",
            "Linux kernel privilege escalation",
            "run_linux_exploit_suggestor()",
            preconditions={"shell_access", "linux_os"},
            postconditions={"root_access_obtained", "full_system_control"},
            impact=10.0,
        ),
        AttackUnit(
            "oss_cloud_cred_exposure",
            "Cloud credential exposure via SSRF or misconfiguration",
            "enumerate_cloud_credentials()",
            preconditions={"internal_resource_access", "cloud_environment_detected"},
            postconditions={"cloud_credentials_obtained", "cloud_console_access"},
            impact=9.5,
        ),
    ]

    for unit in units:
        ATTACK_UNIT_LIBRARY[unit.technique_id] = unit


_seed_units()


# ═══════════════════════════════════════════════════════════════
# CHAIN SYNTHESIZER
# ═══════════════════════════════════════════════════════════════

class ChainSynthesizer:
    """
    Synthesizes novel exploitation chains from partial findings.
    
    Upgraded v2 with Attack-Unit methodology:
      1. Maps confirmed findings to AttackUnits (preconditions→postconditions)
      2. BFS through unit dependency graph to find all reachable chains
      3. Scores chains by length × total_impact
      4. Suggests next steps by readiness (precondition satisfaction)
      5. Generates Datalog-style reachability rules (from the CTI paper)
    
    Preserves v1's chain templates + novel cross-domain synthesis.
    """

    def __init__(self, growth_db=None):
        self._growth_db = growth_db
        self.library = dict(ATTACK_UNIT_LIBRARY)  # Copy, extendable

        # v1 chain templates preserved for backward compatibility
        self._chain_templates = [
            {
                "id": "chain_ssrf_imds_cloud",
                "name": "SSRF → Cloud Metadata → Credential Exposure",
                "trigger_classes": ["SSRF"],
                "required_target_features": ["aws", "gcp", "azure", "cloud"],
                "steps": [
                    {"technique_id": "ssrf_imds_aws",
                     "description": "SSRF to cloud metadata service",
                     "detection": ["169.254.169.254", "metadata.google.internal",
                                   "169.254.169.254/metadata/instance"]},
                    {"technique_id": "cloud_cred_exfil",
                     "description": "Extract IAM/instance credentials",
                     "detection": ["iam/security-credentials/", "computeMetadata/v1/"]},
                    {"technique_id": "cloud_resource_enum",
                     "description": "Enumerate accessible cloud resources",
                     "detection": ["s3 ls", "gcloud storage ls", "az storage blob list"]},
                ],
                "estimated_cvss": 9.5,
            },
            {
                "id": "chain_auth_bypass_graphql",
                "name": "Auth Bypass → GraphQL Introspection → Data Model Enumeration",
                "trigger_classes": ["Authentication Bypass"],
                "required_target_features": ["graphql"],
                "steps": [
                    {"technique_id": "graphql_introspection",
                     "description": "Query GraphQL schema via introspection",
                     "detection": ["{__schema{types{name}}}"], },
                    {"technique_id": "graphql_data_exfil",
                     "description": "Extract data via exposed queries",
                     "detection": ["query { ... }"]},
                ],
                "estimated_cvss": 8.0,
            },
            {
                "id": "chain_sqli_to_rce",
                "name": "SQL Injection → File Write → Remote Code Execution",
                "trigger_classes": ["SQL Injection"],
                "required_target_features": ["mysql", "mariadb", "postgresql"],
                "steps": [
                    {"technique_id": "sqli_file_write",
                     "description": "Write webshell via INTO OUTFILE / COPY",
                     "detection": ["INTO OUTFILE", "COPY (SELECT) TO"]},
                    {"technique_id": "webshell_exec",
                     "description": "Execute commands via uploaded webshell",
                     "detection": ["?cmd=id"]},
                ],
                "estimated_cvss": 9.0,
            },
            {
                "id": "chain_lfi_to_rce",
                "name": "LFI → Log Poisoning → Remote Code Execution",
                "trigger_classes": ["LFI", "File Inclusion"],
                "required_target_features": ["php", "nginx", "apache"],
                "steps": [
                    {"technique_id": "lfi_log_poison",
                     "description": "Inject PHP code into access/error logs",
                     "detection": ["<?php system($_GET['c']); ?>"]},
                    {"technique_id": "lfi_include_log",
                     "description": "Include poisoned log file via LFI",
                     "detection": ["/var/log/apache2/access.log",
                                   "/var/log/nginx/access.log"]},
                ],
                "estimated_cvss": 8.5,
            },
            {
                "id": "chain_open_redirect_oauth",
                "name": "Open Redirect → OAuth Token Theft → Account Takeover",
                "trigger_classes": ["Open Redirect"],
                "required_target_features": ["oauth", "oauth2", "sso"],
                "steps": [
                    {"technique_id": "oauth_redirect_chain",
                     "description": "Chain open redirect with OAuth callback",
                     "detection": [
                         "redirect_uri=https://app.com/redirect?url=https://evil.com"]},
                    {"technique_id": "oauth_token_intercept",
                     "description": "Intercept OAuth authorization code",
                     "detection": ["?code=... in redirect"]},
                ],
                "estimated_cvss": 8.5,
            },
            {
                "id": "chain_ad_to_cloud",
                "name": "AD Compromise → Hybrid Cloud Takeover",
                "trigger_classes": ["AD Compromise", "Domain Admin"],
                "required_target_features": ["azure", "azuread", "entra",
                                              "365", "office365"],
                "steps": [
                    {"technique_id": "ad_connect_sync",
                     "description": "Extract Azure AD Connect credentials",
                     "detection": ["ADSync", "MSOL_Host MSOL_User"]},
                    {"technique_id": "cloud_sync_takeover",
                     "description": "Use sync account for cloud admin",
                     "detection": ["Azure AD Global Admin via sync account"]},
                ],
                "estimated_cvss": 9.5,
            },
        ]

        self._load_from_kb()

    def _load_from_kb(self):
        """Extend attack unit library from the knowledge base."""
        if not self._growth_db:
            return

        try:
            kb_techniques = self._growth_db.get_techniques(
                limit=500
            ) if hasattr(self._growth_db, 'get_techniques') else []
        except Exception:
            kb_techniques = []

        for tech in kb_techniques:
            tid = tech.get("technique_id", "")
            if not tid or tid in self.library:
                continue

            preconditions = set()
            for profile in tech.get("target_profiles", []):
                if isinstance(profile, str):
                    for component in profile.split("+"):
                        c = component.strip().lower()
                        if c in ("nginx", "apache", "iis", "caddy"):
                            preconditions.add("http_endpoint")
                        elif c in ("jwt", "oauth", "sso"):
                            preconditions.add("jwt_auth_present")
                        elif c in ("aws", "gcp", "azure"):
                            preconditions.add("cloud_environment_detected")
                        elif c in ("postgresql", "mysql", "mssql", "sqlite"):
                            preconditions.add("database_backend")

            postconditions = set()
            cls = tech.get("class", "").lower()
            if "rce" in cls or "remote code" in cls:
                postconditions.add("rce_achieved")
                postconditions.add("os_command_execution")
            elif "ssrf" in cls:
                postconditions.add("ssrf_confirmed")
                postconditions.add("internal_resource_access")
            elif "auth" in cls or "bypass" in cls:
                postconditions.add("auth_bypassed")
            elif "sqli" in cls or "sql injection" in cls:
                postconditions.add("sqli_confirmed")
            elif "idor" in cls or "access control" in cls:
                postconditions.add("unauthorized_data_access")

            unit = AttackUnit(
                tid,
                tech.get("name", tid),
                f"execute_{tid}()",
                preconditions or {"unknown_precondition"},
                postconditions or {"finding_confirmed"},
                impact=tech.get("cvss_min", 5.0),
                detection=tech.get("detection", []),
            )
            self.library[tid] = unit

        logger.debug("Loaded %d units from KB into library", len(kb_techniques))

    # ── v1 API (backward compatible) ──────────────────────────

    def synthesize(self, confirmed_findings: list[dict],
                   target_features: list[str]) -> list[dict]:
        """
        Generate exploitation chains from confirmed findings.
        
        v1 method: uses chain templates.
        v2 upgrade: also runs BFS through attack unit graph.
        Returns merged list.
        """
        chains = self._synthesize_from_templates(confirmed_findings, target_features)
        bfs_chains = self._synthesize_from_units(confirmed_findings, target_features)

        # Merge chains from both methods, dedup by chain_id
        seen_ids = {c["chain_id"] for c in chains}
        for bf in bfs_chains:
            if bf["chain_id"] not in seen_ids:
                chains.append(bf)
                seen_ids.add(bf["chain_id"])

        # Also add v1 novel chains
        target_set = set(f.lower().replace(" ", "") for f in target_features)
        novel_chains = self._synthesize_novel(confirmed_findings, target_set)
        # Merge keeping chain_id uniqueness
        for nc in novel_chains:
            if nc["chain_id"] not in seen_ids:
                chains.append(nc)
                seen_ids.add(nc["chain_id"])

        chains.sort(key=lambda c: c.get("confidence", 0), reverse=True)
        return chains

    def _synthesize_from_templates(self, findings: list[dict],
                                   target_features: list[str]) -> list[dict]:
        """v1 template-based chain synthesis."""
        confirmed_classes = set(f.get("class", "") for f in findings)
        confirmed_techniques = set(f.get("technique_id", "") for f in findings)
        target_set = set(f.lower().replace(" ", "") for f in target_features)

        chains = []

        for template in self._chain_templates:
            trigger_matched = any(
                tc.lower() in confirmed_classes
                or tc.lower().replace(" ", "_") in confirmed_classes
                for tc in template["trigger_classes"]
            )
            if not trigger_matched:
                continue

            feature_matched = any(
                tf in target_set for tf in template["required_target_features"]
            )
            feature_match_ratio = 1.0 if feature_matched else 0.3

            steps_confirmed = sum(
                1 for step in template["steps"]
                if step["technique_id"] in confirmed_techniques
            )
            total_steps = len(template["steps"]) or 1
            completion = steps_confirmed / total_steps
            confidence = (0.4 * 1.0) + (0.3 * feature_match_ratio) + (0.3 * completion)

            chains.append({
                "chain_id": template["id"],
                "name": template["name"],
                "confidence": round(confidence, 3),
                "estimated_cvss": template["estimated_cvss"],
                "completion": f"{steps_confirmed}/{total_steps}",
                "steps_confirmed": steps_confirmed,
                "steps_remaining": total_steps - steps_confirmed,
                "steps": template["steps"],
                "trigger_classes": template["trigger_classes"],
                "is_novel": steps_confirmed == 0,
            })

        return chains

    def _synthesize_from_units(self, findings: list[dict],
                                target_features: list[str]) -> list[dict]:
        """v2 Attack-Unit BFS chain synthesis."""
        confirmed_ids = [
            f.get("technique_id", "") for f in findings
            if f.get("technique_id", "")
        ]

        if not confirmed_ids:
            return []

        bfs_chains = self.find_chains(confirmed_ids)

        result = []
        for bfc in bfs_chains:
            chain_id = f"unit_chain_{'_'.join(bfc['path'][:3])}_{int(time.time())}"
            steps = []
            for tid in bfc["path"]:
                unit = self.library.get(tid)
                if unit:
                    steps.append({
                        "technique_id": tid,
                        "description": unit.name,
                        "detection": unit.detection,
                    })

            result.append({
                "chain_id": chain_id,
                "name": " → ".join(
                    self.library.get(tid, AttackUnit(tid, tid, "", set(), set())).name
                    for tid in bfc["path"][:4]
                ),
                "confidence": round(
                    min(1.0, bfc["total_impact"] / 30.0), 3
                ),
                "estimated_cvss": round(
                    min(10.0, bfc["total_impact"] / len(bfc["path"])), 1
                ),
                "completion": f"0/{len(bfc['path'])}",
                "steps_confirmed": 0,
                "steps_remaining": len(bfc["path"]),
                "steps": steps,
                "trigger_classes": list(set(
                    self.library.get(tid).__class__.__name__
                    for tid in bfc["path"] if tid in self.library
                )),
                "is_novel": True,
                "synthesis_note": "Attack-Unit BFS chain (v2 methodology)",
            })

        return result

    def _synthesize_novel(self, findings: list[dict],
                          target_features: set) -> list[dict]:
        """v1 novel chain synthesis (cross-domain heuristics)."""
        confirmed_classes = set(f.get("class", "") for f in findings)
        confirmed_techniques = set(f.get("technique_id", "") for f in findings)

        novel = []

        internal_access_classes = {"SSRF", "LFI", "RCE", "File Read"}
        if (confirmed_classes & internal_access_classes
                and {"aws", "gcp", "azure", "cloud"} & target_features):
            chain = {
                "chain_id": f"novel_internal_to_cloud_{int(time.time())}",
                "name": "Internal Access → Cloud Metadata Probe (Novel)",
                "confidence": 0.55,
                "estimated_cvss": 8.5,
                "completion": "0/2",
                "steps_confirmed": 0,
                "steps_remaining": 2,
                "steps": [
                    {"technique_id": "probe_imds",
                     "description": "Probe cloud metadata endpoints via internal access",
                     "detection": ["curl http://169.254.169.254/",
                                   "curl http://metadata.google.internal/"]},
                    {"technique_id": "cred_exfil",
                     "description": "Extract and use cloud credentials",
                     "detection": ["iam/security-credentials/",
                                   "computeMetadata/v1/"]},
                ],
                "trigger_classes": list(internal_access_classes),
                "is_novel": True,
                "synthesis_note": "Cross-domain: internal access on cloud target",
            }
            novel.append(chain)

        if "Authentication Bypass" in confirmed_classes and {"api", "rest",
                                                              "graphql"} & target_features:
            chain = {
                "chain_id": f"novel_auth_bypass_api_exfil_{int(time.time())}",
                "name": "Auth Bypass → Full API Data Exfil (Novel)",
                "confidence": 0.60,
                "estimated_cvss": 8.0,
                "completion": "0/2",
                "steps_confirmed": 0,
                "steps_remaining": 2,
                "steps": [
                    {"technique_id": "api_endpoint_enum",
                     "description": "Enumerate all API endpoints",
                     "detection": ["/swagger.json", "/api/docs", "/openapi.json"]},
                    {"technique_id": "api_data_harvest",
                     "description": "Harvest data from accessible endpoints",
                     "detection": ["GET /api/users", "GET /api/orders"]},
                ],
                "trigger_classes": ["Authentication Bypass"],
                "is_novel": True,
                "synthesis_note": "Cross-domain: auth bypass on API target",
            }
            novel.append(chain)

        return novel

    # ── v2 Attack-Unit public API ─────────────────────────────

    def find_chains(self, confirmed_technique_ids: list[str]) -> list[dict]:
        """
        Find all possible chains from confirmed techniques using BFS.
        Returns chains sorted by (length × total_impact).
        """
        confirmed_units = []
        for tid in confirmed_technique_ids:
            unit = self.library.get(tid)
            if unit:
                confirmed_units.append(unit)

        if not confirmed_units:
            return []

        achieved_conditions = set()
        for unit in confirmed_units:
            achieved_conditions.update(unit.postconditions)

        logger.info(
            "Chain BFS: %d confirmed units, %d achieved conditions",
            len(confirmed_units),
            len(achieved_conditions),
        )

        visited = set(confirmed_technique_ids)
        all_chains = []

        for start_tid in confirmed_technique_ids:
            start_unit = self.library.get(start_tid)
            if not start_unit:
                continue

            chains = self._bfs_chain(
                current_id=start_tid,
                current_unit=start_unit,
                achieved_conditions=set(achieved_conditions),
                visited=set(visited),
                depth=0,
                max_depth=5,
                path=[start_tid],
            )
            all_chains.extend(chains)

        seen = set()
        scored = []
        for chain in all_chains:
            key = "→".join(chain["path"])
            if key in seen:
                continue
            seen.add(key)
            chain["score"] = len(chain["path"]) * chain["total_impact"]
            scored.append(chain)

        scored.sort(key=lambda c: c["score"], reverse=True)

        logger.info("Chain BFS: %d unique chains (max depth %d)",
                     len(scored),
                     max(len(c["path"]) for c in scored) if scored else 0)
        return scored

    def _bfs_chain(self, current_id: str, current_unit: AttackUnit,
                    achieved_conditions: set, visited: set,
                    depth: int, max_depth: int, path: list[str]) -> list[dict]:
        """BFS to find all chains starting from current unit."""
        if depth >= max_depth:
            return [{
                "path": list(path),
                "total_impact": sum(
                    self.library.get(tid, current_unit).impact
                    for tid in path if tid in self.library
                ),
                "length": len(path),
                "terminal_conditions": list(achieved_conditions),
            }]

        new_conditions = achieved_conditions | current_unit.postconditions

        candidates = []
        for tid, unit in self.library.items():
            if tid in visited:
                continue
            if unit.preconditions.issubset(new_conditions):
                candidates.append((tid, unit))

        if not candidates:
            return [{
                "path": list(path),
                "total_impact": sum(
                    self.library.get(tid, current_unit).impact
                    for tid in path if tid in self.library
                ),
                "length": len(path),
                "terminal_conditions": list(new_conditions),
            }]

        chains = []
        for next_tid, next_unit in candidates:
            visited.add(next_tid)
            sub = self._bfs_chain(
                current_id=next_tid,
                current_unit=next_unit,
                achieved_conditions=new_conditions,
                visited=visited,
                depth=depth + 1,
                max_depth=max_depth,
                path=path + [next_tid],
            )
            chains.extend(sub)
            visited.discard(next_tid)

        return chains

    def suggest_next_steps(self, confirmed_technique_ids: list[str]) -> list[dict]:
        """
        Given what's confirmed, what should the Student try next?
        Returns (technique_id, name, readiness, expected_value) sorted.
        """
        achieved_conditions = set()
        for tid in confirmed_technique_ids:
            unit = self.library.get(tid)
            if unit:
                achieved_conditions.update(unit.postconditions)

        suggestions = []
        for tid, unit in self.library.items():
            if tid in confirmed_technique_ids:
                continue

            satisfied = unit.preconditions & achieved_conditions
            missing = unit.preconditions - achieved_conditions
            readiness = len(satisfied) / max(len(unit.preconditions), 1)

            if readiness > 0.3:
                suggestions.append({
                    "technique_id": tid,
                    "name": unit.name,
                    "readiness": round(readiness, 2),
                    "satisfied": list(satisfied),
                    "missing": list(missing),
                    "impact": unit.impact,
                    "expected_value": round(readiness * unit.impact, 2),
                })

        suggestions.sort(key=lambda s: s["expected_value"], reverse=True)

        if suggestions:
            logger.info("Top next steps:")
            for s in suggestions[:5]:
                logger.info(
                    "  [%d%% ready] %s (expected value: %.1f)",
                    int(s["readiness"] * 100), s["name"], s["expected_value"],
                )

        return suggestions

    def generate_datalog_rules(self) -> list[str]:
        """
        (From the CTI paper) Generate Datalog-style reachability rules.
        
        Rule format:
          reachable(Target, Path) :-
            achieved(InitialCondition),
            attack_unit(Unit1, Pre1, Post1),
            subset(Pre2, Post1),
            ...
        
        Can be loaded into a Datalog engine for formal reachability analysis.
        """
        rules = []

        for tid, unit in self.library.items():
            for i, post in enumerate(unit.postconditions):
                rules.append(
                    f"achieved_on_path('{post}', Path) :- "
                    f"on_path('{tid}', Path), "
                    f"path_position('{tid}', Pos, Path)"
                )

        for tid_a, unit_a in self.library.items():
            for tid_b, unit_b in self.library.items():
                if tid_a == tid_b:
                    continue
                if unit_b.preconditions.issubset(unit_a.postconditions):
                    rules.append(
                        f"reachable('{tid_b}', ['{tid_a}', '{tid_b}']) :- "
                        f"achieved('{list(unit_a.postconditions)[0]}')"
                    )

        return rules

    # ── S1-B: Planner Readiness Adapter ────────────────────────

    def get_readiness_map(self, confirmed_technique_ids: list[str] = None) -> dict[str, float]:
        """S1-B: Build a technique_id → readiness map for the Planner.
        
        Thin wrapper around suggest_next_steps() that produces the exact
        format the Planner's chain_readiness scoring consumes.
        
        Args:
            confirmed_technique_ids: Technique IDs confirmed from evidence/hypotheses.
                Used to determine which preconditions are already satisfied.
        
        Returns:
            Dict mapping technique_id → readiness (0.0-1.0)
        """
        suggestions = self.suggest_next_steps(confirmed_technique_ids or [])
        return {
            s["technique_id"]: s["readiness"]
            for s in suggestions
            if s.get("readiness", 0) > 0
        }

    # ── Introspection ─────────────────────────────────────────

    def stats(self) -> dict:
        return {
            "chain_templates": len(self._chain_templates),
            "attack_units": len(self.library),
            "trigger_classes": list(set(
                tc for t in self._chain_templates for tc in t["trigger_classes"]
            )),
        }
