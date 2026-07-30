"""
shell_generator.py — Shell Candidate Generator (E2)

Converts trigger conditions (T1 Credential Discovery, T2 Exploit Confirmation,
T3 Chain Advisory) into standard Candidate dicts for the Planner.

Architecture:
    WorldModel + HypothesisManager + ChainSynthesizer
        → ShellCandidateGenerator.generate_connect_candidates(targets, context)
            → list[dict] (shell_connect candidates for Planner.decide())
        → ShellCandidateGenerator.generate_command_candidates(active_sessions, objective)
            → list[dict] (shell_command candidates for Planner.decide())
        → ShellCandidateGenerator.generate_disconnect_candidates(active_sessions)
            → list[dict] (shell_disconnect candidates for Planner.decide())

Schema version: 1
"""

import logging
import uuid
from typing import Any, Optional

from orchestrator.brain.world import WorldModel, EntityType, RelationshipType
from orchestrator.brain.evidence import EvidenceGraph
from orchestrator.brain.hypothesis import HypothesisManager, HypothesisStatus

logger = logging.getLogger("candidate_generators.shell")

# ── Candidate Origin Markers ─────────────────────────────────────
CANDIDATE_ORIGIN_SHELL_TRIGGER = "SHELL_TRIGGER"
CANDIDATE_ORIGIN_SHELL_COMMAND = "SHELL_COMMAND_OBJECTIVE"
CANDIDATE_ORIGIN_SHELL_LIFECYCLE = "SHELL_LIFECYCLE"

# ── Objective → Command Map (INV-E2-06: Hardcoded Source of Truth) ──
# Every command here has been vetted. No dynamic command construction.
OBJECTIVE_COMMAND_MAP: dict[str, list[dict]] = {
    "privilege_escalation": [
        {"command": "sudo -l", "evidence_type": "file_content",
         "rationale": "Check sudo permissions"},
        {"command": "find / -type f -perm -4000 2>/dev/null",
         "evidence_type": "vulnerability_indicator",
         "rationale": "Find SUID binaries for privesc"},
        {"command": "cat /etc/shadow",
         "evidence_type": "credential",
         "rationale": "Extract password hashes"},
        {"command": "uname -a",
         "evidence_type": "vulnerability_indicator",
         "rationale": "Kernel version for exploit matching"},
        {"command": "cat /etc/passwd",
         "evidence_type": "user_accounts",
         "rationale": "List user accounts"},
        {"command": "cat /etc/sudoers 2>/dev/null",
         "evidence_type": "file_content",
         "rationale": "Check sudo configuration"},
        {"command": "getcap -r / 2>/dev/null",
         "evidence_type": "vulnerability_indicator",
         "rationale": "Find file capabilities for privesc"},
    ],
    "lateral_movement": [
        {"command": "ip addr",
         "evidence_type": "network_connections",
         "rationale": "Network interfaces for pivot targets"},
        {"command": "netstat -tlnp 2>/dev/null || ss -tlnp",
         "evidence_type": "network_connections",
         "rationale": "Listening services for pivot targets"},
        {"command": "cat ~/.ssh/id_rsa 2>/dev/null",
         "evidence_type": "credential",
         "rationale": "Extract SSH keys for lateral movement"},
        {"command": "cat ~/.ssh/authorized_keys 2>/dev/null",
         "evidence_type": "credential",
         "rationale": "List authorized SSH keys"},
        {"command": "cat ~/.bash_history 2>/dev/null",
         "evidence_type": "credential",
         "rationale": "Extract credentials from history"},
        {"command": "arp -a 2>/dev/null || ip neigh",
         "evidence_type": "network_connections",
         "rationale": "ARP table for lateral targets"},
        {"command": "cat /etc/hosts",
         "evidence_type": "file_content",
         "rationale": "Host resolution for lateral targets"},
    ],
    "credential_access": [
        {"command": "cat /etc/shadow",
         "evidence_type": "credential",
         "rationale": "Extract password hashes"},
        {"command": "env | grep -i -E 'pass|key|token|secret'",
         "evidence_type": "credential",
         "rationale": "Extract credentials from environment"},
        {"command": "find / -name '*.kdbx' -o -name '*.kdb' 2>/dev/null",
         "evidence_type": "file_content",
         "rationale": "Find KeePass databases"},
        {"command": "cat /etc/ssh/sshd_config 2>/dev/null",
         "evidence_type": "file_content",
         "rationale": "Extract SSH config"},
        {"command": "cat ~/.ssh/config 2>/dev/null",
         "evidence_type": "credential",
         "rationale": "Extract SSH client config"},
    ],
    "persistence": [
        {"command": "id",
         "evidence_type": "command_output",
         "rationale": "Current user context"},
        {"command": "cat /etc/crontab 2>/dev/null",
         "evidence_type": "file_content",
         "rationale": "Check crontab for persistence hooks"},
        {"command": "ls -la /etc/init.d/ /etc/systemd/system/ 2>/dev/null",
         "evidence_type": "file_content",
         "rationale": "List system services"},
        {"command": "cat /etc/rc.local 2>/dev/null",
         "evidence_type": "file_content",
         "rationale": "Check rc.local for startup hooks"},
        {"command": "systemctl list-units --type=service --state=running 2>/dev/null || echo 'no systemd'",
         "evidence_type": "command_output",
         "rationale": "List running services"},
    ],
    "reconnaissance": [
        {"command": "id",
         "evidence_type": "command_output",
         "rationale": "Current user context"},
        {"command": "hostnamectl 2>/dev/null || cat /etc/hostname",
         "evidence_type": "command_output",
         "rationale": "Hostname and OS details"},
        {"command": "ls -la /root/ /home/ 2>/dev/null",
         "evidence_type": "file_content",
         "rationale": "List user home directories"},
        {"command": "cat /etc/group",
         "evidence_type": "user_accounts",
         "rationale": "Group memberships"},
        {"command": "w 2>/dev/null || who",
         "evidence_type": "user_accounts",
         "rationale": "Currently logged-in users"},
        {"command": "cat /etc/*release 2>/dev/null | head -5",
         "evidence_type": "command_output",
         "rationale": "OS release information"},
    ],
    "exfiltration": [
        {"command": "ls -la /tmp/",
         "evidence_type": "file_content",
         "rationale": "Check temp for sensitive files"},
        {"command": "df -h",
         "evidence_type": "command_output",
         "rationale": "Disk usage for staging capacity"},
        {"command": "find / -name '*.sql' -o -name '*.dump' -o -name '*.bak' 2>/dev/null | head -20",
         "evidence_type": "file_content",
         "rationale": "Find database dumps and backups"},
        {"command": "ls -la /var/backups/ 2>/dev/null",
         "evidence_type": "file_content",
         "rationale": "Check backup directories"},
    ],
}

# ── Trigger templates ────────────────────────────────────────────

def _check_t1_credential_discovery(
    world: WorldModel,
    evidence_graph: EvidenceGraph,
    targets: list[str],
) -> list[dict]:
    """T1: Credential Discovery — valid SSH/WinRM credentials + open service → shell_connect.

    Evaluates:
    1. WorldModel has CREDENTIAL entities with 'ssh:' or 'winrm:' identifier prefix
    2. Those credentials have AUTHENTICATES_AS relationship to an IDENTITY
    3. The target ASSET has a SERVICE entity of type 'ssh' or 'winrm'
    4. No active SHELL_SESSION exists for the target
    """
    if not world:
        return []

    candidates = []
    credentials = world.get_entities_by_type(EntityType.CREDENTIAL)

    for cred in credentials:
        pid = cred.primary_identifier or ""
        # Check for SSH/WinRM credential types
        if not (pid.startswith("ssh:") or pid.startswith("winrm:")):
            continue
        if "password" in cred.identifiers.get("type", ""):
            continue  # Skip password-based for now (requires interactive)

        # Find authenticates_as relationships to get identity
        # AUTHENTICATES_AS goes FROM identity TO credential,
        # so we search by target=cred.entity_id
        rels = world.get_relationships(
            target=cred.entity_id,
            rel_type=RelationshipType.AUTHENTICATES_AS,
        )
        if not rels:
            # Try source direction as fallback (some callers may reverse)
            rels = world.get_relationships(
                source=cred.entity_id,
                rel_type=RelationshipType.AUTHENTICATES_AS,
            )
        if not rels:
            continue
        # When querying by target=cred.entity_id, identity is the source
        identity_id = rels[0].source_entity_id

        # Determine target: use credential's target identifier or the identity's asset
        target_ip = cred.identifiers.get("target", "")
        if not target_ip and targets:
            # Fallback: use first in-scope target
            target_ip = targets[0]
        if not target_ip:
            continue

        # INV-E2-03: Check no active SHELL_SESSION for target
        if _has_active_session(world, target_ip):
            continue

        username = cred.identifiers.get("username", "root")
        candidate = {
            "action_type": "shell_connect",
            "capability": "ssh_shell",
            "target": target_ip,
            "method": "credential_auth",
            "origin": CANDIDATE_ORIGIN_SHELL_TRIGGER,
            "action_id": f"shell_connect_{target_ip}_cred_{uuid.uuid4().hex[:6]}",
            "rationale": f"T1:Credential Discovery — {username}@{target_ip} via {pid}",
            "session_proposal": {
                "target": target_ip,
                "capability": "ssh_shell",
                "parameters": {
                    "username": username,
                    "auth_method": "key" if "key" in cred.identifiers.get("type", "") else "password",
                    "max_duration": 3600,
                    "idle_timeout": 300,
                },
            },
            "technique_id": "T1_CREDENTIAL_DISCOVERY",
            "impact_estimate": 8.0,
            "confidence": 0.7,
            "candidate_origin": CANDIDATE_ORIGIN_SHELL_TRIGGER,
            "_is_falsification": False,
            "derived_from_world_query_ids": (),
        }
        candidates.append(candidate)

    return candidates


def _check_t2_exploit_confirmation(
    world: WorldModel,
    hypothesis_manager: HypothesisManager,
    evidence_graph: EvidenceGraph,
    targets: list[str],
) -> list[dict]:
    """T2: Exploit Confirmation — CONFIRMED RCE hypothesis → shell_connect with reverse shell.

    Evaluates:
    1. HypothesisManager has hypotheses with status CONFIRMED
    2. Those hypotheses mention RCE/code_execution/remote_access
    3. Target ASSET exists in WorldModel
    4. No active SHELL_SESSION exists for the target
    """
    if not hypothesis_manager or not world:
        return []

    candidates = []
    hypotheses = getattr(hypothesis_manager, 'hypotheses', {})

    rce_keywords = ["rce", "code_execution", "remote_access", "remote_code",
                    "shell", "command_injection", "deserialization"]

    for hid, hyp in hypotheses.items():
        hyp_status = getattr(hyp, 'status', None)
        status_str = hyp_status.value if hasattr(hyp_status, 'value') else str(hyp_status) if hyp_status else ""
        if status_str != "confirmed":
            continue

        statement = getattr(hyp, 'statement', "") or ""
        statement_lower = statement.lower()
        if not any(kw in statement_lower for kw in rce_keywords):
            continue

        # Get target from hypothesis entity_ids
        target_ip = ""
        entity_ids = getattr(hyp, 'entity_ids', [])
        for eid in entity_ids:
            entity = world.get_entity(eid)
            if entity and entity.entity_type == EntityType.ASSET:
                target_ip = entity.primary_identifier
                break
        if not target_ip and targets:
            target_ip = targets[0]
        if not target_ip:
            continue

        # INV-E2-03: Check no active SHELL_SESSION for target
        if _has_active_session(world, target_ip):
            continue

        vuln_id = hid[:12]
        candidate = {
            "action_type": "shell_connect",
            "capability": "reverse_shell",
            "target": target_ip,
            "method": "payload_injection",
            "origin": CANDIDATE_ORIGIN_SHELL_TRIGGER,
            "action_id": f"shell_connect_{target_ip}_rce_{uuid.uuid4().hex[:6]}",
            "rationale": f"T2:Exploit Confirmation — RCE confirmed on {target_ip} via {vuln_id}, deploying reverse shell",
            "session_proposal": {
                "target": target_ip,
                "capability": "reverse_shell",
                "parameters": {
                    "auth_method": "reverse_tcp",
                    "max_duration": 3600,
                    "idle_timeout": 300,
                },
            },
            "technique_id": "T2_EXPLOIT_CONFIRMATION",
            "impact_estimate": 9.0,
            "confidence": 0.8,
            "candidate_origin": CANDIDATE_ORIGIN_SHELL_TRIGGER,
            "_is_falsification": False,
            "derived_from_world_query_ids": (),
        }
        candidates.append(candidate)

    return candidates


def _check_t3_chain_advisory(
    world: WorldModel,
    chain_synthesizer: Any,
    confirmed_technique_ids: list[str],
    targets: list[str],
) -> list[dict]:
    """T3: Chain Advisory — ChainSynthesizer suggests shell as next step.

    Evaluates:
    1. ChainSynthesizer.suggest_next_steps() returns a technique with
       'shell_access_established' in its postconditions
    2. The target ASSET is in-scope
    3. No active SHELL_SESSION exists for target
    """
    if not chain_synthesizer or not hasattr(chain_synthesizer, 'suggest_next_steps'):
        return []

    candidates = []
    try:
        suggestions = chain_synthesizer.suggest_next_steps(confirmed_technique_ids or [])
    except Exception:
        return []

    shell_technique_ids = []
    for s in suggestions:
        tid = s.get("technique_id", "")
        if "shell" in tid.lower() or "connect" in tid.lower():
            shell_technique_ids.append((tid, s.get("readiness", 0.0), s.get("impact", 5.0)))

    if not shell_technique_ids:
        return []

    # Use first in-scope target
    target_ip = targets[0] if targets else "unknown"
    if _has_active_session(world, target_ip):
        return []

    for tid, readiness, impact in shell_technique_ids:
        candidate = {
            "action_type": "shell_connect",
            "capability": "ssh_shell",
            "target": target_ip,
            "method": "chain_advisory",
            "origin": CANDIDATE_ORIGIN_SHELL_TRIGGER,
            "action_id": f"shell_connect_{target_ip}_chain_{uuid.uuid4().hex[:6]}",
            "rationale": f"T3:Chain Advisory — {tid} readiness={readiness:.2f} — shell access required",
            "session_proposal": {
                "target": target_ip,
                "capability": "ssh_shell",
                "parameters": {
                    "auth_method": "key",
                    "max_duration": 3600,
                    "idle_timeout": 300,
                },
            },
            "technique_id": tid,
            "impact_estimate": impact,
            "confidence": readiness,
            "candidate_origin": CANDIDATE_ORIGIN_SHELL_TRIGGER,
            "_is_falsification": False,
            "derived_from_world_query_ids": (),
        }
        candidates.append(candidate)

    return candidates


def _has_active_session(world: WorldModel, target_ip: str) -> bool:
    """INV-E2-03: Check if target already has an active SHELL_SESSION."""
    if not world:
        return False
    sessions = world.get_entities_by_type(EntityType.SHELL_SESSION)
    for sess in sessions:
        if sess.identifiers.get("target", "") == target_ip:
            # Check if session is still active (active flag)
            if getattr(sess, 'active', True):
                return True
    return False


def _get_active_sessions(world: WorldModel) -> list[tuple[str, str, str]]:
    """Get list of (session_id, target_ip, capability_type) for active sessions."""
    if not world:
        return []
    active = []
    sessions = world.get_entities_by_type(EntityType.SHELL_SESSION)
    for sess in sessions:
        if getattr(sess, 'active', True):
            active.append((
                sess.primary_identifier,
                sess.identifiers.get("target", ""),
                sess.identifiers.get("capability_type", "ssh_shell"),
            ))
    return active


# ── Public Generator Class ──────────────────────────────────────

class ShellCandidateGenerator:
    """
    Generates shell-related Candidate dicts for the Planner.

    Three generation modes:
    1. generate_connect_candidates() — shell_connect from trigger conditions
    2. generate_command_candidates() — shell_command for active sessions
    3. generate_disconnect_candidates() — shell_disconnect for cleanup

    All candidates route through CapabilityBroker at execution time (INV-E2-01).
    """

    def __init__(self, chain_synthesizer=None):
        self.chain_synthesizer = chain_synthesizer

    def generate_connect_candidates(
        self,
        world: Optional[WorldModel] = None,
        evidence_graph: Optional[EvidenceGraph] = None,
        hypothesis_manager: Optional[HypothesisManager] = None,
        targets: Optional[list[str]] = None,
        confirmed_technique_ids: Optional[list[str]] = None,
    ) -> list[dict]:
        """Evaluate T1, T2, T3 triggers and return shell_connect candidates.

        Args:
            world: WorldModel for entity lookups
            evidence_graph: EvidenceGraph for evidence queries
            hypothesis_manager: HypothesisManager for CONFIRMED hypotheses
            targets: List of in-scope target IPs
            confirmed_technique_ids: Technique IDs confirmed from evidence

        Returns:
            List of shell_connect candidate dicts for Planner.decide()
        """
        targets = targets or []
        candidates = []

        # T1: Credential Discovery
        try:
            t1 = _check_t1_credential_discovery(world, evidence_graph, targets)
            candidates.extend(t1)
        except Exception as e:
            logger.debug("[ShellGenerator] T1 error: %s", e)

        # T2: Exploit Confirmation
        try:
            t2 = _check_t2_exploit_confirmation(world, hypothesis_manager, evidence_graph, targets)
            candidates.extend(t2)
        except Exception as e:
            logger.debug("[ShellGenerator] T2 error: %s", e)

        # T3: Chain Advisory
        try:
            t3 = _check_t3_chain_advisory(
                world, self.chain_synthesizer, confirmed_technique_ids, targets,
            )
            candidates.extend(t3)
        except Exception as e:
            logger.debug("[ShellGenerator] T3 error: %s", e)

        if candidates:
            logger.info("[ShellGenerator] Generated %d shell_connect candidates (T1:%d T2:%d T3:%d)",
                         len(candidates), len(t1), len(t2), len(t3))

        return candidates

    def generate_command_candidates(
        self,
        objective: str = "",
        world: Optional[WorldModel] = None,
        evidence_graph: Optional[EvidenceGraph] = None,
    ) -> list[dict]:
        """M1 + M2: Generate shell_command candidates for active sessions.

        Uses the hardcoded OBJECTIVE_COMMAND_MAP (INV-E2-06) to propose
        specific commands based on the current engagement objective.

        Args:
            objective: Current objective key (privilege_escalation, lateral_movement, etc.)
            world: WorldModel for active session lookups
            evidence_graph: EvidenceGraph for evidence novelty checks

        Returns:
            List of shell_command candidate dicts
        """
        candidates = []

        # Get active sessions from WorldModel
        active_sessions = _get_active_sessions(world)
        if not active_sessions:
            return []

        # Determine command set from objective
        command_set = OBJECTIVE_COMMAND_MAP.get(objective, [])
        if not command_set:
            # Fallback to recon if no objective match
            command_set = OBJECTIVE_COMMAND_MAP.get("reconnaissance", [])

        # For each active session, propose unexecuted commands
        for session_id, target_ip, cap_type in active_sessions:
            for cmd_entry in command_set:
                # INV-E2-06: command strings are from the hardcoded map only
                command = cmd_entry["command"]
                evidence_type = cmd_entry["evidence_type"]
                rationale = cmd_entry["rationale"]
                cmd_short = command.replace(" ", "_")[:20]

                candidate = {
                    "action_type": "shell_command",
                    "capability": cap_type,
                    "target": target_ip,
                    "method": "execute",
                    "session_id": session_id,
                    "command": command,
                    "expected_evidence_type": evidence_type,
                    "action_id": f"shell_command_{session_id[:8]}_{cmd_short}_{uuid.uuid4().hex[:6]}",
                    "rationale": f"Objective {objective}: {rationale}",
                    "candidate_origin": CANDIDATE_ORIGIN_SHELL_COMMAND,
                    "impact_estimate": 6.0,
                    "confidence": 0.7,
                    "derived_from_world_query_ids": (),
                }
                candidates.append(candidate)

        logger.info("[ShellGenerator] Generated %d shell_command candidates for objective '%s'",
                     len(candidates), objective)
        return candidates

    def generate_disconnect_candidates(
        self,
        world: Optional[WorldModel] = None,
        reason: str = "objective_complete",
    ) -> list[dict]:
        """Generate shell_disconnect candidates for active sessions.

        Args:
            world: WorldModel for active session lookups
            reason: Reason for disconnection

        Returns:
            List of shell_disconnect candidate dicts
        """
        candidates = []
        active_sessions = _get_active_sessions(world)

        for session_id, target_ip, cap_type in active_sessions:
            candidate = {
                "action_type": "shell_disconnect",
                "capability": cap_type,
                "target": target_ip,
                "method": "cleanup",
                "session_id": session_id,
                "reason": reason,
                "action_id": f"shell_disconnect_{session_id[:8]}_{reason}",
                "rationale": f"Terminating {session_id}: {reason}",
                "candidate_origin": CANDIDATE_ORIGIN_SHELL_LIFECYCLE,
                "impact_estimate": 1.0,
                "confidence": 1.0,
            }
            candidates.append(candidate)

        if candidates:
            logger.info("[ShellGenerator] Generated %d shell_disconnect candidates (%s)",
                         len(candidates), reason)
        return candidates

    def get_objective_keys(self) -> list[str]:
        """Return all supported objective keys."""
        return list(OBJECTIVE_COMMAND_MAP.keys())

    def stats(self) -> dict:
        """Return generator statistics."""
        return {
            "connect_triggers": ["T1_CREDENTIAL_DISCOVERY", "T2_EXPLOIT_CONFIRMATION", "T3_CHAIN_ADVISORY"],
            "command_objectives": self.get_objective_keys(),
            "command_templates": sum(len(v) for v in OBJECTIVE_COMMAND_MAP.values()),
        }
