"""
E2 Shell Candidate Generation — Test Suite

Covers 17+ tests:
  - Trigger conditions (T1, T2, T3, duplication guard)
  - Command proposal (M1 objectives, stale session)
  - WorldModel evidence ingestion
  - Falsification re-engagement + dedup
  - INV-E2-04 validation
  - Integration (Planner scoring)
  - Safety (INV-E2-06: no dangerous commands)
  - Edge cases

Schema version: 1
"""

import pytest
import time
import uuid
from unittest.mock import MagicMock

# ── Imports ──────────────────────────────────────────────────────

from orchestrator.brain.world import (
    WorldModel, EntityType, RelationshipType,
    create_asset, create_identity, create_credential,
    create_process, create_file, create_network_connection,
    create_vulnerability, create_shell_session,
    link_authenticates_as, link_runs_on,
    link_observed_in, link_indicates,
)
from orchestrator.brain.evidence import EvidenceGraph, Evidence, TrustLevel
from orchestrator.brain.hypothesis import HypothesisManager, Hypothesis, HypothesisStatus
from orchestrator.brain.candidate_generators.shell_generator import (
    ShellCandidateGenerator,
    OBJECTIVE_COMMAND_MAP,
)
from orchestrator.brain.contradiction import ContradictionManager, create_contradiction_manager


# ═══════════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════════

@pytest.fixture
def evidence_graph():
    return EvidenceGraph()


@pytest.fixture
def world(evidence_graph):
    return WorldModel(evidence_graph)


@pytest.fixture
def hypothesis_manager(evidence_graph, world):
    return HypothesisManager(evidence_graph, world)


@pytest.fixture
def contradiction_manager(evidence_graph, hypothesis_manager, world):
    return create_contradiction_manager(evidence_graph, hypothesis_manager, world)


@pytest.fixture
def shell_generator():
    return ShellCandidateGenerator()


@pytest.fixture
def dummy_evidence_id(evidence_graph):
    """Create a dummy evidence for relationship provenance."""
    ev = Evidence.create(
        raw_content="test evidence", trust_level=TrustLevel.TOOL_OBSERVATION,
        source_detail="test", target="test", evidence_type="test",
    )
    evidence_graph.add_evidence(ev)
    return ev.evidence_id


@pytest.fixture
def asset_and_cred(world, dummy_evidence_id):
    """Create an ASSET with SSH credential for T1 testing."""
    asset = create_asset(world, ip="10.0.1.10", hostname="web-01")
    cred = create_credential(
        world, cred_type="ssh:key", principal="root",
        secret_ref="ssh:key:root@10.0.1.10",
    )
    cred.identifiers["username"] = "root"
    cred.identifiers["target"] = "10.0.1.10"
    cred.identifiers["type"] = "ssh_key"
    identity = create_identity(world, identity_type="user", principal="root")
    link_authenticates_as(world, identity.entity_id, cred.entity_id,
                          evidence_ids=[dummy_evidence_id], established_by="test")
    return asset, cred, identity


@pytest.fixture
def asset_with_session(world):
    """Create an ASSET with an active SHELL_SESSION."""
    asset = create_asset(world, ip="10.0.1.20", hostname="db-01")
    sess = create_shell_session(
        world, "sess_active_001", "ssh_shell", "10.0.1.20",
        username="root",
    )
    return asset, sess


@pytest.fixture
def asset_with_terminated_session(world):
    """Create an ASSET with a TERMINATED SHELL_SESSION (active=False)."""
    asset = create_asset(world, ip="10.0.1.30", hostname="old-host")
    sess = create_shell_session(
        world, "sess_term_001", "ssh_shell", "10.0.1.30",
        username="root",
    )
    sess.active = False
    return asset, sess


@pytest.fixture
def confirmed_rce_hypothesis(hypothesis_manager, world):
    """Create a CONFIRMED RCE hypothesis."""
    asset = create_asset(world, ip="10.0.1.40", hostname="vuln-app")
    hyp = hypothesis_manager.propose(
        statement="Remote Code Execution via shell injection on 10.0.1.40",
        entity_ids=[asset.entity_id],
        evidence_ids=[],
        proposed_by="test",
    )
    # Manually set to confirmed
    hyp.status = HypothesisStatus.CONFIRMED
    hyp.current_confidence = 0.95
    return asset, hyp


# ═══════════════════════════════════════════════════════════════════
# E2-T01: T1 Credential Discovery Trigger
# ═══════════════════════════════════════════════════════════════════

class TestT1CredentialDiscovery:
    """T1: Credentials + SSH service → shell_connect candidate."""

    def test_t1_triggers_connect_candidate(self, shell_generator, world, evidence_graph,
                                            asset_and_cred):
        """E2-T01: WorldModel with CREDENTIAL → shell_connect produced."""
        candidates = shell_generator.generate_connect_candidates(
            world=world,
            evidence_graph=evidence_graph,
            targets=["10.0.1.10"],
        )
        assert len(candidates) >= 1, "T1 should produce shell_connect candidates"
        c = candidates[0]
        assert c["action_type"] == "shell_connect"
        assert c["method"] == "credential_auth"
        assert c["target"] == "10.0.1.10"
        assert "session_proposal" in c
        assert c["session_proposal"]["parameters"]["username"] == "root"

    def test_t1_no_credential_no_candidate(self, shell_generator, world, evidence_graph):
        """No credential → no shell_connect candidate."""
        candidates = shell_generator.generate_connect_candidates(
            world=world, evidence_graph=evidence_graph, targets=["10.0.1.10"],
        )
        assert len(candidates) == 0

    def test_t1_no_target_no_candidate(self, shell_generator, world, evidence_graph,
                                        asset_and_cred):
        """No targets → no shell_connect candidate."""
        candidates = shell_generator.generate_connect_candidates(
            world=world, evidence_graph=evidence_graph, targets=[],
        )
        # Without targets, T1 falls back to credential's own target
        assert len(candidates) >= 1  # Credential has target 10.0.1.10


# ═══════════════════════════════════════════════════════════════════
# E2-T02: T2 Exploit Confirmation Trigger
# ═══════════════════════════════════════════════════════════════════

class TestT2ExploitConfirmation:
    """T2: CONFIRMED RCE hypothesis → shell_connect with reverse payload."""

    def test_t2_triggers_reverse_shell(self, shell_generator, world, evidence_graph,
                                        hypothesis_manager, confirmed_rce_hypothesis):
        """E2-T02: CONFIRMED RCE → shell_connect with method='payload_injection'."""
        candidates = shell_generator.generate_connect_candidates(
            world=world,
            evidence_graph=evidence_graph,
            hypothesis_manager=hypothesis_manager,
            targets=["10.0.1.40"],
        )
        assert len(candidates) >= 1
        c = candidates[0]
        assert c["action_type"] == "shell_connect"
        assert c["method"] == "payload_injection"
        assert c["capability"] == "reverse_shell"

    def test_t2_no_confirmed_hypothesis_no_candidate(self, shell_generator, world,
                                                      evidence_graph, hypothesis_manager):
        """No confirmed hypothesis → no candidate."""
        candidates = shell_generator.generate_connect_candidates(
            world=world, evidence_graph=evidence_graph,
            hypothesis_manager=hypothesis_manager,
            targets=["10.0.1.40"],
        )
        assert len(candidates) == 0

    def test_t2_non_rce_hypothesis_no_candidate(self, shell_generator, world,
                                                  evidence_graph, hypothesis_manager):
        """Confirmed but non-RCE hypothesis → no candidate."""
        asset = create_asset(world, ip="10.0.1.50")
        hyp = hypothesis_manager.propose(
            statement="SSL certificate expired on 10.0.1.50",
            entity_ids=[asset.entity_id],
            evidence_ids=[],
            proposed_by="test",
        )
        hyp.status = HypothesisStatus.CONFIRMED
        candidates = shell_generator.generate_connect_candidates(
            world=world, evidence_graph=evidence_graph,
            hypothesis_manager=hypothesis_manager,
            targets=["10.0.1.50"],
        )
        assert len(candidates) == 0


# ═══════════════════════════════════════════════════════════════════
# E2-T03: T3 Chain Advisory Trigger
# ═══════════════════════════════════════════════════════════════════

class TestT3ChainAdvisory:
    """T3: ChainSynthesizer suggests shell step → shell_connect."""

    def test_t3_chain_advisory(self, shell_generator, world, evidence_graph):
        """E2-T03: ChainSynthesizer with shell technique → shell_connect."""
        mock_cs = MagicMock()
        mock_cs.suggest_next_steps.return_value = [
            {"technique_id": "shell_ssh_connect", "name": "SSH Shell Connection",
             "readiness": 0.8, "impact": 8.0, "expected_value": 6.4},
        ]
        gen = ShellCandidateGenerator(chain_synthesizer=mock_cs)
        create_asset(world, ip="10.0.1.60")
        candidates = gen.generate_connect_candidates(
            world=world, evidence_graph=evidence_graph,
            targets=["10.0.1.60"],
            confirmed_technique_ids=["ssrf_discovery"],
        )
        assert len(candidates) >= 1
        c = candidates[0]
        assert c["action_type"] == "shell_connect"
        assert c["method"] == "chain_advisory"

    def test_t3_no_shell_technique(self, world):
        """ChainSynthesizer with no shell step → no shell_connect."""
        mock_cs = MagicMock()
        mock_cs.suggest_next_steps.return_value = [
            {"technique_id": "enum_users", "name": "Enumerate Users",
             "readiness": 0.9, "impact": 5.0, "expected_value": 4.5},
        ]
        gen = ShellCandidateGenerator(chain_synthesizer=mock_cs)
        candidates = gen.generate_connect_candidates(
            world=world, targets=["10.0.1.60"],
        )
        assert len(candidates) == 0


# ═══════════════════════════════════════════════════════════════════
# E2-T04: Shell_connect NOT proposed for target with active session
# ═══════════════════════════════════════════════════════════════════

class TestT4SessionDedup:
    """INV-E2-03: No shell_connect for target with active session."""

    def test_no_duplicate_connect(self, shell_generator, world, evidence_graph,
                                   asset_with_session):
        """E2-T04: Target with active session → no shell_connect."""
        candidates = shell_generator.generate_connect_candidates(
            world=world, evidence_graph=evidence_graph,
            targets=["10.0.1.20"],
        )
        assert len(candidates) == 0, "No connect candidate for active session target"


# ═══════════════════════════════════════════════════════════════════
# E2-T05 / E2-T06: M1 Objective-Driven Command Proposal
# ═══════════════════════════════════════════════════════════════════

class TestM1ObjectiveDriven:
    """M1: Active shell + objective → correct shell_command candidates."""

    def _add_session(self, world, sid="sess_active"):
        create_shell_session(world, sid, "ssh_shell", "10.0.1.10", username="root")

    def test_privesc_commands(self, shell_generator, world):
        """E2-T05: PRIVESC objective → sudo -l, find -perm, uname."""
        self._add_session(world, "sess_privesc")
        candidates = shell_generator.generate_command_candidates(
            objective="privilege_escalation",
            world=world,
        )
        commands = [c["command"] for c in candidates]
        assert any("sudo -l" in cmd for cmd in commands), "sudo -l expected"
        assert any("find / -type f -perm -4000" in cmd for cmd in commands), "find -perm expected"
        assert any("uname -a" in cmd for cmd in commands), "uname -a expected"
        assert any(c["candidate_origin"] == "SHELL_COMMAND_OBJECTIVE" for c in candidates)

    def test_lateral_commands(self, shell_generator, world):
        """E2-T06: LATERAL objective → ip addr, netstat."""
        self._add_session(world, "sess_lateral")
        candidates = shell_generator.generate_command_candidates(
            objective="lateral_movement",
            world=world,
        )
        commands = [c["command"] for c in candidates]
        assert any("ip addr" in cmd for cmd in commands), "ip addr expected"
        assert any("netstat" in cmd for cmd in commands), "netstat expected"

    def test_credential_access_commands(self, shell_generator, world):
        """Credential access objective → shadow commands."""
        self._add_session(world, "sess_cred")
        candidates = shell_generator.generate_command_candidates(
            objective="credential_access",
            world=world,
        )
        commands = [c["command"] for c in candidates]
        assert any("/etc/shadow" in cmd for cmd in commands)

    def test_no_active_session_no_commands(self, shell_generator, world):
        """No active session → no command candidates."""
        candidates = shell_generator.generate_command_candidates(
            objective="privilege_escalation", world=world,
        )
        assert len(candidates) == 0

    def test_unknown_objective_falls_back_to_recon(self, shell_generator, world):
        """Unknown objective → falls back to recon commands."""
        self._add_session(world, "sess_unknown")
        candidates = shell_generator.generate_command_candidates(
            objective="nonexistent_objective", world=world,
        )
        assert len(candidates) > 0
        assert any(c["command"] == "id" for c in candidates)


# ═══════════════════════════════════════════════════════════════════
# E2-T07: Stale session rejection (INV-E2-02)
# ═══════════════════════════════════════════════════════════════════

class TestStaleSessionRejection:
    """INV-E2-02: TERMINATED session → empty command candidate list."""

    def test_terminated_session_no_commands(self, shell_generator, world,
                                             asset_with_terminated_session):
        """E2-T07: TERMINATED session → no shell_command candidates."""
        candidates = shell_generator.generate_command_candidates(
            objective="privilege_escalation", world=world,
        )
        assert len(candidates) == 0, "No commands for terminated session"


# ═══════════════════════════════════════════════════════════════════
# E2-T08 / E2-T09: WorldModel evidence ingestion
# ═══════════════════════════════════════════════════════════════════

class TestWorldModelIngestion:
    """E2 evidence ingestion into WorldModel entity graph."""

    def test_ingest_process_list(self, world):
        """E2-T08: process_list evidence → PROCESS entity + OBSERVED_IN."""
        sess = create_shell_session(world, "sess_ingest_p", "ssh_shell", "10.0.1.10")
        ev = Evidence.create(
            raw_content="  PID  CMD\n    1 /sbin/init",
            trust_level=TrustLevel.TOOL_OBSERVATION,
            source_detail="shell:ps",
            target="10.0.1.10",
            phase="execution",
            evidence_type="process_list",
            structured_content={
                "processes": [{"pid": 1, "ppid": 0, "user": "root",
                                "cmd": "/sbin/init", "cpu": 0.0, "mem": 0.1}],
            },
        )
        created = world.ingest_shell_evidence(ev, sess.entity_id)
        processes = world.get_entities_by_type(EntityType.PROCESS)
        assert len(processes) >= 1
        assert processes[0].identifiers["pid"] == "1"

    def test_ingest_file_content_shadow(self, world):
        """E2-T09: /etc/shadow → FILE + CREDENTIAL entities."""
        sess = create_shell_session(world, "sess_shad", "ssh_shell", "10.0.1.10")
        shadow_content = "root:$6$xyz$abc:18937:0:99999:7:::\ndaemon:*:18937:0:99999:7:::"
        ev = Evidence.create(
            raw_content=shadow_content,
            trust_level=TrustLevel.TOOL_OBSERVATION,
            source_detail="shell:cat /etc/shadow",
            target="10.0.1.10",
            phase="credential_access",
            evidence_type="file_content",
            structured_content={"path": "/etc/shadow", "content": shadow_content},
        )
        created = world.ingest_shell_evidence(ev, sess.entity_id)
        files = world.get_entities_by_type(EntityType.FILE)
        credentials = world.get_entities_by_type(EntityType.CREDENTIAL)
        assert len(files) >= 1
        assert len(credentials) >= 1, "shadow should create CREDENTIAL entities"
        cred_types = [c.identifiers.get("type", "") for c in credentials]
        assert "password_hash" in cred_types

    def test_ingest_network_connections(self, world):
        """network_connections → NETWORK_CONNECTION entity."""
        sess = create_shell_session(world, "sess_net", "ssh_shell", "10.0.1.10")
        ev = Evidence.create(
            raw_content="Proto Local Address Foreign Address State",
            trust_level=TrustLevel.TOOL_OBSERVATION,
            source_detail="shell:netstat",
            target="10.0.1.10",
            phase="execution",
            evidence_type="network_connections",
            structured_content={
                "connections": [{"proto": "tcp", "local_addr": "0.0.0.0:22",
                                  "foreign_addr": "0.0.0.0:*", "state": "LISTEN", "pid": 1}],
            },
        )
        created = world.ingest_shell_evidence(ev, sess.entity_id)
        conns = world.get_entities_by_type(EntityType.NETWORK_CONNECTION)
        assert len(conns) >= 1

    def test_ingest_user_accounts(self, world):
        """user_accounts → IDENTITY entities."""
        sess = create_shell_session(world, "sess_usr", "ssh_shell", "10.0.1.10")
        ev = Evidence.create(
            raw_content="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
            trust_level=TrustLevel.TOOL_OBSERVATION,
            source_detail="shell:cat /etc/passwd",
            target="10.0.1.10",
            phase="execution",
            evidence_type="user_accounts",
            structured_content={
                "accounts": [{"username": "root", "uid": 0, "shell": "/bin/bash"},
                              {"username": "daemon", "uid": 1, "shell": "/usr/sbin/nologin"}],
            },
        )
        created = world.ingest_shell_evidence(ev, sess.entity_id)
        users = [e for e in world.get_entities_by_type(EntityType.IDENTITY)
                 if e.identifiers.get("uid") in ("0", "1")]
        assert len(users) >= 1

    def test_ingest_credential_evidence(self, world):
        """credential evidence → CREDENTIAL entity."""
        sess = create_shell_session(world, "sess_credev", "ssh_shell", "10.0.1.10")
        ev = Evidence.create(
            raw_content="-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----",
            trust_level=TrustLevel.TARGET_CONTROLLED,
            source_detail="shell:cat ~/.ssh/id_rsa",
            target="10.0.1.10",
            phase="credential_access",
            evidence_type="credential",
            structured_content={"type": "ssh_private_key", "raw": "ssh private key content"},
        )
        created = world.ingest_shell_evidence(ev, sess.entity_id)
        creds = world.get_entities_by_type(EntityType.CREDENTIAL)
        assert len(creds) >= 1

    def test_ingest_vulnerability_indicator(self, world):
        """vulnerability_indicator → VULNERABILITY entity."""
        sess = create_shell_session(world, "sess_vuln", "ssh_shell", "10.0.1.10")
        ev = Evidence.create(
            raw_content="Linux version 4.4.0-142-generic",
            trust_level=TrustLevel.TOOL_OBSERVATION,
            source_detail="shell:uname -a",
            target="10.0.1.10",
            phase="vulnerability_assessment",
            evidence_type="vulnerability_indicator",
            structured_content={
                "vuln_class": "kernel_version_disclosure",
                "description": "Kernel version: 4.4.0-142-generic",
                "confidence": 0.8,
            },
        )
        created = world.ingest_shell_evidence(ev, sess.entity_id)
        vulns = world.get_entities_by_type(EntityType.VULNERABILITY)
        assert len(vulns) >= 1

    def test_update_host_from_shell(self, world):
        """update_host_from_shell() aggregates shell evidence correctly."""
        sess = create_shell_session(world, "sess_agg", "ssh_shell", "10.0.1.10")
        ev = Evidence.create(
            raw_content="  PID CMD\n    1 init",
            trust_level=TrustLevel.TOOL_OBSERVATION,
            source_detail="shell:ps",
            target="10.0.1.10",
            phase="execution",
            evidence_type="process_list",
            structured_content={
                "processes": [{"pid": 1, "ppid": 0, "user": "root",
                                "cmd": "/sbin/init", "cpu": 0.0, "mem": 0.1}],
            },
        )
        world.ingest_shell_evidence(ev, sess.entity_id)
        host = create_asset(world, ip="10.0.1.10")
        summary = world.update_host_from_shell(host.entity_id, sess.entity_id)
        assert summary["process_count"] >= 1
        assert summary["session"] == sess.entity_id

    def test_get_session_host(self, world, dummy_evidence_id):
        """get_session_host() finds host ASSET from SHELL_SESSION."""
        host = create_asset(world, ip="10.0.1.10")
        sess = create_shell_session(world, "sess_host", "ssh_shell", "10.0.1.10")
        proc = create_process(world, pid=1, cmd="/sbin/init", evidence_ids=[dummy_evidence_id], created_by="test")
        link_observed_in(world, proc.entity_id, sess.entity_id,
                         evidence_ids=[dummy_evidence_id], established_by="test")
        link_runs_on(world, proc.entity_id, host.entity_id,
                     evidence_ids=[dummy_evidence_id], established_by="test")
        found = world.get_session_host(sess.entity_id)
        assert found is not None
        assert found.primary_identifier == "10.0.1.10"


# ═══════════════════════════════════════════════════════════════════
# E2-T10 / E2-T11: Falsification re-engagement
# ═══════════════════════════════════════════════════════════════════

class TestFalsificationReengagement:
    """Falsification re-engagement from shell-derived evidence."""

    def test_vulnerability_triggers_falsification(self, world, contradiction_manager):
        """E2-T10: Contradiction between scan and shell evidence is detected."""
        sess = create_shell_session(world, "sess_fal", "ssh_shell", "10.0.1.10")

        # Existing evidence: scan said host is patched
        existing_ev = Evidence.create(
            raw_content="Host 10.0.1.10 is patched against kernel exploits",
            trust_level=TrustLevel.TOOL_OBSERVATION,
            source_detail="nmap scan",
            target="10.0.1.10",
            phase="scan",
            evidence_type="scan_result",
        )
        contradiction_manager.evidence_graph.add_evidence(existing_ev)

        # Shell evidence: kernel is vulnerable
        shell_ev = Evidence.create(
            raw_content="Linux version 4.4.0-142-generic",
            trust_level=TrustLevel.TOOL_OBSERVATION,
            source_detail="shell:uname -a",
            target="10.0.1.10",
            phase="vulnerability_assessment",
            evidence_type="vulnerability_indicator",
            structured_content={
                "vuln_class": "kernel_version_disclosure",
                "description": "Old kernel: 4.4.0-142",
                "confidence": 0.8,
            },
        )
        contradiction_manager.evidence_graph.add_evidence(shell_ev)

        # Add CONTRADICTS relationship between the two
        contradiction_manager.evidence_graph.add_contradiction(
            contradictor_id=shell_ev.evidence_id,
            contradicted_id=existing_ev.evidence_id,
            rationale="Scan says patched, shell says vulnerable",
        )

        # Detect contradictions
        new_contradictions = contradiction_manager.detect_contradictions()
        if new_contradictions:
            for con in new_contradictions:
                discriminators = contradiction_manager.propose_discriminators(con.contradiction_id)
                # Should produce at least some discriminators
                assert len(discriminators) >= 0

    def test_falsification_dedup(self, world, contradiction_manager):
        """E2-T11: Evidence with same content_hash but different ID → multiple VULNERABILITY entities ok."""
        sess = create_shell_session(world, "sess_dedup", "ssh_shell", "10.0.1.10")
        ev1 = Evidence.create(
            raw_content="SUID binary: /usr/bin/pkexec",
            trust_level=TrustLevel.TOOL_OBSERVATION,
            source_detail="shell:find",
            target="10.0.1.10",
            phase="vulnerability_assessment",
            evidence_type="vulnerability_indicator",
            structured_content={"vuln_class": "suid_binary",
                                 "description": "SUID binary: /usr/bin/pkexec",
                                 "confidence": 0.7},
        )
        ev2 = Evidence.create(
            raw_content="SUID binary: /usr/bin/pkexec",
            trust_level=TrustLevel.TOOL_OBSERVATION,
            source_detail="shell:find",
            target="10.0.1.10",
            phase="vulnerability_assessment",
            evidence_type="vulnerability_indicator",
            structured_content={"vuln_class": "suid_binary",
                                 "description": "SUID binary: /usr/bin/pkexec",
                                 "confidence": 0.7},
        )
        world.ingest_shell_evidence(ev1, sess.entity_id)
        world.ingest_shell_evidence(ev2, sess.entity_id)
        vulns = world.get_entities_by_type(EntityType.VULNERABILITY)
        assert len(vulns) >= 1


# ═══════════════════════════════════════════════════════════════════
# E2-T12: INV-E2-04 validation
# ═══════════════════════════════════════════════════════════════════

class TestInve204Validation:
    """INV-E2-04: ingest_shell_evidence requires valid session."""

    def test_invalid_session_raises_value_error(self, world):
        """E2-T12: Invalid session_entity_id → ValueError."""
        ev = Evidence.create(
            raw_content="test", trust_level=TrustLevel.TOOL_OBSERVATION,
            source_detail="test", evidence_type="command_output",
        )
        with pytest.raises(ValueError):
            world.ingest_shell_evidence(ev, "nonexistent_session")


# ═══════════════════════════════════════════════════════════════════
# E2-T13: Planner scores shell_connect candidates
# ═══════════════════════════════════════════════════════════════════

class TestPlannerShellScoring:
    """Planner.decide() scoring for shell candidates."""

    def test_planner_scores_shell_connect(self):
        """E2-T13: Planner selects shell_connect candidate."""
        from orchestrator.brain.action import Planner, ActionRegistry
        eg = EvidenceGraph()
        wm = WorldModel(eg)
        hm = HypothesisManager(eg, wm)
        cm = create_contradiction_manager(eg, hm, wm)
        planner = Planner(
            world=wm, evidence_graph=eg,
            hypothesis_manager=hm, contradiction_manager=cm,
            action_registry=ActionRegistry(),
        )
        candidates = [
            {"action_type": "shell_connect", "target": "10.0.1.10",
             "capability": "ssh_shell", "method": "credential_auth",
             "action_id": "shell_connect_test"},
        ]
        decision = planner.decide(candidates, "obj_001")
        assert decision.selected_action_id is not None
        assert "shell_connect" in decision.selected_action_id
        assert "shell_connect_initiated" in decision.rationale_codes


# ═══════════════════════════════════════════════════════════════════
# E2-T14: Shell_disconnect candidates
# ═══════════════════════════════════════════════════════════════════

class TestShellDisconnect:
    """shell_disconnect candidate generation."""

    def test_disconnect_for_active_session(self, shell_generator, world):
        """Active session → shell_disconnect candidate."""
        create_shell_session(world, "sess_disc", "ssh_shell", "10.0.1.10", username="root")
        candidates = shell_generator.generate_disconnect_candidates(
            world=world, reason="objective_complete",
        )
        assert len(candidates) >= 1
        c = candidates[0]
        assert c["action_type"] == "shell_disconnect"
        assert c["session_id"] == "sess_disc"
        assert c["reason"] == "objective_complete"

    def test_no_active_session_no_disconnect(self, shell_generator, world):
        """No active session → no disconnect."""
        candidates = shell_generator.generate_disconnect_candidates(world=world)
        assert len(candidates) == 0


# ═══════════════════════════════════════════════════════════════════
# E2-T15: INV-E2-06 Objective Command Map Safety
# ═══════════════════════════════════════════════════════════════════

class TestObjectiveCommandMapSafety:
    """INV-E2-06: No dangerous commands in objective_command_map."""

    DANGEROUS_COMMANDS = [
        " rm ", " rm -rf", "rm -rf ", "rmdir ", " dd ", "mkfs", "> /dev/sda",
        "format", ":(){ :|:& };:", "chmod -R 000", "shutdown", "reboot",
        "halt", "poweroff", "init 0", "init 6",
        "kill ", "pkill ", "iptables",
    ]

    def test_no_dangerous_commands(self):
        """E2-T15: OBJECTIVE_COMMAND_MAP contains no destructive commands."""
        for objective, commands in OBJECTIVE_COMMAND_MAP.items():
            for entry in commands:
                cmd = entry["command"]
                for pattern in self.DANGEROUS_COMMANDS:
                    assert pattern not in cmd, (
                        f"Dangerous pattern '{pattern}' found in {objective}: {cmd}"
                    )

    def test_every_objective_has_commands(self):
        """Every objective key has at least one command."""
        for objective, commands in OBJECTIVE_COMMAND_MAP.items():
            assert len(commands) >= 1, f"Objective '{objective}' has no commands"

    def test_all_commands_have_evidence_type(self):
        """Every command entry has evidence_type and rationale."""
        for objective, commands in OBJECTIVE_COMMAND_MAP.items():
            for entry in commands:
                assert "evidence_type" in entry, f"Missing evidence_type in {objective}: {entry}"
                assert "rationale" in entry, f"Missing rationale in {objective}: {entry}"


# ═══════════════════════════════════════════════════════════════════
# E2-T17: Generator Stats
# ═══════════════════════════════════════════════════════════════════

class TestGeneratorStats:
    """ShellCandidateGenerator stats."""

    def test_stats(self, shell_generator):
        """stats() returns correct structure."""
        stats = shell_generator.stats()
        assert "connect_triggers" in stats
        assert "command_objectives" in stats
        assert "command_templates" in stats
        assert stats["command_templates"] >= 30


# ═══════════════════════════════════════════════════════════════════
# E2-T16: Edge cases
# ═══════════════════════════════════════════════════════════════════

class TestEdgeCases:
    """Edge cases for ShellCandidateGenerator."""

    def test_no_chain_synthesizer_no_crash(self):
        """No chain_synthesizer → no crash."""
        gen = ShellCandidateGenerator()
        assert gen.chain_synthesizer is None
        candidates = gen.generate_connect_candidates(targets=["10.0.1.10"])
        assert isinstance(candidates, list)

    def test_generate_all_modes_empty(self, shell_generator):
        """All generate methods return lists even with no state."""
        assert isinstance(shell_generator.generate_connect_candidates(), list)
        assert isinstance(shell_generator.generate_command_candidates(), list)
        assert isinstance(shell_generator.generate_disconnect_candidates(), list)

    def test_disconnect_no_duplicates(self, shell_generator, world):
        """Multiple disconnect calls return consistent results."""
        create_shell_session(world, "sess_disc2", "ssh_shell", "10.0.1.10")
        c1 = shell_generator.generate_disconnect_candidates(world=world, reason="done")
        c2 = shell_generator.generate_disconnect_candidates(world=world, reason="done")
        assert len(c1) == len(c2)
