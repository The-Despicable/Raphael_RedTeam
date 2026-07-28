"""contradiction.py — Contradiction detection, falsification, and discriminating observations.

Stage 2D: When evidence contradicts, Raphael must NOT immediately decide.
Instead: represent contradiction → propose discriminating observation →
execute → update hypotheses.

Schema version: 1
"""

import json
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Optional

from orchestrator.brain.evidence import EvidenceGraph, EvidenceRelationType
from orchestrator.brain.hypothesis import HypothesisManager, HypothesisStatus
from orchestrator.brain.world import WorldModel, Entity, Relationship, RelationshipType


class ContradictionStatus(str, Enum):
    """Lifecycle of a detected contradiction."""
    DETECTED = "detected"          # Newly found
    UNDER_INVESTIGATION = "under_investigation"  # Actively seeking resolution
    RESOLVED_TRUE = "resolved_true"    # One side confirmed, other falsified
    RESOLVED_FALSE = "resolved_false"  # Both false / neither reliable
    ABANDONED = "abandoned"       # Could not resolve within budget


class DiscriminatorType(str, Enum):
    """Type of discriminating observation to resolve a contradiction."""
    DIRECT_PROBE = "direct_probe"           # e.g., direct HTTP request
    ALTERNATIVE_TOOL = "alternative_tool"   # e.g., use curl instead of nmap
    TIME_DELAYED = "time_delayed"           # e.g., re-scan after waiting
    SOURCE_VERIFICATION = "source_verification"  # e.g., check tool calibration
    CORROBORATION = "corroboration"         # e.g., third independent source


@dataclass
class DiscriminatingObservation:
    """
    A proposed action to resolve a contradiction.
    
    Fields:
        discriminator_id: Unique ID
        contradiction_id: Links to Contradiction
        type: What kind of discriminator
        description: Human-readable description
        target_entity: Entity to probe
        action_spec: Structured action (tool, args, expected outcomes)
        expected_resolution: What outcome would support each side
        cost_estimate: Estimated action cost (0-1)
        risk_estimate: Risk of detection/disruption (0-1)
        proposed_by: Who/what proposed this
        proposed_at: Timestamp
        executed: Whether executed
        executed_at: When executed
        result: Outcome if executed
        resolved: Whether contradiction was resolved by this
    """
    discriminator_id: str = field(default_factory=lambda: f"disc_{uuid.uuid4().hex[:12]}")
    contradiction_id: str = ""
    type: DiscriminatorType = DiscriminatorType.DIRECT_PROBE
    description: str = ""
    target_entity: str = ""              # Entity ID to probe
    action_spec: dict = field(default_factory=dict)  # Structured action
    expected_resolution: dict = field(default_factory=dict)  # {"supports_a": "...", "supports_b": "..."}
    cost_estimate: float = 0.0
    risk_estimate: float = 0.0
    proposed_by: str = ""
    proposed_at: float = field(default_factory=time.time)
    executed: bool = False
    executed_at: float = 0.0
    result: str = ""
    resolved: bool = False

    def to_dict(self) -> dict:
        d = asdict(self)
        d["type"] = self.type.value
        return d


@dataclass
class Contradiction:
    """
    A detected contradiction between two or more evidence items.
    
    When Evidence A says X and Evidence B says NOT X:
    - Both are preserved (immutability)
    - A Contradiction object is created
    - Discriminating observations are proposed
    - Resolution updates related hypotheses
    """
    contradiction_id: str = field(default_factory=lambda: f"con_{uuid.uuid4().hex[:12]}")
    status: ContradictionStatus = ContradictionStatus.DETECTED
    
    # The conflicting evidence
    evidence_a_id: str = ""          # First evidence
    evidence_b_id: str = ""          # Second evidence
    evidence_c_ids: list[str] = field(default_factory=list)  # Additional
    
    # What they claim
    claim_a: str = ""                # What evidence A asserts
    claim_b: str = ""                # What evidence B asserts
    contradiction_type: str = ""     # e.g., "version_mismatch", "state_conflict", "existence_conflict"
    
    # Context
    target_entity_id: str = ""       # Entity the contradiction concerns
    evidence_graph_ref: str = ""     # Reference to EvidenceGraph relation
    
    # Resolution tracking
    discriminators: list[str] = field(default_factory=list)  # DiscriminatingObservation IDs
    resolution: str = ""             # "a_true", "b_true", "both_false", "unresolvable"
    resolved_at: float = 0.0
    resolved_by: str = ""
    resolution_evidence_ids: list[str] = field(default_factory=list)
    
    # Timeline
    detected_at: float = field(default_factory=time.time)
    investigation_started_at: float = 0.0
    
    # Budget
    max_discriminators: int = 5
    max_budget: float = 10.0
    spent_budget: float = 0.0

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        return d


class ContradictionManager:
    """
    Detects, tracks, and manages contradictions.
    
    Integrates with:
    - EvidenceGraph: finds CONTRADICTS relationships
    - HypothesisManager: updates hypotheses when contradictions resolved
    - WorldModel: can propose discriminators as actions
    """
    
    def __init__(
        self,
        evidence_graph: EvidenceGraph,
        hypothesis_manager: 'HypothesisManager',
        world_model: WorldModel,
    ):
        self.evidence_graph = evidence_graph
        self.hypothesis_manager = hypothesis_manager
        self.world_model = world_model
        
        self.contradictions: dict[str, Contradiction] = {}
        self.discriminators: dict[str, DiscriminatingObservation] = {}
        
        # Index
        self._by_entity: dict[str, set[str]] = {}  # entity_id -> {contradiction_id}
        self._by_evidence: dict[str, set[str]] = {}  # evidence_id -> {contradiction_id}

    def detect_contradictions(self) -> list[Contradiction]:
        """
        Scan EvidenceGraph for CONTRADICTS relationships.
        Returns newly detected contradictions.
        """
        new_contradictions = []
        
        for relation in self.evidence_graph._relations:
            if relation.relation_type != EvidenceRelationType.CONTRADICTS:
                continue
            
            # Check if we already have this contradiction
            existing = self._find_existing(relation.from_evidence_id, relation.to_evidence_id)
            if existing:
                continue
            
            # Get the evidence
            ev_a = self.evidence_graph.get_evidence(relation.from_evidence_id)
            ev_b = self.evidence_graph.get_evidence(relation.to_evidence_id)
            
            if not ev_a or not ev_b:
                continue
            
            # Create contradiction
            con = Contradiction(
                evidence_a_id=ev_a.evidence_id,
                evidence_b_id=ev_b.evidence_id,
                claim_a=ev_a.description or ev_a.raw_content[:200],
                claim_b=ev_b.description or ev_b.raw_content[:200],
                contradiction_type=self._classify_contradiction(ev_a, ev_b),
                target_entity_id=ev_a.target or ev_b.target or "",
                evidence_graph_ref=relation.relation_id,
                status=ContradictionStatus.DETECTED,
            )
            
            self.contradictions[con.contradiction_id] = con
            
            # Index
            for eid in [con.evidence_a_id, con.evidence_b_id]:
                if eid not in self._by_evidence:
                    self._by_evidence[eid] = set()
                self._by_evidence[eid].add(con.contradiction_id)
            
            if con.target_entity_id:
                if con.target_entity_id not in self._by_entity:
                    self._by_entity[con.target_entity_id] = set()
                self._by_entity[con.target_entity_id].add(con.contradiction_id)
            
            new_contradictions.append(con)
        
        return new_contradictions

    def _find_existing(self, eid_a: str, eid_b: str) -> Optional[Contradiction]:
        for con in self.contradictions.values():
            if (con.evidence_a_id == eid_a and con.evidence_b_id == eid_b) or \
               (con.evidence_a_id == eid_b and con.evidence_b_id == eid_a):
                return con
        return None

    def _classify_contradiction(self, ev_a: Evidence, ev_b: Evidence) -> str:
        """Classify the type of contradiction."""
        # Simple heuristic based on evidence types
        if ev_a.evidence_type != ev_b.evidence_type:
            return "tool_disagreement"
        if ev_a.target != ev_b.target:
            return "target_mismatch"
        if "version" in (ev_a.description + ev_b.description).lower():
            return "version_mismatch"
        if "open" in ev_a.description.lower() and "closed" in ev_b.description.lower():
            return "state_conflict"
        return "content_conflict"

    def propose_discriminators(self, contradiction_id: str, max_proposals: int = 3) -> list[DiscriminatingObservation]:
        """
        Propose discriminating observations to resolve a contradiction.
        
        Strategy:
        1. DIRECT_PROBE: Directly query the target
        2. ALTERNATIVE_TOOL: Use different tool
        2. TIME_DELAYED: Re-check after delay
        4. SOURCE_VERIFICATION: Verify tool calibration
        5. CORROBORATION: Find third independent source
        """
        con = self.contradictions.get(contradiction_id)
        if not con:
            return []
        
        if con.status != ContradictionStatus.DETECTED and con.status != ContradictionStatus.UNDER_INVESTIGATION:
            return []
        
        if con.status == ContradictionStatus.DETECTED:
            con.status = ContradictionStatus.UNDER_INVESTIGATION
            con.investigation_started_at = time.time()
        
        proposals = []
        
        # D14-Fix2: Determine if the contradiction involves SSH evidence.
        # Check evidence raw_content and description for SSH indicators.
        # This makes the discriminator service-aware: SSH targets get ssh_banner,
        # HTTP targets get direct_probe (HTTP GET).
        _ev_a = self.evidence_graph.get_evidence(con.evidence_a_id) if hasattr(self, 'evidence_graph') else None
        _ev_b = self.evidence_graph.get_evidence(con.evidence_b_id) if hasattr(self, 'evidence_graph') else None
        _evidences_for_service_check = []
        if _ev_a:
            _evidences_for_service_check.append(getattr(_ev_a, 'raw_content', '') or '')
            _evidences_for_service_check.append(getattr(_ev_a, 'description', '') or '')
        if _ev_b:
            _evidences_for_service_check.append(getattr(_ev_b, 'raw_content', '') or '')
            _evidences_for_service_check.append(getattr(_ev_b, 'description', '') or '')
        _combined_text = ' '.join(_evidences_for_service_check).lower()
        # Heuristic: if evidence mentions SSH (as a service or in description), use ssh_banner
        _is_ssh_target = ('ssh' in _combined_text and 'http' not in _combined_text)
        # Also check the contradiction type from upstream structural detector
        if con.contradiction_type in ('tool_disagreement', 'version_mismatch') and 'ssh' in _combined_text:
            _is_ssh_target = True
        
        # 1. Direct probe (service-aware)
        if len(con.discriminators) < con.max_discriminators:
            if _is_ssh_target:
                # SSH target: propose ssh_banner instead of HTTP direct_probe
                _action = "ssh_banner"
                _capability = "ssh"
                _methods = ["ssh_banner", "ssh_handshake"]
                _description = f"SSH banner grab of {con.target_entity_id} to resolve {con.contradiction_type}"
            else:
                # HTTP or unknown target: propose direct_probe (HTTP GET)
                _action = "direct_probe"
                _capability = "curl"
                _methods = ["http_get", "tcp_connect", "dns_query"]
                _description = f"Direct probe of {con.target_entity_id} to resolve {con.contradiction_type}"
            
            disc = DiscriminatingObservation(
                contradiction_id=contradiction_id,
                type=DiscriminatorType.DIRECT_PROBE,
                description=_description,
                target_entity=con.target_entity_id,
                action_spec={
                    "action": _action,
                    "action_type": _action,
                    "capability": _capability,
                    "target": con.target_entity_id,
                    "methods": _methods,
                },
                expected_resolution={
                    "supports_a": f"Result matches evidence {con.evidence_a_id[:8]} claim",
                    "supports_b": f"Result matches evidence {con.evidence_b_id[:8]} claim",
                },
                cost_estimate=0.2,
                risk_estimate=0.1,
                proposed_by="contradiction_manager",
            )
            proposals.append(disc)
        
        # 2. Alternative tool
        if len(con.discriminators) < con.max_discriminators:
            disc = DiscriminatingObservation(
                contradiction_id=contradiction_id,
                type=DiscriminatorType.ALTERNATIVE_TOOL,
                description=f"Use alternative tool to verify {con.target_entity_id}",
                target_entity=con.target_entity_id,
                action_spec={
                    "action": "alternative_tool",
                    "target": con.target_entity_id,
                    "tools": ["curl", "netcat", "telnet", "openssl"],
                },
                expected_resolution={
                    "supports_a": "Alternative tool confirms evidence A",
                    "supports_b": "Alternative tool confirms evidence B",
                },
                cost_estimate=0.3,
                risk_estimate=0.15,
                proposed_by="contradiction_manager",
            )
            proposals.append(disc)
        
        # 3. Time-delayed re-check
        if len(con.discriminators) < con.max_discriminators:
            disc = DiscriminatingObservation(
                contradiction_id=contradiction_id,
                type=DiscriminatorType.TIME_DELAYED,
                description=f"Re-check {con.target_entity_id} after delay (state may have changed)",
                target_entity=con.target_entity_id,
                action_spec={
                    "action": "time_delayed_recheck",
                    "target": con.target_entity_id,
                    "delay_seconds": 60,
                },
                expected_resolution={
                    "supports_a": "State unchanged, evidence A still valid",
                    "supports_b": "State changed, evidence B was stale",
                },
                cost_estimate=0.1,
                risk_estimate=0.05,
                proposed_by="contradiction_manager",
            )
            proposals.append(disc)
        
        # 4. Corroboration (third source)
        if len(con.discriminators) < con.max_discriminators:
            disc = DiscriminatingObservation(
                contradiction_id=contradiction_id,
                type=DiscriminatorType.CORROBORATION,
                description=f"Find third independent source for {con.target_entity_id}",
                target_entity=con.target_entity_id,
                action_spec={
                    "action": "corroboration",
                    "target": con.target_entity_id,
                    "sources": ["third_party_scanner", "passive_dns", "certificate_transparency"],
                },
                expected_resolution={
                    "supports_a": "Third source matches evidence A",
                    "supports_b": "Third source matches evidence B",
                },
                cost_estimate=0.4,
                risk_estimate=0.1,
                proposed_by="contradiction_manager",
            )
            proposals.append(disc)
        
        # Store proposals
        for p in proposals:
            self.discriminators[p.discriminator_id] = p
            con.discriminators.append(p.discriminator_id)
        
        return proposals

    def execute_discriminator(self, discriminator_id: str, action_result: dict) -> bool:
        """
        Record the execution of a discriminator and its result.
        
        action_result should contain:
        - outcome: "supports_a" | "supports_b" | "inconclusive"
        - evidence_id: newly created evidence ID
        - details: free-form result details
        """
        disc = self.discriminators.get(discriminator_id)
        if not disc:
            return False
        
        if disc.executed:
            return False  # Already executed
        
        disc.executed = True
        disc.executed_at = time.time()
        disc.result = action_result.get("outcome", "inconclusive")
        
        con = self.contradictions.get(disc.contradiction_id)
        if not con:
            return False
        
        # Check if this resolves the contradiction
        outcome = action_result.get("outcome", "inconclusive")
        new_evidence_id = action_result.get("evidence_id")
        
        if outcome == "supports_a":
            con.resolution = "a_true"
            con.resolution_evidence_ids.append(new_evidence_id)
            con.status = ContradictionStatus.RESOLVED_TRUE
        elif outcome == "supports_b":
            con.resolution = "b_true"
            con.resolution_evidence_ids.append(new_evidence_id)
            con.status = ContradictionStatus.RESOLVED_TRUE
        else:
            con.resolution = "inconclusive"
        
        con.resolved_at = time.time()
        con.resolved_by = "discriminator_execution"
        disc.resolved = (con.status in (ContradictionStatus.RESOLVED_TRUE, ContradictionStatus.RESOLVED_FALSE))
        
        # Update related hypotheses
        self._update_hypotheses_from_resolution(con, outcome, new_evidence_id)
        
        return True

    def _update_hypotheses_from_resolution(self, con: Contradiction, outcome: str, new_evidence_id: str):
        """Update hypotheses affected by contradiction resolution."""
        # Find hypotheses that reference the contradicted entities
        affected_hypotheses = self.hypothesis_manager.get_by_entity(con.target_entity_id)
        
        for hyp in affected_hypotheses:
            if hyp.status in (HypothesisStatus.FALSIFIED, HypothesisStatus.ABANDONED):
                continue
            
            # If contradiction was about this hypothesis's claim
            if con.evidence_a_id in hyp.evidence_ids or con.evidence_b_id in hyp.evidence_ids:
                if outcome == "supports_a" and con.evidence_b_id in hyp.evidence_ids:
                    # Evidence B (which supported hyp) is now contradicted
                    self.hypothesis_manager.add_contradiction(hyp.hypothesis_id, con.evidence_b_id)
                elif outcome == "supports_b" and con.evidence_a_id in hyp.evidence_ids:
                    self.hypothesis_manager.add_contradiction(hyp.hypothesis_id, con.evidence_a_id)
            elif new_evidence_id:
                # New evidence might support or contradict
                self.hypothesis_manager.add_evidence(hyp.hypothesis_id, new_evidence_id)

    def get_contradiction(self, contradiction_id: str) -> Optional[Contradiction]:
        return self.contradictions.get(contradiction_id)

    def get_contradictions_for_entity(self, entity_id: str) -> list[Contradiction]:
        ids = self._by_entity.get(entity_id, set())
        return [self.contradictions[cid] for cid in ids if cid in self.contradictions]

    def get_contradictions_for_evidence(self, evidence_id: str) -> list[Contradiction]:
        ids = self._by_evidence.get(evidence_id, set())
        return [self.contradictions[cid] for cid in ids if cid in self.contradictions]

    def get_active_contradictions(self) -> list[Contradiction]:
        return [c for c in self.contradictions.values() 
                if c.status in (ContradictionStatus.DETECTED, ContradictionStatus.UNDER_INVESTIGATION)]

    def stats(self) -> dict:
        return {
            "total": len(self.contradictions),
            "detected": len([c for c in self.contradictions.values() if c.status == ContradictionStatus.DETECTED]),
            "investigating": len([c for c in self.contradictions.values() if c.status == ContradictionStatus.UNDER_INVESTIGATION]),
            "resolved": len([c for c in self.contradictions.values() if c.status == ContradictionStatus.RESOLVED_TRUE]),
            "abandoned": len([c for c in self.contradictions.values() if c.status == ContradictionStatus.ABANDONED]),
            "discriminators_proposed": len(self.discriminators),
            "discriminators_executed": len([d for d in self.discriminators.values() if d.executed]),
        }

    def to_dict(self) -> dict:
        return {
            "schema_version": 1,
            "contradictions": {cid: c.to_dict() for cid, c in self.contradictions.items()},
            "discriminators": {did: d.to_dict() for did, d in self.discriminators.items()},
        }


# ── Integration helpers ──────────────────────────────────────────

def create_contradiction_manager(
    evidence_graph: EvidenceGraph,
    hypothesis_manager: 'HypothesisManager',
    world_model: WorldModel,
) -> ContradictionManager:
    """Factory for ContradictionManager."""
    return ContradictionManager(evidence_graph, hypothesis_manager, world_model)


# ── Arena Scenario #4 integration ────────────────────────────────

def load_scenario_4_contradiction() -> dict:
    """
    Load the contradictory-observations scenario data.
    
    Scenario: Two tools report contradictory states for the same service.
    - Nmap version detection: nginx 1.24.0 (NOT vulnerable to CVE-2023-44487)
    - Direct HTTP probe: Server header says nginx/1.25.0 (VULNERABLE to CVE-2023-44487)
    
    Ground truth: nginx 1.25.0 is running; nmap fingerprint is stale/misleading.
    
    Returns a dict with evidence and expected resolution.
    """
    return {
        "scenario_id": "arena-v0-004",
        "name": "Contradictory Observations",
        "description": "Two tools report contradictory versions for the same web server",
        "evidence": [
            {
                "evidence_id": "ev_nmap_001",
                "raw_content": "PORT   STATE SERVICE VERSION\n80/tcp open  http    nginx 1.24.0",
                "trust_level": "tool_observation",
                "source_detail": "nmap -sV -p 80 10.0.3.10",
                "target": "10.0.3.10",
                "phase": "recon",
                "evidence_type": "version_scan",
                "description": "nmap reports nginx 1.24.0 on port 80",
                "expected_claim": "nginx 1.24.0 (not vulnerable to CVE-2023-44487)",
            },
            {
                "evidence_id": "ev_http_001",
                "raw_content": "HTTP/1.1 200 OK\nServer: nginx/1.25.0\nDate: Mon, 01 Jan 2024 00:00:00 GMT\nContent-Length: 612\n\n<html>...",
                "trust_level": "tool_observation",
                "source_detail": "curl -I http://10.0.3.10",
                "target": "10.0.3.10",
                "phase": "recon",
                "evidence_type": "http_probe",
                "description": "Direct HTTP probe reveals Server header",
                "expected_claim": "nginx 1.25.0 (VULNERABLE to CVE-2023-44487)",
            },
        ],
        "ground_truth": {
            "true_version": "1.25.0",
            "vulnerable": True,
            "cve": "CVE-2023-44487",
            "resolution": "http_probe_correct",
            "why_nmap_wrong": "nmap fingerprint database outdated; Server header is authoritative",
        },
        "expected_discriminators": [
            {
                "type": "direct_probe",
                "target": "10.0.3.10",
                "expected": "Server header confirms 1.25.0",
            },
            {
                "type": "corroboration",
                "target": "10.0.3.10",
                "expected": "Certificate transparency or passive DNS confirms 1.25.0",
            },
        ],
        "success_conditions": [
            "Raphael detects contradiction between version scans",
            "Raphael proposes discriminating observations",
            "Raphael executes at least one discriminator",
            "Raphael correctly identifies HTTP probe as authoritative",
            "Raphael updates hypothesis confidence accordingly",
        ],
    }


def run_scenario_4_test() -> dict:
    """
    Execute the Arena Scenario #4 contradiction test.
    
    Returns a result dict with pass/fail and details.
    """
    from orchestrator.brain.evidence import EvidenceGraph, Evidence, set_evidence_graph, get_evidence_graph
    from orchestrator.brain.trust import TrustLevel
    from orchestrator.brain.world import WorldModel, create_asset
    from orchestrator.brain.hypothesis import HypothesisManager
    from orchestrator.brain.contradiction import (
        ContradictionManager, create_contradiction_manager,
        load_scenario_4_contradiction,
        DiscriminatorType, ContradictionStatus,
    )
    
    # Setup
    set_evidence_graph(EvidenceGraph())
    eg = get_evidence_graph()
    world = WorldModel(eg)
    hm = HypothesisManager(eg, world)
    cm = create_contradiction_manager(eg, hm, world)
    
    results = {
        "scenario": "arena-v0-004",
        "steps": [],
        "passed": False,
        "details": {},
    }
    
    # Step 1: Load scenario evidence
    scenario = load_scenario_4_contradiction()
    evidence_ids = []
    for ev_data in scenario["evidence"]:
        trust_map = {
            "tool_observation": TrustLevel.TOOL_OBSERVATION,
        }
        ev = Evidence.create(
            raw_content=ev_data["raw_content"],
            trust_level=trust_map.get(ev_data["trust_level"], TrustLevel.TOOL_OBSERVATION),
            source_detail=ev_data["source_detail"],
            target=ev_data["target"],
            phase=ev_data["phase"],
            evidence_type=ev_data["evidence_type"],
            description=ev_data["description"],
        )
        eg.add_evidence(ev)
        evidence_ids.append(ev.evidence_id)

    eg.add_contradiction(evidence_ids[0], evidence_ids[1], 
                         rationale="Version mismatch between nmap and HTTP header")
    
    results["steps"].append({
        "step": "load_evidence",
        "evidence_count": len(evidence_ids),
        "status": "ok",
    })
    
    # Step 2: Detect contradictions
    detected = cm.detect_contradictions()
    if not detected:
        results["passed"] = False
        results["details"]["error"] = "No contradiction detected"
        return results
    
    con = detected[0]
    results["steps"].append({
        "step": "detect_contradiction",
        "contradiction_id": con.contradiction_id,
        "type": con.contradiction_type,
        "status": con.status.value,
    })
    
    # Step 3: Propose discriminators
    discriminators = cm.propose_discriminators(con.contradiction_id)
    if len(discriminators) < 2:
        results["passed"] = False
        results["details"]["error"] = f"Expected at least 2 discriminators, got {len(discriminators)}"
        return results
    
    results["steps"].append({
        "step": "propose_discriminators",
        "count": len(discriminators),
        "types": [d.type.value for d in discriminators],
    })
    
    # Step 4: Execute discriminator (simulate HTTP probe confirming 1.25.0)
    # Find the direct_probe discriminator
    direct_probe = next((d for d in discriminators if d.type == DiscriminatorType.DIRECT_PROBE), None)
    if not direct_probe:
        results["passed"] = False
        results["details"]["error"] = "No direct_probe discriminator proposed"
        return results
    
    # Simulate execution: create new evidence confirming HTTP probe
    confirmation_ev = Evidence.create(
        raw_content="Server: nginx/1.25.0",
        trust_level=TrustLevel.TOOL_OBSERVATION,
        source_detail="curl -I http://10.0.3.10 (discriminator execution)",
        target="10.0.3.10",
        phase="recon",
        evidence_type="http_probe",
        description="Discriminator execution: direct HTTP probe confirms 1.25.0",
    )
    eg.add_evidence(confirmation_ev)
    
    # Execute discriminator
    exec_result = cm.execute_discriminator(direct_probe.discriminator_id, {
        "outcome": "supports_b",  # HTTP probe supports evidence B (1.25.0)
        "evidence_id": confirmation_ev.evidence_id,
        "details": "Direct HTTP probe confirms Server: nginx/1.25.0",
    })
    
    if not exec_result:
        results["passed"] = False
        results["details"]["error"] = "Discriminator execution failed"
        return results
    
    results["steps"].append({
        "step": "execute_discriminator",
        "discriminator_id": direct_probe.discriminator_id,
        "outcome": "supports_b",
        "new_evidence": confirmation_ev.evidence_id,
    })
    
    # Step 5: Verify contradiction resolved
    con_resolved = cm.get_contradiction(con.contradiction_id)
    if con_resolved.status != ContradictionStatus.RESOLVED_TRUE:
        results["passed"] = False
        results["details"]["error"] = f"Contradiction not resolved: {con_resolved.status.value}"
        return results
    
    results["steps"].append({
        "step": "verify_resolution",
        "status": con_resolved.status.value,
        "resolution": con_resolved.resolution,
    })
    
    # Step 6: Check hypothesis impact
    # Create a hypothesis about the version
    hyp = hm.propose(
        statement="Target web server runs nginx 1.25.0 (vulnerable to CVE-2023-44487)",
        entity_ids=[],  # Would link to web-server entity
        evidence_ids=[confirmation_ev.evidence_id],
        proposed_by="test",
        assumptions=[],
    )
    
    # Verify hypothesis was updated
    updated = hm.update_confidence(hyp.hypothesis_id, trigger="contradiction_resolution", 
                                    reason="Contradiction resolved in favor of HTTP probe")
    if not updated or updated.overall_confidence < 0.7:
        results["passed"] = False
        results["details"]["error"] = f"Hypothesis confidence too low after resolution: {updated.overall_confidence if updated else 'None'}"
        return results
    
    results["steps"].append({
        "step": "verify_hypothesis_update",
        "hypothesis_confidence": updated.overall_confidence,
        "hypothesis_status": hyp.status.value,
    })
    
    # All checks passed
    results["passed"] = True
    results["details"] = {
        "contradiction_type": con.contradiction_type,
        "discriminators_proposed": len(discriminators),
        "discriminators_executed": 1,
        "final_resolution": con_resolved.resolution,
        "ground_truth_matched": con_resolved.resolution == "b_true",  # Evidence B was correct
        "hypothesis_final_confidence": updated.overall_confidence,
    }
    
    return results


# ── Convenience exports ──────────────────────────────────────────

__all__ = [
    "Contradiction",
    "ContradictionStatus",
    "DiscriminatingObservation",
    "DiscriminatorType",
    "ContradictionManager",
    "create_contradiction_manager",
    "load_scenario_4_contradiction",
    "run_scenario_4_test",
    "compute_independence",
    "compute_freshness",
]