"""action.py — Generalized Action/State Transitions for autonomous planning.

Generalizes the AttackUnit concept into a structured action system:
- Action: preconditions, effects, cost, authorization, reversibility
- State: WorldModel snapshot
- Planner: searches for action sequences to achieve goals

Schema version: 1
"""

import time
import uuid
import copy
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Callable, Optional, List, Tuple


from orchestrator.brain.world import WorldModel, Entity, Relationship, EntityType, RelationshipType
from orchestrator.brain.evidence import EvidenceGraph, Evidence, TrustLevel
from orchestrator.brain.hypothesis import HypothesisManager, HypothesisStatus
from orchestrator.brain.contradiction import ContradictionManager, ContradictionStatus
from orchestrator.brain.trust import TrustLevel
from orchestrator.hardening.action_receipt import (
    ActionReceipt, ActionProposalStatus, create_proposal, authorize, deny,
    start_execution, complete_execution, timeout_execution,
)

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from arena.conclusion import PlanDecision
    # Runtime import avoided via lazy import inside decide() method body


class ActionType(str, Enum):
    """Categories of actions for cost/risk estimation."""
    RECON = "recon"                    # Information gathering (low cost/risk)
    SCAN = "scan"                      # Active scanning (medium cost/risk)
    ENUMERATE = "enumerate"            # Service enumeration (medium)
    EXPLOIT = "exploit"                # Vulnerability exploitation (high cost/risk)
    PRIVILEGE_ESCALATION = "privesc"   # Privilege escalation (high)
    LATERAL_MOVEMENT = "lateral"       # Lateral movement (high)
    CREDENTIAL_ACCESS = "cred_access"  # Credential theft (medium-high)
    PERSISTENCE = "persistence"        # Persistence establishment (high)
    EXFILTRATION = "exfiltration"      # Data exfiltration (high)
    CLEANUP = "cleanup"                # Anti-forensics (medium)
    COMMAND = "command"                # Generic command execution (variable)


class PreconditionType(str, Enum):
    """Types of preconditions for actions."""
    ENTITY_EXISTS = "entity_exists"              # Entity must exist in world model
    RELATIONSHIP_EXISTS = "relationship_exists"  # Relationship must exist
    HYPOTHESIS_CONFIDENCE = "hypothesis_confidence"  # Hypothesis must have min confidence
    EVIDENCE_EXISTS = "evidence_exists"          # Specific evidence must exist
    CAPABILITY_AVAILABLE = "capability_available"  # Tool/capability must be available
    AUTHORIZATION = "authorization"              # Must be authorized by broker
    NO_CONTRADICTION = "no_contradiction"        # No unresolved contradictions
    FRESH_EVIDENCE = "fresh_evidence"            # Evidence must be recent


@dataclass
class Precondition:
    """A condition that must be satisfied before an action can execute."""
    type: PreconditionType = PreconditionType.ENTITY_EXISTS
    target: str = ""                    # Entity ID, hypothesis ID, evidence ID, etc.
    parameters: dict = field(default_factory=dict)  # Type-specific params
    
    # For HYPOTHESIS_CONFIDENCE
    min_confidence: float = 0.5
    # For FRESH_EVIDENCE
    max_age_hours: float = 168.0  # 1 week
    # For CAPABILITY_AVAILABLE
    capability_name: str = ""
    # For RELATIONSHIP_EXISTS
    relationship_type: str = ""
    source_entity: str = ""
    target_entity: str = ""

    def check(self, world: 'WorldModel', evidence_graph: 'EvidenceGraph', 
              hypothesis_manager: 'HypothesisManager', contradiction_manager: 'ContradictionManager') -> tuple[bool, str]:
        """Check if precondition is satisfied. Returns (satisfied, reason)."""
        if self.type == PreconditionType.ENTITY_EXISTS:
            ent = world.get_entity(self.target)
            return (ent is not None, f"Entity {self.target} {'exists' if ent else 'not found'}")
        
        elif self.type == PreconditionType.RELATIONSHIP_EXISTS:
            rels = world.get_relationships(
                source=self.source_entity,
                target=self.target_entity,
                rel_type=self.parameters.get("relationship_type", self.relationship_type)
            )
            satisfied = len(rels) > 0
            return (satisfied, f"Relationship {self.source_entity} -> {self.target_entity} ({self.relationship_type}) {'exists' if satisfied else 'missing'}")
        
        elif self.type == PreconditionType.HYPOTHESIS_CONFIDENCE:
            hyp = self.hypothesis_manager.get_hypothesis(self.target)
            if not hyp:
                return (False, f"Hypothesis {self.target} not found")
            satisfied = hyp.current_confidence >= self.min_confidence
            return (satisfied, f"Hypothesis confidence {hyp.current_confidence:.2f} >= {self.min_confidence}")
        
        elif self.type == PreconditionType.EVIDENCE_EXISTS:
            ev = evidence_graph.get_evidence(self.target)
            return (ev is not None, f"Evidence {self.target} {'exists' if ev else 'not found'}")
        
        elif self.type == PreconditionType.CAPABILITY_AVAILABLE:
            # Would check tool availability
            return (True, f"Capability {self.capability_name} assumed available")
        
        elif self.type == PreconditionType.AUTHORIZATION:
            # Would check CapabilityBroker
            return (True, "Authorization assumed for planning")
        
        elif self.type == PreconditionType.NO_CONTRADICTION:
            active = contradiction_manager.get_active_contradictions()
            target_contradictions = [c for c in active if c.target_entity_id == self.target]
            satisfied = len(target_contradictions) == 0
            return (satisfied, f"Target has {len(target_contradictions)} unresolved contradictions")
        
        elif self.type == PreconditionType.FRESH_EVIDENCE:
            ev = evidence_graph.get_evidence(self.target)
            if not ev:
                return (False, f"Evidence {self.target} not found")
            age_hours = (time.time() - ev.collected_at) / 3600.0
            satisfied = age_hours <= self.max_age_hours
            return (satisfied, f"Evidence age {age_hours:.1f}h {'<=' if satisfied else '>'} {self.max_age_hours}h")
        
        return (False, f"Unknown precondition type: {self.type.value}")


@dataclass
class Effect:
    """An effect that an action has on the world model."""
    # What kind of change
    creates_entity: Optional[dict] = None           # {entity_type, identifiers, evidence_ids}
    creates_relationship: Optional[dict] = None     # {source, target, type, evidence_ids}
    updates_hypothesis: Optional[dict] = None       # {hypothesis_id, new_confidence, status}
    adds_evidence: Optional[dict] = None            # {raw_content, trust_level, ...}
    resolves_contradiction: Optional[str] = None    # contradiction_id
    creates_contradiction: Optional[dict] = None    # {evidence_a, evidence_b, ...}
    
    # Metadata
    description: str = ""
    certainty: float = 1.0  # How certain this effect will occur (0-1)


@dataclass
class Action:
    """
    A generalized action with preconditions, effects, and metadata for planning.
    
    This replaces the old AttackUnit concept with a more structured representation
    that supports automated planning, cost estimation, and authorization.
    """
    schema_version: int = 1
    action_id: str = field(default_factory=lambda: f"act_{uuid.uuid4().hex[:12]}")
    name: str = ""
    action_type: ActionType = ActionType.RECON
    
    # Description
    description: str = ""
    
    # Preconditions (ALL must be satisfied)
    preconditions: list[Precondition] = field(default_factory=list)
    
    # Effects (what happens when action executes)
    effects: list[Effect] = field(default_factory=list)
    
    # Cost/Risk/Impact estimation
    cost_estimate: float = 1.0          # Abstract cost units (0-10)
    risk_estimate: float = 0.0          # Probability of detection/failure (0-1)
    impact_estimate: float = 0.0        # Expected impact on objective (0-10)
    time_estimate_seconds: float = 10.0 # Expected execution time
    
    # Reversibility
    reversible: bool = False
    reversal_action_id: str = ""        # Action that reverses this one
    reversal_cost: float = 0.0
    
    # Authorization requirements
    requires_authorization: bool = True
    authorization_capability: str = ""  # e.g., "network_scan", "exploit"
    authorization_impact: str = "low"   # low, medium, high
    
    # Tool/Capability requirements
    required_capabilities: list[str] = field(default_factory=list)
    
    # Metadata
    created_by: str = ""
    created_at: float = field(default_factory=time.time)
    tags: list[str] = field(default_factory=list)

    def check_preconditions(
        self, world: WorldModel, evidence_graph: EvidenceGraph,
        hypothesis_manager: HypothesisManager, contradiction_manager: ContradictionManager
    ) -> tuple[bool, list[str]]:
        """Check all preconditions. Returns (all_satisfied, list_of_failures)."""
        failures = []
        for pre in self.preconditions:
            satisfied, reason = pre.check(world, evidence_graph, hypothesis_manager, contradiction_manager)
            if not satisfied:
                failures.append(f"{pre.type.value}({pre.target}): {reason}")
        return len(failures) == 0, failures

    def estimate_utility(self, world: WorldModel) -> float:
        """
        Estimate utility of this action for current state.
        Higher = more desirable.
        """
        # Simple utility: impact / (cost + risk + 1)
        # In practice, would use more sophisticated utility function
        denominator = self.cost_estimate + self.risk_estimate + 1.0
        return self.impact_estimate / denominator

    def to_dict(self) -> dict:
        d = asdict(self)
        d["action_type"] = self.action_type.value
        d["preconditions"] = [asdict(p) for p in self.preconditions]
        d["effects"] = [asdict(e) for e in self.effects]
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Action":
        # Convert preconditions
        preconditions = []
        for p in d.get("preconditions", []):
            preconditions.append(Precondition(
                type=PreconditionType(p["type"]),
                target=p.get("target", ""),
                parameters=p.get("parameters", {}),
                min_confidence=p.get("min_confidence", 0.5),
                max_age_hours=p.get("max_age_hours", 168.0),
                capability_name=p.get("capability_name", ""),
                relationship_type=p.get("relationship_type", ""),
                source_entity=p.get("source_entity", ""),
                target_entity=p.get("target_entity", ""),
            ))
        
        # Convert effects
        effects = []
        for e in d.get("effects", []):
            effects.append(Effect(
                creates_entity=e.get("creates_entity"),
                creates_relationship=e.get("creates_relationship"),
                updates_hypothesis=e.get("updates_hypothesis"),
                adds_evidence=e.get("adds_evidence"),
                resolves_contradiction=e.get("resolves_contradiction"),
                creates_contradiction=e.get("creates_contradiction"),
                description=e.get("description", ""),
                certainty=e.get("certainty", 1.0),
            ))
        
        return cls(
            action_id=d.get("action_id", ""),
            name=d.get("name", ""),
            action_type=ActionType(d.get("action_type", "recon")),
            description=d.get("description", ""),
            preconditions=preconditions,
            effects=effects,
            cost_estimate=d.get("cost_estimate", 1.0),
            risk_estimate=d.get("risk_estimate", 0.0),
            impact_estimate=d.get("impact_estimate", 0.0),
            time_estimate_seconds=d.get("time_estimate_seconds", 10.0),
            reversible=d.get("reversible", False),
            reversal_action_id=d.get("reversal_action_id", ""),
            reversal_cost=d.get("reversal_cost", 0.0),
            requires_authorization=d.get("requires_authorization", True),
            authorization_capability=d.get("authorization_capability", ""),
            authorization_impact=d.get("authorization_impact", "low"),
            required_capabilities=d.get("required_capabilities", []),
            created_by=d.get("created_by", ""),
            created_at=d.get("created_at", time.time()),
            tags=d.get("tags", []),
        )


# ── Action Library ────────────────────────────────────────────────

def create_nmap_scan_action(target: str, evidence_id: str = "") -> Action:
    """Create an nmap scan action."""
    return Action(
        name=f"nmap_scan_{target}",
        action_type=ActionType.SCAN,
        description=f"Nmap service version scan of {target}",
        preconditions=[
            Precondition(type=PreconditionType.ENTITY_EXISTS, target="network_access"),
            Precondition(type=PreconditionType.CAPABILITY_AVAILABLE, capability_name="nmap"),
            Precondition(type=PreconditionType.AUTHORIZATION, parameters={"capability": "network_scan"}),
        ],
        effects=[
            Effect(
                adds_evidence={
                    "raw_content": f"Nmap scan of {target} - results pending",
                    "trust_level": "tool_observation",
                    "source_detail": f"nmap -sV {target}",
                    "target": target,
                    "phase": "scan",
                    "evidence_type": "port_scan",
                    "description": f"Nmap scan results for {target}",
                },
                description="Nmap scan produces version detection evidence",
                certainty=0.9,
            ),
        ],
        cost_estimate=2.0,
        risk_estimate=0.2,
        impact_estimate=3.0,
        time_estimate_seconds=30.0,
        requires_authorization=True,
        authorization_capability="network_scan",
        authorization_impact="low",
        required_capabilities=["nmap"],
        created_by="planner",
    )


def create_http_probe_action(target: str, path: str = "/", evidence_id: str = "") -> Action:
    """Create an HTTP probe action."""
    return Action(
        name=f"http_probe_{target}",
        action_type=ActionType.RECON,
        description=f"HTTP probe of {target}{path}",
        preconditions=[
            Precondition(type=PreconditionType.ENTITY_EXISTS, target="network_access"),
            Precondition(type=PreconditionType.CAPABILITY_AVAILABLE, capability_name="curl"),
            Precondition(type=PreconditionType.AUTHORIZATION, parameters={"capability": "http_request"}),
        ],
        effects=[
            Effect(
                adds_evidence={
                    "raw_content": f"HTTP probe of {target}{path} - results pending",
                    "trust_level": "tool_observation",
                    "source_detail": f"curl -I {target}{path}",
                    "target": target,
                    "phase": "recon",
                    "evidence_type": "http_probe",
                    "description": f"HTTP header probe of {target}{path}",
                },
                description="HTTP probe returns headers and status",
                certainty=0.95,
            ),
        ],
        cost_estimate=0.5,
        risk_estimate=0.05,
        impact_estimate=2.0,
        time_estimate_seconds=5.0,
        requires_authorization=True,
        authorization_capability="http_request",
        authorization_impact="low",
        required_capabilities=["curl"],
        created_by="planner",
    )


def create_iam_policy_check_action(role: str, resource: str) -> Action:
    """Create an IAM policy evaluation action."""
    return Action(
        name=f"iam_check_{role}",
        action_type=ActionType.RECON,
        description=f"Evaluate IAM permissions for {role} on {resource}",
        preconditions=[
            Precondition(type=PreconditionType.CAPABILITY_AVAILABLE, capability_name="aws_cli"),
            Precondition(type=PreconditionType.AUTHORIZATION, parameters={"capability": "iam_evaluate"}),
        ],
        effects=[
            Effect(
                adds_evidence={
                    "raw_content": f"IAM policy evaluation for {role} on {resource}",
                    "trust_level": "tool_observation",
                    "source_detail": "aws iam simulate-principal-policy",
                    "target": resource,
                    "phase": "cloud_abuse",
                    "evidence_type": "iam_policy",
                    "description": "IAM policy evaluation results",
                },
                description="IAM policy evaluation reveals effective permissions",
                certainty=0.9,
            ),
        ],
        cost_estimate=1.0,
        risk_estimate=0.1,
        impact_estimate=4.0,
        time_estimate_seconds=15.0,
        requires_authorization=True,
        authorization_capability="iam_evaluate",
        authorization_impact="low",
        required_capabilities=["aws"],
        created_by="planner",
    )


def create_exploit_action(cve: str, target: str, exploit_module: str) -> Action:
    """Create an exploitation action."""
    return Action(
        name=f"exploit_{cve}_{target}",
        action_type=ActionType.EXPLOIT,
        description=f"Exploit {cve} on {target} using {exploit_module}",
        preconditions=[
            Precondition(type=PreconditionType.HYPOTHESIS_CONFIDENCE, 
                        target="", min_confidence=0.7,
                        parameters={"statement_contains": cve}),
            Precondition(type=PreconditionType.CAPABILITY_AVAILABLE, capability_name=exploit_module),
            Precondition(type=PreconditionType.NO_CONTRADICTION, target=""),
            Precondition(type=PreconditionType.AUTHORIZATION, parameters={"capability": "exploit"}),
        ],
        effects=[
            Effect(
                updates_hypothesis={
                    "hypothesis_id": "",
                    "new_confidence": 0.9,
                    "status": "confirmed",
                },
                description=f"Successful exploitation confirms vulnerability {cve}",
                certainty=0.7,
            ),
            Effect(
                creates_entity={
                    "entity_type": "shell",
                    "identifiers": {"type": "reverse_shell", "target": target},
                    "evidence_ids": [],
                },
                description="Exploitation yields shell access",
                certainty=0.6,
            ),
        ],
        cost_estimate=5.0,
        risk_estimate=0.7,
        impact_estimate=8.0,
        time_estimate_seconds=60.0,
        reversible=False,
        requires_authorization=True,
        authorization_capability="exploit",
        authorization_impact="high",
        required_capabilities=[exploit_module, "metasploit"],
        created_by="planner",
        tags=["exploit", cve],
    )


def create_lateral_movement_action(source: str, target: str, technique: str) -> Action:
    """Create a lateral movement action."""
    return Action(
        name=f"lateral_{technique}_{source}_to_{target}",
        action_type=ActionType.LATERAL_MOVEMENT,
        description=f"Lateral movement from {source} to {target} via {technique}",
        preconditions=[
            Precondition(type=PreconditionType.RELATIONSHIP_EXISTS,
                        source_entity=source, target_entity=target,
                        relationship_type="connects_to"),
            Precondition(type=PreconditionType.CAPABILITY_AVAILABLE, capability_name=technique),
            Precondition(type=PreconditionType.AUTHORIZATION, parameters={"capability": "lateral_movement"}),
        ],
        effects=[
            Effect(
                creates_relationship={
                    "source": source,
                    "target": target,
                    "type": "compromised",
                    "evidence_ids": [],
                },
                description=f"Lateral movement establishes foothold on {target}",
                certainty=0.7,
            ),
        ],
        cost_estimate=3.0,
        risk_estimate=0.5,
        impact_estimate=6.0,
        time_estimate_seconds=45.0,
        requires_authorization=True,
        authorization_capability="lateral_movement",
        authorization_impact="high",
        required_capabilities=[technique],
        created_by="planner",
        tags=["lateral", technique],
    )


# ── Action Registry ──────────────────────────────────────────────

class ActionRegistry:
    """Registry of available actions for planning."""
    
    def __init__(self):
        self._actions: dict[str, Action] = {}
        self._by_type: dict[ActionType, list[str]] = {t: [] for t in ActionType}
        self._by_tag: dict[str, set[str]] = {}
        
        # Register built-in actions
        self._register_builtins()
    
    def _register_builtins(self):
        """Register template actions (these are instantiated with parameters)."""
        pass  # Templates are created by factory functions above
    
    def register(self, action: Action) -> str:
        """Register a concrete action instance."""
        self._actions[action.action_id] = action
        self._by_type[action.action_type].append(action.action_id)
        for tag in action.tags:
            if tag not in self._by_tag:
                self._by_tag[tag] = set()
            self._by_tag[tag].add(action.action_id)
        return action.action_id
    
    def get(self, action_id: str) -> Optional[Action]:
        return self._actions.get(action_id)
    
    def get_by_type(self, action_type: ActionType) -> list[Action]:
        return [self._actions[aid] for aid in self._by_type.get(action_type, [])]
    
    def get_by_tag(self, tag: str) -> list[Action]:
        return [self._actions[aid] for aid in self._by_tag.get(tag, set())]
    
    def get_applicable(
        self, world: WorldModel, evidence_graph: EvidenceGraph,
        hypothesis_manager: HypothesisManager, contradiction_manager: ContradictionManager,
        min_utility: float = 0.0
    ) -> list[Action]:
        """Return actions whose preconditions are satisfied, sorted by utility."""
        applicable = []
        for action in self._actions.values():
            satisfied, failures = action.check_preconditions(
                world, evidence_graph, hypothesis_manager, contradiction_manager
            )
            if satisfied:
                utility = action.estimate_utility(world)
                if utility >= min_utility:
                    applicable.append((utility, action))
        
        # Sort by utility descending
        applicable.sort(key=lambda x: x[0], reverse=True)
        return [a for _, a in applicable]


# ── D7-R1: Denial Lifecycle ───────────────────────────────────

class DenialClass(str, Enum):
    """Classification of a denial for lifecycle management.
    
    PERSISTENT: The denial is based on policy/scope/capability and will
    not change within the episode. Proposals with matching (action_type,
    target, capability) should be suppressed.
    
    TEMPORARY: The denial is based on rate limits, budget, or transient
    conditions that may resolve within the episode. Recorded for feedback
    but does NOT suppress proposals.
    """
    PERSISTENT = "persistent"
    TEMPORARY = "temporary"


@dataclass
class DenialRecord:
    """Structured record of a Broker DENIED receipt for Planner feedback.
    
    Stored in Planner.feedback_records for consumption as decision-relevant
    feedback on subsequent iterations.
    """
    action_type: str
    target: str
    capability: str = ""
    denial_class: DenialClass = DenialClass.PERSISTENT
    receipt_id: str = ""
    iteration: int = 0
    reason: str = ""
    timestamp: float = field(default_factory=time.time)


# ── Planner ──────────────────────────────────────────────────────

@dataclass
class Plan:
    """A sequence of actions to achieve a goal."""
    plan_id: str = field(default_factory=lambda: f"plan_{uuid.uuid4().hex[:12]}")
    goal: str = ""
    actions: list[Action] = field(default_factory=list)
    total_cost: float = 0.0
    total_risk: float = 0.0
    total_time: float = 0.0
    status: str = "pending"  # pending, executing, completed, failed
    created_at: float = field(default_factory=time.time)

    def add_action(self, action: Action):
        self.actions.append(action)
        self.total_cost += action.cost_estimate
        self.total_risk = max(self.total_risk, action.risk_estimate)
        self.total_time += action.time_estimate_seconds


# ── Denial classification helpers ───────────────────────────────

def _classify_denial(reason: str) -> DenialClass:
    """Classify a denial reason as PERSISTENT or TEMPORARY.
    
    Policy/scope/capability denials are PERSISTENT — they won't change
    within an episode. Rate/budget/transient denials are TEMPORARY —
    they may resolve.
    """
    reason_lower = reason.lower()
    # PERSISTENT indicators: policy, scope, capability, prohibited
    persistent_keywords = [
        "not in allowed", "prohibited", "target explicitly",
        "no allowed targets", "scope",
    ]
    # TEMPORARY indicators: rate, budget, time, concurrent
    temporary_keywords = [
        "rate", "budget", "impact", "time window", "concurrent",
        "max actions", "too many", "throttl",
    ]
    
    for kw in persistent_keywords:
        if kw in reason_lower:
            return DenialClass.PERSISTENT
    for kw in temporary_keywords:
        if kw in reason_lower:
            return DenialClass.TEMPORARY
    # Default: PERSISTENT (deny-by-default)
    return DenialClass.PERSISTENT


def _is_persistent_proposal_suppressed(
    action_type: str, target: str, capability: str,
    feedback_records: dict,
) -> bool:
    """Check if a proposal should be suppressed due to PERSISTENT denial feedback.
    
    A proposal is suppressed if there EXISTS a PERSISTENT DenialRecord
    with matching (action_type, target, capability).
    
    capability matching: if the denial record has a capability, it must
    match. If the denial record has no capability, only action_type+target
    must match (all-capability suppression).
    """
    for rec in feedback_records.values():
        if rec.denial_class != DenialClass.PERSISTENT:
            continue
        if rec.action_type != action_type:
            continue
        if rec.target != target:
            continue
        # If the denial has a capability, it must match
        if rec.capability and rec.capability != capability:
            continue
        return True  # Found a suppressing denial
    return False


class Planner:
    """
    Simple forward-chaining planner.
    
    Given a goal and current world state, find a sequence of actions
    that achieves the goal while respecting preconditions and authorization.
    """
    
    def __init__(
        self,
        world: WorldModel,
        evidence_graph: EvidenceGraph,
        hypothesis_manager: HypothesisManager,
        contradiction_manager: ContradictionManager,
        action_registry: ActionRegistry,
        chain_synthesizer: Optional[Any] = None,  # S1-B: PlannerAdvisor for chain readiness hints
    ):
        self.world = world
        self.evidence_graph = evidence_graph
        self.hypothesis_manager = hypothesis_manager
        self.contradiction_manager = contradiction_manager
        self.action_registry = action_registry
        # S1-B: Optional ChainSynthesizer for chain readiness scoring hints
        self.chain_synthesizer = chain_synthesizer
        self._chain_readiness_map: dict[str, float] = {}
        # Add contradiction_manager to registry for precondition checking
        self.action_registry.contradiction_manager = contradiction_manager
        # D7-R1: Typed denial lifecycle feedback records
        # Maps receipt_id -> DenialRecord for structured feedback consumption
        self.feedback_records: dict[str, DenialRecord] = {}
        # Episode iteration counter for denial record timestamps
        self._iteration: int = 0
    
    @property
    def unavailable_actions(self) -> set[tuple[str, str]]:
        """Backward-compatible property: (action_type, target) with PERSISTENT denial.
        
        Maintains compatibility with diagnostic code that reads this set.
        """
        return {
            (r.action_type, r.target)
            for r in self.feedback_records.values()
            if r.denial_class == DenialClass.PERSISTENT
        }
    
    @property
    def suppressed_proposals(self) -> set[tuple[str, str, str]]:
        """Full (action_type, target, capability) triples under active suppression."""
        return {
            (r.action_type, r.target, r.capability)
            for r in self.feedback_records.values()
            if r.denial_class == DenialClass.PERSISTENT
        }
    
    def _build_chain_readiness_map(self, confirmed_technique_ids: list[str] = None) -> dict[str, float]:
        """S1-B: Build a technique_id → readiness map from ChainSynthesizer.
        
        Calls ChainSynthesizer.suggest_next_steps() with confirmed technique IDs
        to obtain chain readiness hints. Each hint scores 0.0-1.0 based on
        how many preconditions for the next step are already satisfied.
        
        This map is consumed by the scoring loop in decide() to apply a
        weighted chain_readiness boost (0.15 weight) to matching candidates.
        
        Args:
            confirmed_technique_ids: Technique IDs confirmed from evidence/hypotheses
            
        Returns:
            Dict mapping technique_id → readiness (0.0-1.0)
        """
        self._chain_readiness_map = {}
        if self.chain_synthesizer is None:
            return self._chain_readiness_map
        
        try:
            confirmed = confirmed_technique_ids or []
            suggestions = self.chain_synthesizer.suggest_next_steps(confirmed)
            for s in suggestions:
                tid = s.get("technique_id", "")
                readiness = s.get("readiness", 0.0)
                if tid and readiness > 0:
                    self._chain_readiness_map[tid] = readiness
        except Exception as e:
            logger.debug("[Planner] ChainSynthesizer readiness: %s", e)
        
        return self._chain_readiness_map

    def _resolve_candidate_target(self, target: str):
        """Resolve a candidate target string to a WorldModel Entity.
        
        D11: Three resolution strategies:
        1. find_by_identifier(target) — IP/hostname lookup (original behavior)
        2. get_entity(target) — direct entity_id lookup if target starts with 'ent_'
        3. Hypothesis entity fallback — if target is literal 'target',
           resolve to first entity from active hypotheses
        
        Args:
            target: The target string from a candidate action dict
            
        Returns:
            WorldModel Entity if resolvable, None otherwise
        """
        if not hasattr(self, 'world') or not self.world:
            return None
        
        # Strategy 1: IP/hostname lookup
        if hasattr(self.world, 'find_by_identifier'):
            entity = self.world.find_by_identifier(target)
            if entity is not None:
                return entity
        
        # Strategy 2: Direct entity_id lookup (for 'ent_xxx' style targets)
        if target.startswith('ent_') and hasattr(self.world, 'get_entity'):
            entity = self.world.get_entity(target)
            if entity is not None:
                return entity
        
        # Strategy 3: Literal 'target' — resolve via hypothesis entities
        if target == 'target' and hasattr(self, 'hypothesis_manager') and self.hypothesis_manager:
            for hid in list(getattr(self.hypothesis_manager, '_hypotheses', {}).keys())[:5]:
                hyp = self.hypothesis_manager.get_hypothesis(hid)
                if hyp and hyp.entity_ids:
                    for eid in hyp.entity_ids[:3]:
                        if hasattr(self.world, 'get_entity'):
                            entity = self.world.get_entity(eid)
                            if entity is not None:
                                return entity
        
        return None

    def register_denial(
        self,
        action_type: str,
        target: str,
        capability: str = "",
        receipt_id: str = "",
        reason: str = "",
    ) -> None:
        """D7-R1: Register a DENIED receipt as structured feedback.
        
        Classifies the denial as PERSISTENT or TEMPORARY based on the
        broker's reason. PERSISTENT denials suppress future proposals
        of the same (action_type, target, capability). TEMPORARY denials
        are recorded but do not suppress.
        
        The Broker remains the sole authority deciding ALLOW/DENY.
        This method only closes the causal loop: DENIED output →
        consumed as decision-relevant feedback.
        
        Args:
            action_type: The action type that was denied
            target: The target identifier
            capability: The capability that was denied
            receipt_id: The Broker's receipt ID for traceability
            reason: Denial reason from the Broker
        """
        self._iteration += 1
        denial_class = _classify_denial(reason)
        rec_id = receipt_id or f"denial_{self._iteration}"
        
        self.feedback_records[rec_id] = DenialRecord(
            action_type=action_type,
            target=target,
            capability=capability,
            denial_class=denial_class,
            receipt_id=rec_id,
            iteration=self._iteration,
            reason=reason,
        )
    
    def plan(
        self,
        goal: str,
        target_entities: list[str] = None,
        max_depth: int = 5,
        max_cost: float = 50.0,
        max_risk: float = 1.0,
    ) -> Optional[Plan]:
        """
        Find a plan to achieve the goal.
        
        This is a simplified planner - in practice would use A*, MCTS, or similar.
        """
        # Parse goal into desired state
        # For now, simple goal: achieve CAN_ACCESS relationship
        if "can_access" in goal.lower() or "access" in goal.lower():
            return self._plan_can_access(goal, target_entities, max_depth, max_cost, max_risk)
        
        return None

    def decide(
        self,
        candidates: list[dict],
        objective_id: str,
        world_query_ids: tuple[str, ...] = (),
        hypothesis_ids: tuple[str, ...] = (),
        evidence_ids: tuple[str, ...] = (),
        planner_invocation_id: str = "",
        confirmed_technique_ids: tuple[str, ...] = (),  # S1-B: for chain readiness hints
    ) -> "PlanDecision":
        """
        Select the best action from a candidate set and return a PlanDecision.
        
        This is the causal intermediate between candidate generation and execution.
        Candidate generation happens BEFORE this method. The Planner does NOT
        influence the candidate set — it only scores and selects from what's given.
        
        S1-B: If a ChainSynthesizer is configured, confirmed_technique_ids are
        used to compute chain_readiness hints. Candidates with technique_ids
        matching a ready chain step receive a weighted scoring boost (0.15).
        
        Args:
            candidates: List of candidate action dicts from _generate_candidates
            objective_id: The objective this decision serves
            world_query_ids: WorldQueryResult IDs that informed this decision
            hypothesis_ids: Hypothesis IDs that informed this decision
            evidence_ids: Evidence IDs that informed this decision
            planner_invocation_id: Trace ID from planner invocation
            confirmed_technique_ids: S1-B: Technique IDs confirmed from evidence
                for ChainSynthesizer readiness computation
            
        Returns:
            PlanDecision with selected_action_id and rationale
        """
        # Lazy import to avoid circular dependency: arena.conclusion → arena.runner → action
        from arena.conclusion import PlanDecision

        if not candidates:
            return PlanDecision(
                decision_id=f"PD_{uuid.uuid4().hex[:12]}",
                objective_id=objective_id,
                planner_invocation_id=planner_invocation_id,
            )

        # D7-R1: Filter out candidates suppressed by PERSISTENT denial feedback.
        # PERSISTENT denials (policy/scope/capability) suppress the same proposal.
        # TEMPORARY denials (rate/budget) are recorded but do NOT suppress.
        # This closes the causal loop: DENIED receipts become decision-relevant
        # feedback without adding a Planner-level allowlist.
        filtered = []
        filtered_count = 0
        for c in candidates:
            if _is_persistent_proposal_suppressed(
                action_type=c.get("action_type", ""),
                target=c.get("target", ""),
                capability=c.get("capability", ""),
                feedback_records=self.feedback_records,
            ):
                filtered_count += 1
                continue  # Skip — PERSISTENT denial feedback for this proposal
            filtered.append(c)
        candidates = filtered
        
        # Candidate exhaustion: if all candidates are suppressed by PERSISTENT
        # denial feedback, return a clean termination decision rather than
        # resurrecting denied candidates or crashing.
        if not candidates:
            return PlanDecision(
                decision_id=f"PD_{uuid.uuid4().hex[:12]}",
                objective_id=objective_id,
                planner_invocation_id=planner_invocation_id,
                rationale_codes=("all_candidates_suppressed_by_denial_feedback",),
            )

        # S1-B: Build chain_readiness map from ChainSynthesizer (if configured).
        # Uses confirmed_technique_ids to determine which attack chain steps
        # have their preconditions satisfied and are ready for execution.
        self._build_chain_readiness_map(list(confirmed_technique_ids))

        # Score each candidate using the same utility logic as before
        scored = []
        for c in candidates:
            utility_score = 0.5  # Base score
            rationale_codes = []  # Track rationale for this candidate

            # D11: Resolve candidate target to WorldModel entity for scoring
            # Uses _resolve_candidate_target() which handles IP, entity_id, and
            # hypothesis-based resolution for falsification/defeater targets.
            target_entity_id = None
            target_entity_resolved = self._resolve_candidate_target(c.get("target", ""))
            if target_entity_resolved:
                utility_score += 0.3  # Known entity
                target_entity_id = target_entity_resolved.entity_id
                # Check for existing relationships
                if hasattr(self.world, 'get_relationships'):
                    rels = self.world.get_relationships(source=target_entity_resolved.entity_id)
                    if rels:
                        utility_score += 0.2  # Has relationships to explore

            # D11: Falsification candidates get priority
            # Base +0.4 boost. If linked to an active contradiction, +0.6 extra
            # to ensure falsification probes rank above generic scans.
            if c.get("_is_falsification"):
                falsification_boost = 0.4  # Base falsification priority
                # Check for active contradictions using both entity_id and raw target
                # (contradiction index may use IPs while entity_id is "ent_xxx")
                has_active_contradiction = False
                if self.contradiction_manager:
                    # Check by entity_id
                    if target_entity_id:
                        active_conts = self.contradiction_manager.get_contradictions_for_entity(target_entity_id)
                        if any(con.status in (ContradictionStatus.DETECTED, ContradictionStatus.UNDER_INVESTIGATION) for con in active_conts):
                            has_active_contradiction = True
                    # Also check by raw target (IP/hostname) as fallback
                    if not has_active_contradiction:
                        raw_target = c.get("target", "")
                        if raw_target:
                            active_conts = self.contradiction_manager.get_contradictions_for_entity(raw_target)
                            if any(con.status in (ContradictionStatus.DETECTED, ContradictionStatus.UNDER_INVESTIGATION) for con in active_conts):
                                has_active_contradiction = True
                if has_active_contradiction:
                    falsification_boost += 0.6  # Extra boost for active contradiction
                    rationale_codes.append("falsification_contradiction_resolution")
                utility_score += falsification_boost
                rationale_codes.append("falsification_priority")

            # Version detection scans get priority for finding service versions
            # But only if version info isn't already available for this target
            version_already_known = False
            if self.evidence_graph and c.get("target"):
                for ev in self.evidence_graph.get_all_evidence():
                    ev_content = getattr(ev, 'raw_content', '') or ''
                    if c["target"] in ev_content and ('version' in ev_content.lower() or 'Server:' in ev_content):
                        version_already_known = True
                        break
            if c["action_type"] in ("scan", "recon") and c.get("method") == "all" and not version_already_known:
                utility_score += 0.35  # Version detection is valuable for identifying services

            # Novelty bonus
            # (Would need access to executed actions - simplified here)

            # Concrete action bonus
            if c["action_type"] in ("http_get", "ssh_banner", "arp_query",
                                     "ssh_exec", "ssh_handshake", "http_options",
                                     "banner_grab", "direct_probe"):
                utility_score += 0.2

            # E1 Shell action scoring
            if c["action_type"] == "shell_connect":
                utility_score += 0.3  # High value: enables command execution
            elif c["action_type"] == "shell_command":
                utility_score += 0.4  # Highest: direct execution within session
            elif c["action_type"] == "shell_disconnect":
                utility_score += 0.1  # Cleanup: less urgent

            # Estimate cost/risk
            cost_estimate = 1.0
            risk_estimate = 0.1
            if c["action_type"] in ("scan", "recon", "enumerate"):
                cost_estimate = 2.0
                risk_estimate = 0.2
            elif c["action_type"] in ("http_get", "ssh_banner", "ssh_handshake"):
                cost_estimate = 1.0
                risk_estimate = 0.1
            elif c["action_type"] in ("ssh_exec", "direct_probe"):
                cost_estimate = 3.0
                risk_estimate = 0.4
            elif c["action_type"] == "shell_connect":
                cost_estimate = 5.0  # Higher cost: interactive session
                risk_estimate = 0.5  # Higher risk: bidirectional access
            elif c["action_type"] == "shell_command":
                cost_estimate = 2.0  # Low cost per command
                risk_estimate = 0.3  # Moderate risk per command
            elif c["action_type"] == "shell_disconnect":
                cost_estimate = 0.5  # Cleanup: trivial
                risk_estimate = 0.0  # No risk

            # D-4: Hypothesis-driven scoring boost
            # If we have hypotheses with semantic_inference_ids (LLM-derived),
            # boost candidates that target the same entities
            # D11: Uses already-resolved target_entity_id from _resolve_candidate_target().
            rationale_codes = []
            if hypothesis_ids and self.hypothesis_manager:
                for hid in hypothesis_ids:
                    hyp = self.hypothesis_manager.get_hypothesis(hid)
                    if hyp and hyp.semantic_inference_ids:
                        # Boost if candidate targets same entity as hypothesis
                        # (target_entity_id is already resolved by _resolve_candidate_target above)
                        if target_entity_id and target_entity_id in hyp.entity_ids:
                            utility_score += 0.5  # Strong boost for SI-derived hypothesis relevance
                            rationale_codes.append("semantic_inference_driven")
                            break
                        # Also boost if candidate is evidence-seeking for that hypothesis
                        if c["action_type"] in ("direct_probe", "http_get", "ssh_banner", "banner_grab", "ssh_handshake"):
                            # These actions can provide evidence for the hypothesis
                            utility_score += 0.25
                            if "semantic_inference_driven" not in rationale_codes:
                                rationale_codes.append("semantic_inference_driven")
                            break

            # D11: Defeater candidates get priority
            # Base +0.4 boost. Additional +0.3 if linked to active contradiction.
            # Additional +0.3 if has a fresh defeater trigger.
            if c.get("_is_defeater"):
                defeater_boost = 0.4  # Base defeater priority
                # Check for active contradictions using both entity_id and raw target
                has_active_contradiction = False
                if self.contradiction_manager:
                    if target_entity_id:
                        active_conts = self.contradiction_manager.get_contradictions_for_entity(target_entity_id)
                        if any(con.status in (ContradictionStatus.DETECTED, ContradictionStatus.UNDER_INVESTIGATION) for con in active_conts):
                            has_active_contradiction = True
                    if not has_active_contradiction:
                        raw_target = c.get("target", "")
                        if raw_target:
                            active_conts = self.contradiction_manager.get_contradictions_for_entity(raw_target)
                            if any(con.status in (ContradictionStatus.DETECTED, ContradictionStatus.UNDER_INVESTIGATION) for con in active_conts):
                                has_active_contradiction = True
                if has_active_contradiction:
                    defeater_boost += 0.3  # Extra boost linked to contradiction
                    if "defeater_contradiction_link" not in rationale_codes:
                        rationale_codes.append("defeater_contradiction_link")
                if c.get("defeater_trigger_id"):
                    defeater_boost += 0.3  # Fresh trigger
                    if "defeater_fresh_trigger" not in rationale_codes:
                        rationale_codes.append("defeater_fresh_trigger")
                utility_score += defeater_boost
                if "defeater_priority" not in rationale_codes:
                    rationale_codes.append("defeater_priority")

            # S1-B: ChainSynthesizer readiness boost.
            # If this candidate's technique_id matches a step that the
            # ChainSynthesizer reports as ready (high precondition satisfaction),
            # apply a weighted boost of 0.15 * readiness.
            # Weight 0.15 ensures falsification (+0.4 to +1.0) and defeater
            # (+0.4 to +1.0) priorities are NOT overridden.
            tech_id = c.get("technique_id", "")
            if tech_id and tech_id in self._chain_readiness_map:
                readiness = self._chain_readiness_map.get(tech_id, 0.0)
                chain_boost = 0.15 * readiness
                if chain_boost > 0.001:
                    utility_score += chain_boost
                    if "chain_readiness_boost" not in rationale_codes:
                        rationale_codes.append("chain_readiness_boost")

            scored.append((utility_score, c, cost_estimate, risk_estimate, rationale_codes))

        # Sort by utility descending
        scored.sort(key=lambda x: x[0], reverse=True)

        # Find first authorized candidate (highest utility that passes broker check)
        selected = None
        rejected = []
        selected_rationale = []
        selected_cost = 0.0
        selected_risk = 1.0
        for score, c, cost, risk, rc in scored:
            # Check if action would be allowed (simplified)
            # In reality, would check against broker policy
            allowed = True  # Assume allowed for planning purposes
            if allowed:
                selected = c
                selected_rationale = rc
                selected_cost = cost
                selected_risk = risk
                break  # Take highest-scoring authorized candidate
            else:
                rejected.append(c.get("action_id", c.get("action_type", "unknown")))
        
        if selected is None:
            selected = scored[0][1]
            selected_rationale = scored[0][4]
            selected_cost = scored[0][2]
            selected_risk = scored[0][3]
        
        # Build PlanDecision
        considered_ids = [c.get("action_id", f"{c['action_type']}_{c['target']}") for _, c, _, _, _ in scored]
        rejected_ids = [c.get("action_id", f"{c['action_type']}_{c['target']}") for _, c, _, _, _ in scored if c != selected]
        selected_id = selected.get("action_id", f"{selected['action_type']}_{selected['target']}")
        
        # Determine rationale - use the selected candidate's rationale
        rationale_codes = list(selected_rationale)
        # D11: De-duplicated post-selection rationale codes.
        # Falsification and defeater codes are now tracked during per-candidate
        # scoring and carried through selected_rationale. Post-selection adds
        # only codes that weren't already captured.
        if selected.get("_is_falsification") and "falsification_priority" not in rationale_codes:
            rationale_codes.append("falsification_priority")
        if selected.get("_is_defeater") and "defeater_priority" not in rationale_codes:
            rationale_codes.append("defeater_priority")
        if world_query_ids:
            rationale_codes.append("world_model_context")
        if hypothesis_ids:
            rationale_codes.append("hypothesis_driven")
        if selected["action_type"] in ("http_get", "ssh_banner", "ssh_handshake"):
            rationale_codes.append("concrete_action_preferred")
        if selected["action_type"] == "shell_connect":
            rationale_codes.append("shell_connect_initiated")
        if selected["action_type"] == "shell_command":
            rationale_codes.append("shell_command_execution")
        if selected["action_type"] == "shell_disconnect":
            rationale_codes.append("shell_session_cleanup")
        
        return PlanDecision(
            decision_id=f"PD_{uuid.uuid4().hex[:12]}",
            objective_id=objective_id,
            considered_action_ids=tuple(considered_ids),
            rejected_action_ids=tuple(rejected_ids),
            selected_action_id=selected_id,
            rationale_codes=tuple(rationale_codes),
            estimated_cost=selected_cost,
            estimated_risk=selected_risk,
            estimated_utility=scored[0][0] if scored else 0.0,
            supporting_evidence_ids=evidence_ids,
            supporting_world_query_ids=world_query_ids,
            supporting_hypothesis_ids=hypothesis_ids,
            planner_invocation_id=planner_invocation_id,
        )
    def _plan_can_access(
        self,
        goal: str,
        target_entities: list[str],
        max_depth: int,
        max_cost: float,
        max_risk: float,
    ) -> Optional[Plan]:
        """
        Plan to achieve CAN_ACCESS to target resources.
        
        Strategy:
        1. Find identities that can access the resource (via IAM, network, etc.)
        2. Find ways to assume those identities (credentials, role assumption, etc.)
        3. Plan path from current position to target identity
        """
        # This is a placeholder - full implementation would do graph search
        # over the world model's relationship graph
        plan = Plan(goal=goal)
        
        # For now, return a simple reconnaissance plan
        if self.world.entities:
            # Pick first asset as target
            asset_id = list(self.world.entities.keys())[0]
            
            # Add nmap scan
            scan_action = create_nmap_scan_action("target")
            plan.add_action(scan_action)
            
            # Add HTTP probe
            probe_action = create_http_probe_action("target")
            plan.add_action(probe_action)
            
            # Add IAM check if cloud asset
            iam_action = create_iam_policy_check_action("role", "resource")
            plan.add_action(iam_action)
        
        return plan if plan.actions else None


# ── Execution Engine ─────────────────────────────────────────────

class ExecutionEngine:
    """
    Executes plans through the CapabilityBroker.
    
    Each action becomes an ActionProposal -> ActionReceipt lifecycle.
    """
    
    def __init__(
        self,
        world: WorldModel,
        evidence_graph: EvidenceGraph,
        hypothesis_manager: HypothesisManager,
        contradiction_manager: ContradictionManager,
        # broker: 'CapabilityBroker',  # To be implemented
    ):
        self.world = world
        self.evidence_graph = evidence_graph
        self.hypothesis_manager = hypothesis_manager
        self.contradiction_manager = contradiction_manager
        # self.broker = broker
        
        self.active_receipts: dict[str, ActionReceipt] = {}
        self.execution_log: list[dict] = []
    
    def execute_plan(self, plan: Plan) -> dict:
        """Execute a plan step by step."""
        results = {
            "plan_id": plan.plan_id,
            "goal": plan.goal,
            "steps": [],
            "overall_success": True,
        }
        
        for i, action in enumerate(plan.actions):
            step_result = self.execute_action(action)
            results["steps"].append(step_result)
            
            if not step_result["success"]:
                results["overall_success"] = False
                # Could implement rollback/replanning here
                break
        
        return results
    
    def execute_action(self, action: Action) -> dict:
        """Execute a single action through the authorization pipeline."""
        # 1. Create proposal
        proposal = create_proposal(
            target=action.preconditions[0].target if action.preconditions else "unknown",
            capability=action.authorization_capability or action.action_type.value,
            method="auto",
            impact_estimate=action.impact_estimate,
        )
        
        # 2. Authorize (would go through CapabilityBroker)
        # For now, auto-authorize if risk is low
        if action.risk_estimate <= 0.3:
            proposal = authorize(proposal, reason="Low risk auto-authorized", 
                                policy_version="1.0", authorized_by="auto")
        else:
            proposal = deny(proposal, reason="Risk exceeds auto-authorization threshold",
                          policy_version="1.0", authorized_by="auto")
        
        # 3. Execute if authorized
        if proposal.status == ActionProposalStatus.AUTHORIZED:
            proposal = start_execution(proposal)
            
            # Simulate execution (in reality, would call actual tool)
            time.sleep(min(action.time_estimate_seconds, 0.1))  # Cap at 0.1s for testing
            
            # Simulate success
            success = True  # In reality, would call actual capability
            result = f"Action {action.name} executed"
            evidence_ids = []
            
            # Apply effects to world model
            self._apply_effects(action)
            
            proposal = complete_execution(proposal, success=success, 
                                          result=result, evidence_ids=evidence_ids)
        else:
            success = False
            result = f"Action denied: {proposal.reason}"
        
        return {
            "action_id": action.action_id,
            "action_name": action.name,
            "success": success,
            "result": result,
            "receipt_id": proposal.action_id,
            "receipt_status": proposal.status.value,
        }
    
    def _apply_effects(self, action: Action):
        """Apply action effects to world model and evidence graph."""
        for effect in action.effects:
            if effect.adds_evidence:
                ev_data = effect.adds_evidence
                ev = Evidence.create(
                    raw_content=ev_data.get("raw_content", ""),
                    trust_level=TrustLevel(ev_data.get("trust_level", "tool_observation")),
                    source_detail=ev_data.get("source_detail", ""),
                    target=ev_data.get("target", ""),
                    phase=ev_data.get("phase", "execution"),
                    evidence_type=ev_data.get("evidence_type", "action_result"),
                    description=ev_data.get("description", ""),
                )
                self.evidence_graph.add_evidence(ev)
            
            if effect.creates_entity:
                entity_data = effect.creates_entity
                # Would create entity in world model
                pass
            
            if effect.creates_relationship:
                rel_data = effect.creates_relationship
                # Would create relationship in world model
                pass
            
            if effect.resolves_contradiction:
                # Would mark contradiction as resolved
                pass


# ── Factory for common planning scenarios ───────────────────────

def create_recon_plan(target: str) -> Plan:
    """Create a standard reconnaissance plan for a target."""
    plan = Plan(goal=f"reconnaissance of {target}")
    
    plan.add_action(create_nmap_scan_action(target))
    plan.add_action(create_http_probe_action(target))
    
    return plan


def create_cloud_recon_plan(account_id: str) -> Plan:
    """Create a cloud reconnaissance plan."""
    plan = Plan(goal=f"cloud reconnaissance of account {account_id}")
    
    # Add IAM checks, resource enumeration, etc.
    plan.add_action(create_iam_policy_check_action("role", "resource"))
    
    return plan