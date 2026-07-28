"""evidence.py — Immutable evidence graph with provenance and relationships.

Core invariants:

1. Evidence is IMMUTABLE. Once created, it never changes.
   If Raphael changes its mind, it creates a new HYPOTHESIS — not a
   modified evidence record.

2. Every piece of evidence carries its provenance:
   - trust_level (SYSTEM_POLICY, OPERATOR_INSTRUCTION, ENGAGEMENT_CONFIG,
                   TOOL_OBSERVATION, TARGET_CONTROLLED, MODEL_INFERENCE)
   - source_detail (tool name, URL, command, LLM call, etc.)
   - collected_at (timestamp)
   - collected_by (action_receipt_id that produced it)

3. Relationships are separate from the evidence objects:
   - derived_from → provenance DAG (evidence chain of custody)
   - supports / contradicts / correlates_with → semantic graph

4. Entity resolution uses hypothesis states:
   - POSSIBLY_SAME_AS → CONFIRMED_SAME_AS
   - Each resolution step requires evidence

Schema version: 1
"""

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Optional

from orchestrator.brain.trust import TrustLevel


class EvidenceRelationType(str, Enum):
    """Semantic relationships between evidence items."""
    DERIVED_FROM = "derived_from"          # Provenance DAG: B was derived from A
    SUPPORTS = "supports"                  # B supports the claim in A
    CONTRADICTS = "contradicts"            # B contradicts the claim in A
    CORRELATES_WITH = "correlates_with"    # B is related to A but neither supports nor contradicts
    CONTAINS = "contains"                  # Structural: evidence A contains evidence B


class EntityResolutionState(str, Enum):
    """State of entity identity resolution."""
    SEPARATE = "separate"                  # Distinct entities
    POSSIBLY_SAME_AS = "possibly_same_as"  # Hypothesis: may be same entity
    CONFIRMED_SAME_AS = "confirmed_same_as" # Confirmed: same entity


@dataclass(frozen=True)
class Evidence:
    """
    Immutable evidence record.

    Once created, no field may be modified. All relationships and
    derived conclusions are maintained separately in EvidenceGraph.
    """
    # Schema and identity
    schema_version: int = 1
    evidence_id: str = field(default_factory=lambda: f"ev_{uuid.uuid4().hex[:12]}")
    content_hash: str = ""

    # Provenance (immutable, set at creation)
    trust_level: TrustLevel = TrustLevel.TOOL_OBSERVATION
    source_detail: str = ""
    collected_at: float = field(default_factory=time.time)
    collected_by: str = ""  # action_receipt_id that produced this evidence

    # Content
    raw_content: str = ""           # Raw bytes/text as observed
    structured_content: dict = field(default_factory=dict)  # Parsed/structured form

    # Context
    target: str = ""                # Target entity (IP, hostname, etc.)
    entity_hint: str = ""           # Suggested entity ID if known
    phase: str = ""                 # Phase that produced this

    # Type classification
    evidence_type: str = ""         # e.g., "port_scan", "http_response", "file_content"
    description: str = ""           # Human-readable summary

    def __post_init__(self):
        """Compute content_hash after all fields are set."""
        if not self.content_hash:
            # Hash the immutable content fields
            content = {
                "trust_level": self.trust_level.value,
                "source_detail": self.source_detail,
                "collected_at": self.collected_at,
                "collected_by": self.collected_by,
                "raw_content": self.raw_content,
                "structured_content": self.structured_content,
                "target": self.target,
                "entity_hint": self.entity_hint,
                "phase": self.phase,
                "evidence_type": self.evidence_type,
                "description": self.description,
            }
            raw = json.dumps(content, sort_keys=True, default=str)
            object.__setattr__(self, "content_hash", hashlib.sha256(raw.encode()).hexdigest())

    def to_dict(self) -> dict:
        """Serialize to dictionary (including computed hash)."""
        d = asdict(self)
        # Convert TrustLevel to string
        d["trust_level"] = self.trust_level.value
        return d

    @classmethod
    def create(
        cls,
        raw_content: str,
        trust_level: TrustLevel,
        source_detail: str,
        target: str = "",
        entity_hint: str = "",
        phase: str = "",
        evidence_type: str = "",
        description: str = "",
        structured_content: dict = None,
        collected_by: str = "",
    ) -> "Evidence":
        """Factory method to create Evidence with auto-generated ID and hash."""
        return cls(
            trust_level=trust_level,
            source_detail=source_detail,
            raw_content=raw_content,
            structured_content=structured_content or {},
            target=target,
            entity_hint=entity_hint,
            phase=phase,
            evidence_type=evidence_type,
            description=description,
            collected_by=collected_by,
        )


@dataclass
class EvidenceRelation:
    """A directed, labeled relationship between two evidence items."""
    schema_version: int = 1
    relation_id: str = field(default_factory=lambda: f"rel_{uuid.uuid4().hex[:12]}")
    from_evidence_id: str = ""
    to_evidence_id: str = ""
    relation_type: EvidenceRelationType = EvidenceRelationType.CORRELATES_WITH
    rationale: str = ""              # Why this relationship was asserted
    asserted_by: str = ""            # "analyst", "automated", "llm_inference", etc.
    timestamp: float = field(default_factory=time.time)
    confidence: float = 1.0          # Confidence in the relationship itself (0-1)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["relation_type"] = self.relation_type.value
        return d


@dataclass
class EntityIdentity:
    """Represents a resolved or hypothesized entity in the world model."""
    schema_version: int = 1
    entity_id: str = field(default_factory=lambda: f"ent_{uuid.uuid4().hex[:12]}")
    primary_identifier: str = ""     # Canonical name (e.g., "10.0.1.10")
    aliases: list[str] = field(default_factory=list)  # Other names for this entity

    # Resolution state
    resolution_state: EntityResolutionState = EntityResolutionState.SEPARATE
    resolved_with: list[str] = field(default_factory=list)  # Other entity_ids

    # Evidence supporting this identity
    evidence_ids: list[str] = field(default_factory=list)

    # Type hints
    entity_type: str = ""            # e.g., "host", "service", "identity", "cloud_resource"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["resolution_state"] = self.resolution_state.value
        return d


@dataclass
class EntityResolution:
    """Record of an entity identity resolution hypothesis."""
    schema_version: int = 1
    resolution_id: str = field(default_factory=lambda: f"res_{uuid.uuid4().hex[:12]}")
    entity_a_id: str = ""
    entity_b_id: str = ""
    proposed_state: EntityResolutionState = EntityResolutionState.POSSIBLY_SAME_AS
    supporting_evidence: list[str] = field(default_factory=list)
    contradicting_evidence: list[str] = field(default_factory=list)
    rationale: str = ""
    proposed_by: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["proposed_state"] = self.proposed_state.value
        return d


class EvidenceGraph:
    """
    Manages the evidence graph: evidence, relationships, and entity resolution.

    All operations that add structure (relations, resolutions) return new
    objects; the graph itself is the mutable index, but evidence objects
    remain immutable.
    """

    def __init__(self):
        self._evidence: dict[str, Evidence] = {}
        self._relations: list[EvidenceRelation] = []
        self._entities: dict[str, EntityIdentity] = {}
        self._resolutions: list[EntityResolution] = []

    # ── Evidence management ──────────────────────────────────────

    def add_evidence(self, evidence: Evidence) -> str:
        """Add evidence to the graph. Returns evidence_id."""
        if evidence.evidence_id in self._evidence:
            raise ValueError(f"Evidence {evidence.evidence_id} already exists")
        self._evidence[evidence.evidence_id] = evidence
        return evidence.evidence_id

    def get_evidence(self, evidence_id: str) -> Optional[Evidence]:
        return self._evidence.get(evidence_id)

    def get_all_evidence(self) -> list[Evidence]:
        return list(self._evidence.values())

    def get_evidence_for_target(self, target: str) -> list[Evidence]:
        return [e for e in self._evidence.values() if e.target == target]

    def get_evidence_by_type(self, evidence_type: str) -> list[Evidence]:
        return [e for e in self._evidence.values() if e.evidence_type == evidence_type]

    # ── Provenance DAG (derived_from) ────────────────────────────

    def add_derived_from(self, child_id: str, parent_id: str, rationale: str = "",
                         asserted_by: str = "automated", confidence: float = 1.0) -> str:
        """Record that child evidence was derived from parent evidence."""
        rel = EvidenceRelation(
            from_evidence_id=child_id,
            to_evidence_id=parent_id,
            relation_type=EvidenceRelationType.DERIVED_FROM,
            rationale=rationale,
            asserted_by=asserted_by,
            confidence=confidence,
        )
        self._relations.append(rel)
        return rel.relation_id

    def get_provenance_chain(self, evidence_id: str, max_depth: int = 10) -> list[Evidence]:
        """Walk the derived_from chain upward from evidence_id."""
        chain = []
        current_id = evidence_id
        depth = 0
        while depth < max_depth:
            # Find relations where current_id is the child (from_evidence_id)
            parents = [r for r in self._relations
                       if r.from_evidence_id == current_id
                       and r.relation_type == EvidenceRelationType.DERIVED_FROM]
            if not parents:
                break
            # Take the first parent (could have multiple in complex cases)
            parent = parents[0]
            parent_ev = self.get_evidence(parent.to_evidence_id)
            if not parent_ev:
                break
            chain.append(parent_ev)
            current_id = parent.to_evidence_id
            depth += 1
        return chain

    # ── Semantic relationships ───────────────────────────────────

    def add_support(self, supporter_id: str, supported_id: str, rationale: str = "",
                    asserted_by: str = "automated", confidence: float = 1.0) -> str:
        rel = EvidenceRelation(
            from_evidence_id=supporter_id,
            to_evidence_id=supported_id,
            relation_type=EvidenceRelationType.SUPPORTS,
            rationale=rationale,
            asserted_by=asserted_by,
            confidence=confidence,
        )
        self._relations.append(rel)
        return rel.relation_id

    def add_contradiction(self, contradictor_id: str, contradicted_id: str, rationale: str = "",
                          asserted_by: str = "automated", confidence: float = 1.0) -> str:
        rel = EvidenceRelation(
            from_evidence_id=contradictor_id,
            to_evidence_id=contradicted_id,
            relation_type=EvidenceRelationType.CONTRADICTS,
            rationale=rationale,
            asserted_by=asserted_by,
            confidence=confidence,
        )
        self._relations.append(rel)
        return rel.relation_id

    def add_correlation(self, a_id: str, b_id: str, rationale: str = "",
                        asserted_by: str = "automated", confidence: float = 1.0) -> str:
        rel = EvidenceRelation(
            from_evidence_id=a_id,
            to_evidence_id=b_id,
            relation_type=EvidenceRelationType.CORRELATES_WITH,
            rationale=rationale,
            asserted_by=asserted_by,
            confidence=confidence,
        )
        self._relations.append(rel)
        return rel.relation_id

    def get_supporters(self, evidence_id: str) -> list[Evidence]:
        rels = [r for r in self._relations
                if r.to_evidence_id == evidence_id
                and r.relation_type == EvidenceRelationType.SUPPORTS]
        return [self.get_evidence(r.from_evidence_id) for r in rels if self.get_evidence(r.from_evidence_id)]

    def get_contradictors(self, evidence_id: str) -> list[Evidence]:
        rels = [r for r in self._relations
                if r.to_evidence_id == evidence_id
                and r.relation_type == EvidenceRelationType.CONTRADICTS]
        return [self.get_evidence(r.from_evidence_id) for r in rels if self.get_evidence(r.from_evidence_id)]

    def get_contradictions(self, evidence_id: str) -> list[tuple[Evidence, EvidenceRelation]]:
        """Return (contradicting_evidence, relation) pairs for evidence_id."""
        results = []
        for r in self._relations:
            if r.to_evidence_id == evidence_id and r.relation_type == EvidenceRelationType.CONTRADICTS:
                ev = self.get_evidence(r.from_evidence_id)
                if ev:
                    results.append((ev, r))
        return results

    # ── Entity resolution ────────────────────────────────────────

    def add_entity(self, entity: EntityIdentity) -> str:
        if entity.entity_id in self._entities:
            raise ValueError(f"Entity {entity.entity_id} already exists")
        self._entities[entity.entity_id] = entity
        return entity.entity_id

    def get_entity(self, entity_id: str) -> Optional[EntityIdentity]:
        return self._entities.get(entity_id)

    def find_entity_by_identifier(self, identifier: str) -> Optional[EntityIdentity]:
        for ent in self._entities.values():
            if ent.primary_identifier == identifier or identifier in ent.aliases:
                return ent
        return None

    def propose_same_as(self, entity_a_id: str, entity_b_id: str,
                        evidence_ids: list[str], rationale: str = "",
                        proposed_by: str = "automated") -> str:
        """Propose that two entity IDs represent the same real-world entity."""
        res = EntityResolution(
            entity_a_id=entity_a_id,
            entity_b_id=entity_b_id,
            proposed_state=EntityResolutionState.POSSIBLY_SAME_AS,
            supporting_evidence=evidence_ids,
            rationale=rationale,
            proposed_by=proposed_by,
        )
        self._resolutions.append(res)
        return res.resolution_id

    def confirm_same_as(self, resolution_id: str, additional_evidence: list[str] = None) -> bool:
        """Confirm a POSSIBLY_SAME_AS hypothesis as CONFIRMED_SAME_AS."""
        for res in self._resolutions:
            if res.resolution_id == resolution_id:
                if res.proposed_state == EntityResolutionState.POSSIBLY_SAME_AS:
                    object.__setattr__(res, "proposed_state", EntityResolutionState.CONFIRMED_SAME_AS)
                    if additional_evidence:
                        res.supporting_evidence.extend(additional_evidence)
                    # Merge entity aliases
                    ent_a = self.get_entity(res.entity_a_id)
                    ent_b = self.get_entity(res.entity_b_id)
                    if ent_a and ent_b:
                        # Merge B into A
                        ent_a.aliases.extend(ent_b.aliases)
                        ent_a.aliases.extend([ent_b.primary_identifier])
                        ent_a.evidence_ids.extend(ent_b.evidence_ids)
                    return True
        return False

    def get_resolution(self, resolution_id: str) -> Optional[EntityResolution]:
        for r in self._resolutions:
            if r.resolution_id == resolution_id:
                return r
        return None

    def get_entity_resolutions(self, entity_id: str) -> list[EntityResolution]:
        return [r for r in self._resolutions
                if r.entity_a_id == entity_id or r.entity_b_id == entity_id]

    # ── Queries ──────────────────────────────────────────────────

    def get_evidence_neighborhood(self, evidence_id: str, depth: int = 2) -> dict:
        """Get evidence, its supporters, contradictors, and provenance up to depth."""
        ev = self.get_evidence(evidence_id)
        if not ev:
            return {"error": "Evidence not found"}

        result = {
            "center": ev.to_dict(),
            "provenance": [e.to_dict() for e in self.get_provenance_chain(evidence_id, max_depth=depth)],
            "supporters": [e.to_dict() for e in self.get_supporters(evidence_id)],
            "contradictors": [e.to_dict() for e in self.get_contradictors(evidence_id)],
        }
        return result

    def find_contradictions(self) -> list[tuple[Evidence, Evidence, EvidenceRelation]]:
        """Find all CONTRADICTS pairs in the graph."""
        results = []
        for r in self._relations:
            if r.relation_type == EvidenceRelationType.CONTRADICTS:
                a = self.get_evidence(r.from_evidence_id)
                b = self.get_evidence(r.to_evidence_id)
                if a and b:
                    results.append((a, b, r))
        return results

    def get_all_relations(self) -> list[EvidenceRelation]:
        return list(self._relations)

    def stats(self) -> dict:
        return {
            "evidence_count": len(self._evidence),
            "relation_count": len(self._relations),
            "entity_count": len(self._entities),
            "resolution_count": len(self._resolutions),
            "contradiction_pairs": len(self.find_contradictions()),
        }


# ── Global instance (can be replaced by per-engagement instances) ──
_evidence_graph: Optional[EvidenceGraph] = None


def get_evidence_graph() -> EvidenceGraph:
    global _evidence_graph
    if _evidence_graph is None:
        _evidence_graph = EvidenceGraph()
    return _evidence_graph


def set_evidence_graph(graph: EvidenceGraph) -> None:
    global _evidence_graph
    _evidence_graph = graph