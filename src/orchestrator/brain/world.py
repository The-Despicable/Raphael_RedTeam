"""world.py — World and Identity Model with entity resolution.

Core design:

ENTITY HIERARCHY:
  Entity (base)
    ├── Asset
    ├── Service
    ├── Application
    ├── Identity
    ├── Credential
    ├── CloudResource
    ├── Container
    ├── Cluster
    ├── Repository
    └── Pipeline

RELATIONSHIPS (with provenance):
  RUNS_ON, CONNECTS_TO, AUTHENTICATES_AS, MEMBER_OF,
  OWNS, ASSUMES, TRUSTS, CAN_ACCESS, DEPENDS_ON, OBSERVED_ON

ENTITY RESOLUTION:
  POSSIBLY_SAME_AS → CONFIRMED_SAME_AS
  Each resolution step requires evidence.

QUERY INTERFACE:
  world.query_can_access(identity, resource) → evidence_chain
  world.query_why(entity_a, relation, entity_b) → evidence_path

Schema version: 1
"""

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Optional, List, Tuple

from orchestrator.brain.evidence import EvidenceGraph
from orchestrator.brain.trust import TrustLevel


class EntityType(str, Enum):
    """Types of entities in the world model."""
    ASSET = "asset"
    SERVICE = "service"
    APPLICATION = "application"
    IDENTITY = "identity"
    CREDENTIAL = "credential"
    CLOUD_RESOURCE = "cloud_resource"
    CONTAINER = "container"
    CLUSTER = "cluster"
    REPOSITORY = "repository"
    PIPELINE = "pipeline"
    # E1 Shell-derived entity types
    PROCESS = "process"
    FILE = "file"
    NETWORK_CONNECTION = "network_connection"
    VULNERABILITY = "vulnerability"
    SHELL_SESSION = "shell_session"


class RelationshipType(str, Enum):
    """Semantic relationships between entities."""
    RUNS_ON = "runs_on"
    CONNECTS_TO = "connects_to"
    AUTHENTICATES_AS = "authenticates_as"
    MEMBER_OF = "member_of"
    OWNS = "owns"
    ASSUMES = "assumes"
    TRUSTS = "trusts"
    CAN_ACCESS = "can_access"
    DEPENDS_ON = "depends_on"
    OBSERVED_ON = "observed_on"
    # E1 Shell-derived relationships
    EXECUTED_BY = "executed_by"           # Process executed by Identity
    READ_BY = "read_by"                   # File read by Process/Identity
    WRITTEN_BY = "written_by"             # File written by Process/Identity
    CONNECTS_FROM = "connects_from"       # Network connection from Process
    CONNECTS_TO_PORT = "connects_to_port" # Network connection to Port
    OBSERVED_IN = "observed_in"           # Evidence observed in ShellSession
    INDICATES = "indicates"               # Vulnerability indicates weakness


class ResolutionState(str, Enum):
    """State of entity identity resolution."""
    SEPARATE = "separate"
    POSSIBLY_SAME_AS = "possibly_same_as"
    CONFIRMED_SAME_AS = "confirmed_same_as"


@dataclass
class Entity:
    """
    Base entity in the world model.
    
    Every entity has a unique ID and can have multiple identifiers.
    Relationships are stored separately with provenance.
    """
    schema_version: int = 1
    entity_id: str = field(default_factory=lambda: f"ent_{uuid.uuid4().hex[:12]}")
    entity_type: EntityType = EntityType.ASSET
    
    # Primary and alternative identifiers
    primary_identifier: str = ""       # e.g., "10.0.1.10", "i-0abc123", "arn:aws:iam::..."
    identifiers: dict[str, str] = field(default_factory=dict)  # {"ip": "10.0.1.10", "hostname": "web-01"}
    
    # Metadata
    name: str = ""
    description: str = ""
    tags: list[str] = field(default_factory=list)
    
    # State
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    active: bool = True
    
    # Provenance
    created_by: str = ""               # action_receipt_id or "manual"
    evidence_ids: list[str] = field(default_factory=list)  # Evidence supporting this entity's existence

    def add_identifier(self, key: str, value: str) -> None:
        """Add an alternative identifier."""
        self.identifiers[key] = value
        self.last_seen = time.time()

    def to_dict(self) -> dict:
        d = asdict(self)
        d["entity_type"] = self.entity_type.value
        return d


@dataclass
class Relationship:
    """
    A directed relationship between two entities with full provenance.
    
    Every relationship MUST have supporting evidence.
    """
    schema_version: int = 1
    relationship_id: str = field(default_factory=lambda: f"rel_{uuid.uuid4().hex[:12]}")
    relationship_type: RelationshipType = RelationshipType.CONNECTS_TO
    
    source_entity_id: str = ""
    target_entity_id: str = ""
    
    # Provenance
    confidence: float = 1.0            # 0.0 to 1.0
    evidence_ids: list[str] = field(default_factory=list)
    established_by: str = ""            # action_receipt_id or reasoning step
    established_at: float = field(default_factory=time.time)
    
    # Optional metadata
    metadata: dict = field(default_factory=dict)
    expires_at: float = 0.0            # 0 = never expires

    def is_expired(self) -> bool:
        if self.expires_at == 0:
            return False
        return time.time() > self.expires_at

    def to_dict(self) -> dict:
        d = asdict(self)
        d["relationship_type"] = self.relationship_type.value
        return d


@dataclass
class EntityResolution:
    """
    Hypothesis that two entity IDs refer to the same real-world entity.
    
    States: SEPARATE → POSSIBLY_SAME_AS → CONFIRMED_SAME_AS
    """
    schema_version: int = 1
    resolution_id: str = field(default_factory=lambda: f"res_{uuid.uuid4().hex[:12]}")
    
    entity_a_id: str = ""
    entity_b_id: str = ""
    
    # Current state
    state: ResolutionState = ResolutionState.SEPARATE
    
    # Provenance
    proposed_by: str = ""              # action_receipt_id or reasoning step
    proposed_at: float = field(default_factory=time.time)
    evidence_ids: list[str] = field(default_factory=list)
    
    # Confirmation
    confirmed_by: str = ""
    confirmed_at: float = 0.0
    confirmation_evidence_ids: list[str] = field(default_factory=list)
    
    # Rationale
    rationale: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["state"] = self.state.value
        return d


# ── World Query Result ──────────────────────────────────────────────

@dataclass(frozen=True)
class WorldQueryResult:
    """
    Read-only projection of WorldModel state at a point in time.

    This is the causal intermediate between WorldModel mutation and
    candidate generation. It is NOT an inference mechanism — it simply
    exposes what WorldModel already knows at query time.

    Every query gets a unique query_id for causal traceability.
    Candidates that consume this result record:
        derived_from_world_query_ids = ("WQ17",)

    Causal chain: INVOKED (query call) -> PRODUCED (WQR object)
                  -> REFERENCED (candidate records query_id)
                  -> DECISION_RELEVANT (affects downstream choice)
    """
    query_id: str = field(default_factory=lambda: f"WQ_{uuid.uuid4().hex[:12]}")
    entities: tuple = ()          # tuple of Entity objects (read-only view)
    relationships: tuple = ()     # tuple of Relationship objects
    resolutions: tuple = ()       # tuple of EntityResolution objects
    supporting_evidence_ids: tuple[str, ...] = ()
    confidence: Optional[float] = None
    generated_at: float = field(default_factory=time.time)
    query_params: tuple[tuple[str, str], ...] = ()  # (param_name, value) for reproducibility

    def to_dict(self) -> dict:
        return {
            "query_id": self.query_id,
            "entity_count": len(self.entities),
            "relationship_count": len(self.relationships),
            "resolution_count": len(self.resolutions),
            "supporting_evidence_ids": list(self.supporting_evidence_ids),
            "confidence": self.confidence,
            "generated_at": self.generated_at,
            "query_params": dict(self.query_params),
        }


class WorldModel:
    """
    The world model: entities, relationships, and identity resolution.
    
    All queries return evidence chains for auditability.
    """
    
    def __init__(self, evidence_graph: EvidenceGraph):
        self.evidence_graph = evidence_graph
        
        self.entities: dict[str, Entity] = {}
        self.relationships: dict[str, Relationship] = {}
        self.resolutions: dict[str, EntityResolution] = {}
        
        # Indexes for fast queries
        self._by_type: dict[EntityType, set[str]] = {t: set() for t in EntityType}
        self._by_identifier: dict[str, str] = {}  # identifier -> entity_id
        self._outgoing_rels: dict[str, list[str]] = {}  # entity_id -> [rel_id]
        self._incoming_rels: dict[str, list[str]] = {}  # entity_id -> [rel_id]

    # ── Entity management ────────────────────────────────────────

    def add_entity(self, entity: Entity) -> str:
        """Add an entity to the world model."""
        if entity.entity_id in self.entities:
            return entity.entity_id
        
        self.entities[entity.entity_id] = entity
        self._by_type[entity.entity_type].add(entity.entity_id)
        
        # Index identifiers
        if entity.primary_identifier:
            self._by_identifier[entity.primary_identifier] = entity.entity_id
        for key, value in entity.identifiers.items():
            self._by_identifier[f"{key}:{value}"] = entity.entity_id
        
        return entity.entity_id

    def get_entity(self, entity_id: str) -> Optional[Entity]:
        return self.entities.get(entity_id)

    def find_by_identifier(self, identifier: str) -> Optional[Entity]:
        """Find entity by any identifier (IP, hostname, ARN, etc.)."""
        entity_id = self._by_identifier.get(identifier)
        if entity_id:
            return self.entities.get(entity_id)
        return None

    def get_entities_by_type(self, entity_type: EntityType) -> list[Entity]:
        return [self.entities[eid] for eid in self._by_type.get(entity_type, set())]

    # ── Relationship management ──────────────────────────────────

    def add_relationship(self, rel: Relationship) -> str:
        """Add a relationship with provenance."""
        if not rel.evidence_ids:
            raise ValueError("Relationship must have at least one evidence_id")
        
        self.relationships[rel.relationship_id] = rel
        
        # Update indexes
        if rel.source_entity_id not in self._outgoing_rels:
            self._outgoing_rels[rel.source_entity_id] = []
        self._outgoing_rels[rel.source_entity_id].append(rel.relationship_id)
        
        if rel.target_entity_id not in self._incoming_rels:
            self._incoming_rels[rel.target_entity_id] = []
        self._incoming_rels[rel.target_entity_id].append(rel.relationship_id)
        
        return rel.relationship_id

    def get_relationships(
        self, 
        source: Optional[str] = None, 
        target: Optional[str] = None,
        rel_type: Optional[RelationshipType] = None,
    ) -> list[Relationship]:
        """Query relationships with optional filters."""
        results = []
        for rel in self.relationships.values():
            if rel.is_expired():
                continue
            if source and rel.source_entity_id != source:
                continue
            if target and rel.target_entity_id != target:
                continue
            if rel_type and rel.relationship_type != rel_type:
                continue
            results.append(rel)
        return results

    def get_outgoing(self, entity_id: str) -> list[Relationship]:
        rel_ids = self._outgoing_rels.get(entity_id, [])
        return [self.relationships[rid] for rid in rel_ids if not self.relationships[rid].is_expired()]

    def get_incoming(self, entity_id: str) -> list[Relationship]:
        rel_ids = self._incoming_rels.get(entity_id, [])
        return [self.relationships[rid] for rid in rel_ids if not self.relationships[rid].is_expired()]

    # ── Entity resolution ────────────────────────────────────────

    def propose_same_as(
        self,
        entity_a_id: str,
        entity_b_id: str,
        evidence_ids: list[str],
        rationale: str,
        proposed_by: str = "",
    ) -> EntityResolution:
        """Propose that two entities are the same real-world entity."""
        if entity_a_id not in self.entities or entity_b_id not in self.entities:
            raise ValueError("Both entities must exist")
        
        # Check existing resolution
        existing = self._find_resolution(entity_a_id, entity_b_id)
        if existing:
            return existing
        
        res = EntityResolution(
            entity_a_id=entity_a_id,
            entity_b_id=entity_b_id,
            state=ResolutionState.POSSIBLY_SAME_AS,
            proposed_by=proposed_by,
            evidence_ids=evidence_ids,
            rationale=rationale,
        )
        self.resolutions[res.resolution_id] = res
        return res

    def confirm_same_as(
        self,
        resolution_id: str,
        confirmed_by: str,
        additional_evidence: list[str] = None,
    ) -> EntityResolution:
        """Confirm a POSSIBLY_SAME_AS resolution."""
        res = self.resolutions.get(resolution_id)
        if not res:
            raise ValueError(f"Resolution {resolution_id} not found")
        if res.state != ResolutionState.POSSIBLY_SAME_AS:
            raise ValueError(f"Resolution is not in POSSIBLY_SAME_AS state: {res.state.value}")
        
        res.state = ResolutionState.CONFIRMED_SAME_AS
        res.confirmed_by = confirmed_by
        res.confirmed_at = time.time()
        if additional_evidence:
            res.confirmation_evidence_ids = additional_evidence
        return res

    def _find_resolution(self, a_id: str, b_id: str) -> Optional[EntityResolution]:
        for res in self.resolutions.values():
            if (res.entity_a_id == a_id and res.entity_b_id == b_id) or \
               (res.entity_a_id == b_id and res.entity_b_id == a_id):
                return res
        return None

    def get_resolution(self, resolution_id: str) -> Optional[EntityResolution]:
        return self.resolutions.get(resolution_id)

    def get_resolutions_for_entity(self, entity_id: str) -> list[EntityResolution]:
        return [r for r in self.resolutions.values() 
                if r.entity_a_id == entity_id or r.entity_b_id == entity_id]

    # ── Query with evidence chains ───────────────────────────────

    def query_why_can_access(self, identity_id: str, resource_id: str) -> list[dict]:
        """
        Return evidence chain for why an identity can access a resource.
        
        Returns a list of steps, each with relationship + evidence.
        """
        chain = []
        
        # Direct CAN_ACCESS relationship
        direct = self.get_relationships(source=identity_id, target=resource_id, 
                                         rel_type=RelationshipType.CAN_ACCESS)
        for rel in direct:
            chain.append({
                "step": "direct_can_access",
                "relationship": rel.to_dict(),
                "evidence": [self.evidence_graph.get_evidence(eid).to_dict() 
                            if self.evidence_graph.get_evidence(eid) 
                            else {"evidence_id": eid, "error": "not found"} 
                            for eid in rel.evidence_ids],
            })
        
        # Transitive: identity → (ASSUMES/MEMBER_OF) → role → CAN_ACCESS → resource
        # This is a simplified traversal; a full implementation would do graph search
        for rel in self.get_outgoing(identity_id):
            if rel.relationship_type in (RelationshipType.ASSUMES, RelationshipType.MEMBER_OF):
                intermediate = rel.target_entity_id
                for rel2 in self.get_outgoing(intermediate):
                    if rel2.relationship_type == RelationshipType.CAN_ACCESS and rel2.target_entity_id == resource_id:
                        chain.append({
                            "step": f"transitive_via_{intermediate}",
                            "hop1": rel.to_dict(),
                            "hop1_evidence": [self.evidence_graph.get_evidence(eid).to_dict() 
                                             if self.evidence_graph.get_evidence(eid) 
                                             else {"evidence_id": eid, "error": "not found"} 
                                             for eid in rel.evidence_ids],
                            "hop2": rel2.to_dict(),
                            "hop2_evidence": [self.evidence_graph.get_evidence(eid).to_dict() 
                                             if self.evidence_graph.get_evidence(eid) 
                                             else {"evidence_id": eid, "error": "not found"} 
                                             for eid in rel2.evidence_ids],
                        })
        
        return chain

    def query_why(self, entity_a_id: str, relationship: RelationshipType, entity_b_id: str) -> list[dict]:
        """Return evidence path for a specific relationship between two entities."""
        # Direct
        direct = self.get_relationships(source=entity_a_id, target=entity_b_id, rel_type=relationship)
        if direct:
            return [{
                "type": "direct",
                "relationship": r.to_dict(),
                "evidence": [self.evidence_graph.get_evidence(eid).to_dict() 
                            for eid in r.evidence_ids if self.evidence_graph.get_evidence(eid)]
            } for r in direct]
        
        return []

    # ── WorldQueryResult interface ─────────────────────────────────

    def query(
        self,
        entity_ids: Optional[list[str]] = None,
        relationship_types: Optional[list[RelationshipType]] = None,
        include_resolutions: bool = True,
        max_results: int = 100,
        query_reason: str = "",
    ) -> "WorldQueryResult":
        """
        Return a read-only projection of current WorldModel state.
        
        This is the causal intermediate between WorldModel mutation and
        candidate generation. It is NOT an inference mechanism — it simply
        exposes what WorldModel already knows at query time.
        
        Every query gets a unique query_id for causal traceability.
        Candidates that consume this result should record:
            derived_from_world_query_ids = (query_id,)
        
        Causal chain: INVOKED (query call) -> PRODUCED (WQR object) 
                      -> REFERENCED (candidate records query_id) 
                      -> DECISION_RELEVANT (affects downstream choice)
        
        Args:
            entity_ids: Specific entity IDs to include (None = all)
            relationship_types: Filter to specific relationship types
            include_resolutions: Whether to include entity resolutions
            max_results: Maximum entities to return
            query_reason: Human-readable reason for this query
            
        Returns:
            WorldQueryResult with entities, relationships, resolutions,
            and supporting evidence IDs.
        """
        # Filter entities
        if entity_ids is None:
            selected_entities = list(self.entities.values())[:max_results]
        else:
            selected_entities = [
                self.entities[eid] for eid in entity_ids 
                if eid in self.entities
            ][:max_results]
        
        # Filter relationships
        selected_relationships = []
        for rel in self.relationships.values():
            if rel.is_expired():
                continue
            if relationship_types and rel.relationship_type not in relationship_types:
                continue
            if entity_ids is not None:
                if rel.source_entity_id not in entity_ids and rel.target_entity_id not in entity_ids:
                    continue
            selected_relationships.append(rel)
            if len(selected_relationships) >= max_results:
                break
        
        # Filter resolutions
        selected_resolutions = []
        if include_resolutions:
            for res in self.resolutions.values():
                if entity_ids is None or res.entity_a_id in entity_ids or res.entity_b_id in entity_ids:
                    selected_resolutions.append(res)
                    if len(selected_resolutions) >= max_results:
                        break
        
        # Collect supporting evidence IDs
        evidence_ids = set()
        for e in selected_entities:
            evidence_ids.update(e.evidence_ids)
        for r in selected_relationships:
            evidence_ids.update(r.evidence_ids)
        for res in selected_resolutions:
            evidence_ids.update(res.evidence_ids)
            evidence_ids.update(res.confirmation_evidence_ids)
        
        # Calculate confidence based on evidence density
        confidence = None
        if selected_entities:
            evidenced = sum(1 for e in selected_entities if e.evidence_ids)
            confidence = evidenced / len(selected_entities)
        
        return WorldQueryResult(
            entities=tuple(selected_entities),
            relationships=tuple(selected_relationships),
            resolutions=tuple(selected_resolutions),
            supporting_evidence_ids=tuple(sorted(evidence_ids)),
            confidence=confidence,
            query_params=(
                ("entity_count", str(len(selected_entities))),
                ("relationship_count", str(len(selected_relationships))),
                ("resolution_count", str(len(selected_resolutions))),
                ("query_reason", query_reason),
            ),
        )

    def stats(self) -> dict:
        return {
            "entities": len(self.entities),
            "by_type": {t.value: len(s) for t, s in self._by_type.items()},
            "relationships": len(self.relationships),
            "resolutions": len(self.resolutions),
            "resolutions_by_state": {
                s.value: len([r for r in self.resolutions.values() if r.state == s])
                for s in ResolutionState
            },
        }

    # ── Serialization ────────────────────────────────────────────

    def to_dict(self) -> dict:
        return {
            "schema_version": 1,
            "entities": {eid: e.to_dict() for eid, e in self.entities.items()},
            "relationships": {rid: r.to_dict() for rid, r in self.relationships.items()},
            "resolutions": {rid: r.to_dict() for rid, r in self.resolutions.items()},
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    # ── E2: Shell Evidence Ingestion ──────────────────────────────

    def ingest_shell_evidence(
        self,
        evidence: 'Evidence',
        session_entity_id: str,
        host_asset_id: str = "",
        collected_by: str = "",
    ) -> list[str]:
        """E2: Dispatch shell-derived evidence to the correct ingestion handler.

        INV-E2-04: Validates that session_entity_id references an existing
        SHELL_SESSION entity. Raises ValueError if not found.

        Args:
            evidence: Evidence object from TTYNormalizer.EvidenceExtractor
            session_entity_id: Entity ID of the SHELL_SESSION that produced this evidence
            host_asset_id: Entity ID of the host ASSET being acted upon
            collected_by: Action receipt ID that collected this evidence

        Returns:
            List of entity IDs created or updated during ingestion

        Raises:
            ValueError: If session_entity_id does not reference an existing entity
        """
        # INV-E2-04: Validate session entity exists
        session_entity = self.get_entity(session_entity_id)
        if not session_entity:
            raise ValueError(
                f"ingest_shell_evidence: session_entity_id '{session_entity_id}' "
                f"not found in WorldModel"
            )

        if host_asset_id and not self.get_entity(host_asset_id):
            host_asset_id = ""  # Gracefully degrade if host asset not found

        evidence_type = getattr(evidence, 'evidence_type', '') or ''
        structured = getattr(evidence, 'structured_content', {}) or {}
        target = getattr(evidence, 'target', '') or ''
        raw = getattr(evidence, 'raw_content', '') or ''
        evidence_ids = [evidence.evidence_id] if evidence.evidence_id else []

        # Dispatch to type-specific handler
        handler_map = {
            "process_list": self._ingest_process_list,
            "file_content": self._ingest_file_content,
            "network_connections": self._ingest_network_connections,
            "user_accounts": self._ingest_user_accounts,
            "credential": self._ingest_credential,
            "vulnerability_indicator": self._ingest_vulnerability_indicator,
            "command_executed": self._ingest_command_executed,
            "command_output": self._ingest_command_output,
        }

        handler = handler_map.get(evidence_type)
        if handler:
            created_ids = handler(
                structured=structured,
                raw=raw,
                target=target,
                evidence_ids=evidence_ids,
                session_entity_id=session_entity_id,
                host_asset_id=host_asset_id,
                collected_by=collected_by,
            )
        else:
            created_ids = []

        # Always link evidence to session via OBSERVED_IN
        # Only if we created entities
        for eid in created_ids:
            link_observed_in(
                self, evidence_id=eid,
                session_id=session_entity_id,
                evidence_ids=evidence_ids,
                established_by=collected_by or "shell_ingestion",
            )

        return created_ids

    def _ingest_process_list(
        self,
        structured: dict,
        raw: str,
        target: str,
        evidence_ids: list[str],
        session_entity_id: str,
        host_asset_id: str = "",
        collected_by: str = "",
    ) -> list[str]:
        """Ingest process list evidence into PROCESS entities."""
        created = []
        processes = structured.get("processes", [])
        for proc in processes:
            pid = proc.get("pid", 0)
            if not pid:
                continue
            entity = create_process(
                self,
                pid=pid,
                ppid=proc.get("ppid", 0),
                user=proc.get("user", ""),
                cmd=proc.get("cmd", ""),
                cpu=proc.get("cpu", 0.0),
                mem=proc.get("mem", 0.0),
                evidence_ids=evidence_ids,
                created_by=collected_by or "shell_ingestion",
            )
            # Link process to host asset via RUNS_ON
            if host_asset_id:
                link_runs_on(
                    self,
                    service_id=entity.entity_id,
                    asset_id=host_asset_id,
                    evidence_ids=evidence_ids,
                    established_by=collected_by or "shell_ingestion",
                )
            created.append(entity.entity_id)
        return created

    def _ingest_file_content(
        self,
        structured: dict,
        raw: str,
        target: str,
        evidence_ids: list[str],
        session_entity_id: str,
        host_asset_id: str = "",
        collected_by: str = "",
    ) -> list[str]:
        """Ingest file content evidence into FILE + CREDENTIAL entities."""
        created = []
        path = structured.get("path", "") or target
        if not path:
            return created

        content = raw or structured.get("content", "")
        entity = create_file(
            self,
            path=path,
            size=structured.get("size_bytes", len(content.encode())),
            permissions="",
            owner="",
            evidence_ids=evidence_ids,
            created_by=collected_by or "shell_ingestion",
        )
        created.append(entity.entity_id)

        # Link file to host asset
        if host_asset_id:
            link_runs_on(
                self, service_id=entity.entity_id,
                asset_id=host_asset_id,
                evidence_ids=evidence_ids,
                established_by=collected_by or "shell_ingestion",
            )

        # Check if file content contains credential indicators
        shadow_indicators = ["root:$", "root:*:", "root:!"]
        if any(ind in content for ind in shadow_indicators):
            # Extract usernames and hashes
            for line in content.splitlines():
                if ":" in line and not line.startswith("#"):
                    parts = line.split(":")
                    if len(parts) >= 2:
                        cred_entity = create_credential(
                            self,
                            cred_type="password_hash",
                            principal=parts[0],
                            secret_ref=f"hash:{parts[1][:20] if len(parts) > 1 else 'unknown'}",
                            evidence_ids=evidence_ids,
                            created_by=collected_by or "shell_ingestion",
                        )
                        created.append(cred_entity.entity_id)

        # SSH private key detection
        if "PRIVATE KEY" in content:
            cred_entity = create_credential(
                self,
                cred_type="ssh_private_key",
                principal=path.split("/")[-2] if "/" in path else "unknown",
                secret_ref=f"path:{path}",
                evidence_ids=evidence_ids,
                created_by=collected_by or "shell_ingestion",
            )
            created.append(cred_entity.entity_id)

        return created

    def _ingest_network_connections(
        self,
        structured: dict,
        raw: str,
        target: str,
        evidence_ids: list[str],
        session_entity_id: str,
        host_asset_id: str = "",
        collected_by: str = "",
    ) -> list[str]:
        """Ingest network connection evidence into NETWORK_CONNECTION entities."""
        created = []
        connections = structured.get("connections", [])
        for conn in connections:
            proto = conn.get("proto", "tcp")
            local = conn.get("local_addr", "")
            remote = conn.get("foreign_addr", "")
            state = conn.get("state", "")
            pid = conn.get("pid", 0)
            try:
                pid = int(pid) if pid else 0
            except (ValueError, TypeError):
                pid = 0

            entity = create_network_connection(
                self,
                proto=proto,
                local_addr=local,
                remote_addr=remote,
                state=state,
                pid=pid,
                evidence_ids=evidence_ids,
                created_by=collected_by or "shell_ingestion",
            )
            created.append(entity.entity_id)

            # Link to host asset
            if host_asset_id:
                link_runs_on(
                    self, service_id=entity.entity_id,
                    asset_id=host_asset_id,
                    evidence_ids=evidence_ids,
                    established_by=collected_by or "shell_ingestion",
                )

        return created

    def _ingest_user_accounts(
        self,
        structured: dict,
        raw: str,
        target: str,
        evidence_ids: list[str],
        session_entity_id: str,
        host_asset_id: str = "",
        collected_by: str = "",
    ) -> list[str]:
        """Ingest user account evidence into IDENTITY entities."""
        created = []
        accounts = structured.get("accounts", [])
        for acct in accounts:
            username = acct.get("username", "")
            if not username:
                continue
            uid = acct.get("uid", 1000)
            shell = acct.get("shell", "")
            entity = create_identity(
                self,
                identity_type="user",
                principal=username,
                evidence_ids=evidence_ids,
                created_by=collected_by or "shell_ingestion",
            )
            entity.identifiers["uid"] = str(uid)
            entity.identifiers["shell"] = shell
            created.append(entity.entity_id)

            if host_asset_id:
                # Link user to host via OBSERVED_ON
                from orchestrator.brain.world import RelationshipType
                rel = Relationship(
                    relationship_type=RelationshipType.OBSERVED_ON,
                    source_entity_id=entity.entity_id,
                    target_entity_id=host_asset_id,
                    evidence_ids=evidence_ids,
                    established_by=collected_by or "shell_ingestion",
                )
                self.add_relationship(rel)

        return created

    def _ingest_credential(
        self,
        structured: dict,
        raw: str,
        target: str,
        evidence_ids: list[str],
        session_entity_id: str,
        host_asset_id: str = "",
        collected_by: str = "",
    ) -> list[str]:
        """Ingest credential evidence into CREDENTIAL entities."""
        created = []
        cred_type = structured.get("type", "generic_credential")
        principal = structured.get("source_command", raw[:50])
        secret = structured.get("raw", raw[:100])

        entity = create_credential(
            self,
            cred_type=cred_type,
            principal=principal[:60],
            secret_ref=f"hash:{hashlib.sha256(secret.encode()).hexdigest()[:16]}",
            evidence_ids=evidence_ids,
            created_by=collected_by or "shell_ingestion",
        )
        created.append(entity.entity_id)

        return created

    def _ingest_vulnerability_indicator(
        self,
        structured: dict,
        raw: str,
        target: str,
        evidence_ids: list[str],
        session_entity_id: str,
        host_asset_id: str = "",
        collected_by: str = "",
    ) -> list[str]:
        """Ingest vulnerability indicator evidence into VULNERABILITY entities."""
        created = []
        vuln_class = structured.get("vuln_class", "unknown_indicator")
        description = structured.get("description", raw[:200])

        entity = create_vulnerability(
            self,
            vuln_class=vuln_class,
            description=description,
            evidence_text=raw[:200],
            confidence=structured.get("confidence", 0.5),
            evidence_ids=evidence_ids,
            created_by=collected_by or "shell_ingestion",
        )
        created.append(entity.entity_id)

        # Link vulnerability to host asset
        if host_asset_id:
            link_indicates(
                self,
                vulnerability_id=entity.entity_id,
                target_entity_id=host_asset_id,
                evidence_ids=evidence_ids,
                established_by=collected_by or "shell_ingestion",
            )

        return created

    def _ingest_command_executed(
        self,
        structured: dict,
        raw: str,
        target: str,
        evidence_ids: list[str],
        session_entity_id: str,
        host_asset_id: str = "",
        collected_by: str = "",
    ) -> list[str]:
        """Ingest command execution record — metadata only, no new entities."""
        return []  # No entities created for command execution alone

    def _ingest_command_output(
        self,
        structured: dict,
        raw: str,
        target: str,
        evidence_ids: list[str],
        session_entity_id: str,
        host_asset_id: str = "",
        collected_by: str = "",
    ) -> list[str]:
        """Ingest command output — metadata only, no new entities."""
        return []  # Raw output is linked via evidence chain, not entities

    def update_host_from_shell(
        self,
        host_asset_id: str,
        session_entity_id: str,
    ) -> dict:
        """E2: Aggregate all shell-derived evidence for a host into a consolidated state.

        Args:
            host_asset_id: Entity ID of the host ASSET
            session_entity_id: Entity ID of the SHELL_SESSION

        Returns:
            Dict with summary of host state from shell evidence
        """
        host = self.get_entity(host_asset_id)
        if not host:
            return {"error": f"Host {host_asset_id} not found"}

        # Collect all entities linked to this session
        session_rels = self.get_relationships(target=session_entity_id,
                                                rel_type=RelationshipType.OBSERVED_IN)
        observed_entity_ids = [r.source_entity_id for r in session_rels]

        processes = []
        files = []
        connections = []
        users = []
        vulnerabilities = []
        credentials = []

        for eid in observed_entity_ids:
            entity = self.get_entity(eid)
            if not entity:
                continue
            etype = entity.entity_type
            if etype == EntityType.PROCESS:
                processes.append(entity.to_dict())
            elif etype == EntityType.FILE:
                files.append(entity.to_dict())
            elif etype == EntityType.NETWORK_CONNECTION:
                connections.append(entity.to_dict())
            elif etype == EntityType.VULNERABILITY:
                vulnerabilities.append(entity.to_dict())
            elif etype == EntityType.CREDENTIAL:
                credentials.append(entity.to_dict())

        # Find IDENTITY entities linked via OBSERVED_ON
        user_rels = self.get_relationships(target=host_asset_id,
                                            rel_type=RelationshipType.OBSERVED_ON)
        for r in user_rels:
            entity = self.get_entity(r.source_entity_id)
            if entity:
                users.append(entity.to_dict())

        return {
            "host": host.primary_identifier,
            "session": session_entity_id,
            "process_count": len(processes),
            "file_count": len(files),
            "connection_count": len(connections),
            "user_count": len(users),
            "vulnerability_count": len(vulnerabilities),
            "credential_count": len(credentials),
            "processes": processes,
            "files": files,
            "connections": connections,
            "users": users,
            "vulnerabilities": vulnerabilities,
            "credentials": credentials,
        }

    def get_session_host(self, session_entity_id: str) -> Optional['Entity']:
        """E2: Find the host ASSET that a SHELL_SESSION is connected to.

        Traverses OBSERVED_IN relationships to find entities linked to the session,
        then follows RUNS_ON to find the host ASSET.
        """
        # Check if session entity exists
        session = self.get_entity(session_entity_id)
        if not session:
            return None

        # Find entities observed in this session
        session_rels = self.get_relationships(target=session_entity_id,
                                                rel_type=RelationshipType.OBSERVED_IN)
        for r in session_rels:
            # Follow RUNS_ON from observed entity to host
            runs_on = self.get_relationships(
                source=r.source_entity_id,
                rel_type=RelationshipType.RUNS_ON,
            )
            for rr in runs_on:
                host = self.get_entity(rr.target_entity_id)
                if host and host.entity_type == EntityType.ASSET:
                    return host

        return None


# ── Convenience factory functions ────────────────────────────────

def create_asset(
    world: WorldModel,
    ip: str = "",
    hostname: str = "",
    os: str = "",
    evidence_ids: list[str] = None,
    created_by: str = "",
) -> Entity:
    """Create and add an asset entity."""
    entity = Entity(
        entity_type=EntityType.ASSET,
        primary_identifier=ip or hostname,
        identifiers={},
        name=hostname or ip,
        description=f"Asset: {os}",
        evidence_ids=evidence_ids or [],
        created_by=created_by,
    )
    if ip:
        entity.add_identifier("ip", ip)
    if hostname:
        entity.add_identifier("hostname", hostname)
    if os:
        entity.add_identifier("os", os)
    world.add_entity(entity)
    return entity


def create_identity(
    world: WorldModel,
    identity_type: str = "user",  # user, service_account, role
    principal: str = "",
    evidence_ids: list[str] = None,
    created_by: str = "",
) -> Entity:
    """Create and add an identity entity."""
    entity = Entity(
        entity_type=EntityType.IDENTITY,
        primary_identifier=principal,
        identifiers={"type": identity_type, "principal": principal},
        name=principal,
        description=f"{identity_type}: {principal}",
        evidence_ids=evidence_ids or [],
        created_by=created_by,
    )
    world.add_entity(entity)
    return entity


def create_credential(
    world: WorldModel,
    cred_type: str,
    principal: str,
    secret_ref: str = "",
    evidence_ids: list[str] = None,
    created_by: str = "",
) -> Entity:
    """Create and add a credential entity."""
    entity = Entity(
        entity_type=EntityType.CREDENTIAL,
        primary_identifier=f"{cred_type}:{principal}",
        identifiers={"type": cred_type, "principal": principal},
        name=f"{cred_type} for {principal}",
        evidence_ids=evidence_ids or [],
        created_by=created_by,
    )
    if secret_ref:
        entity.add_identifier("secret_ref", secret_ref)
    world.add_entity(entity)
    return entity


def link_can_access(
    world: WorldModel,
    identity_id: str,
    resource_id: str,
    evidence_ids: list[str],
    established_by: str = "",
) -> Relationship:
    """Create a CAN_ACCESS relationship with provenance."""
    rel = Relationship(
        relationship_type=RelationshipType.CAN_ACCESS,
        source_entity_id=identity_id,
        target_entity_id=resource_id,
        evidence_ids=evidence_ids,
        established_by=established_by,
    )
    world.add_relationship(rel)
    return rel


def link_runs_on(
    world: WorldModel,
    service_id: str,
    asset_id: str,
    evidence_ids: list[str],
    established_by: str = "",
) -> Relationship:
    """Create a RUNS_ON relationship (service runs on asset)."""
    rel = Relationship(
        relationship_type=RelationshipType.RUNS_ON,
        source_entity_id=service_id,
        target_entity_id=asset_id,
        evidence_ids=evidence_ids,
        established_by=established_by,
    )
    world.add_relationship(rel)
    return rel


def link_authenticates_as(
    world: WorldModel,
    identity_id: str,
    credential_id: str,
    evidence_ids: list[str],
    established_by: str = "",
) -> Relationship:
    """Create an AUTHENTICATES_AS relationship."""
    rel = Relationship(
        relationship_type=RelationshipType.AUTHENTICATES_AS,
        source_entity_id=identity_id,
        target_entity_id=credential_id,
        evidence_ids=evidence_ids,
        established_by=established_by,
    )
    world.add_relationship(rel)
    return rel


def link_member_of(
    world: WorldModel,
    identity_id: str,
    group_id: str,
    evidence_ids: list[str],
    established_by: str = "",
) -> Relationship:
    """Create a MEMBER_OF relationship."""
    rel = Relationship(
        relationship_type=RelationshipType.MEMBER_OF,
        source_entity_id=identity_id,
        target_entity_id=group_id,
        evidence_ids=evidence_ids,
        established_by=established_by,
    )
    world.add_relationship(rel)
    return rel


def link_assumes(
    world: WorldModel,
    identity_id: str,
    role_id: str,
    evidence_ids: list[str],
    established_by: str = "",
) -> Relationship:
    """Create an ASSUMES relationship (identity assumes role)."""
    rel = Relationship(
        relationship_type=RelationshipType.ASSUMES,
        source_entity_id=identity_id,
        target_entity_id=role_id,
        evidence_ids=evidence_ids,
        established_by=established_by,
    )
    world.add_relationship(rel)
    return rel


# ── E1 Shell-derived Entity Factories ──────────────────────────────


def create_process(
    world: WorldModel,
    pid: int,
    ppid: int = 0,
    user: str = "",
    cmd: str = "",
    cpu: float = 0.0,
    mem: float = 0.0,
    evidence_ids: list[str] = None,
    created_by: str = "",
) -> Entity:
    """Create a process entity from shell session output."""
    entity = Entity(
        entity_type=EntityType.PROCESS,
        primary_identifier=f"pid:{pid}",
        identifiers={
            "pid": str(pid),
            "ppid": str(ppid),
            "user": user,
            "cmd": cmd,
            "cpu": str(cpu),
            "mem": str(mem),
        },
        name=f"Process {pid}: {cmd[:50]}",
        description=f"PID {pid} (PPID {ppid}) running as {user}: {cmd}",
        evidence_ids=evidence_ids or [],
        created_by=created_by,
    )
    world.add_entity(entity)
    return entity


def create_file(
    world: WorldModel,
    path: str,
    size: int = 0,
    permissions: str = "",
    owner: str = "",
    content_hash: str = "",
    evidence_ids: list[str] = None,
    created_by: str = "",
) -> Entity:
    """Create a file entity from shell session output."""
    entity = Entity(
        entity_type=EntityType.FILE,
        primary_identifier=path,
        identifiers={
            "path": path,
            "size": str(size),
            "permissions": permissions,
            "owner": owner,
            "sha256": content_hash,
        },
        name=f"File: {path}",
        description=f"File at {path} ({size} bytes, perms {permissions}, owner {owner})",
        evidence_ids=evidence_ids or [],
        created_by=created_by,
    )
    world.add_entity(entity)
    return entity


def create_network_connection(
    world: WorldModel,
    proto: str,
    local_addr: str,
    remote_addr: str,
    state: str = "",
    pid: int = 0,
    evidence_ids: list[str] = None,
    created_by: str = "",
) -> Entity:
    """Create a network connection entity from shell session output."""
    entity = Entity(
        entity_type=EntityType.NETWORK_CONNECTION,
        primary_identifier=f"{proto}:{local_addr}->{remote_addr}",
        identifiers={
            "protocol": proto,
            "local_addr": local_addr,
            "remote_addr": remote_addr,
            "state": state,
            "pid": str(pid),
        },
        name=f"Connection {proto} {local_addr} -> {remote_addr} ({state})",
        description=f"{proto} connection from {local_addr} to {remote_addr} [{state}] PID {pid}",
        evidence_ids=evidence_ids or [],
        created_by=created_by,
    )
    world.add_entity(entity)
    return entity


def create_vulnerability(
    world: WorldModel,
    vuln_class: str,
    description: str,
    evidence_text: str = "",
    confidence: float = 0.5,
    evidence_ids: list[str] = None,
    created_by: str = "",
) -> Entity:
    """Create a vulnerability indicator entity from shell session output."""
    entity = Entity(
        entity_type=EntityType.VULNERABILITY,
        primary_identifier=f"vuln:{vuln_class}:{hashlib.sha256(description.encode()).hexdigest()[:12]}",
        identifiers={
            "class": vuln_class,
            "confidence": str(confidence),
            "evidence_text": evidence_text[:200],
        },
        name=f"Vulnerability: {vuln_class}",
        description=description,
        evidence_ids=evidence_ids or [],
        created_by=created_by,
    )
    world.add_entity(entity)
    return entity


def create_shell_session(
    world: WorldModel,
    session_id: str,
    capability_type: str,
    target: str,
    username: str = "",
    evidence_ids: list[str] = None,
    created_by: str = "",
) -> Entity:
    """Create a shell session entity for tracking."""
    entity = Entity(
        entity_type=EntityType.SHELL_SESSION,
        primary_identifier=session_id,
        identifiers={
            "session_id": session_id,
            "capability_type": capability_type,
            "target": target,
            "username": username,
        },
        name=f"Shell Session {session_id} ({capability_type})",
        description=f"Interactive {capability_type} session to {target} as {username}",
        evidence_ids=evidence_ids or [],
        created_by=created_by,
    )
    world.add_entity(entity)
    return entity


# ── E1 Shell-derived Relationship Factories ────────────────────────


def link_executed_by(
    world: WorldModel,
    process_id: str,
    identity_id: str,
    evidence_ids: list[str],
    established_by: str = "",
) -> Relationship:
    """Create an EXECUTED_BY relationship (Process executed by Identity)."""
    rel = Relationship(
        relationship_type=RelationshipType.EXECUTED_BY,
        source_entity_id=process_id,
        target_entity_id=identity_id,
        evidence_ids=evidence_ids,
        established_by=established_by,
    )
    world.add_relationship(rel)
    return rel


def link_read_by(
    world: WorldModel,
    file_id: str,
    reader_id: str,  # Process or Identity
    evidence_ids: list[str],
    established_by: str = "",
) -> Relationship:
    """Create a READ_BY relationship (File read by Process/Identity)."""
    rel = Relationship(
        relationship_type=RelationshipType.READ_BY,
        source_entity_id=file_id,
        target_entity_id=reader_id,
        evidence_ids=evidence_ids,
        established_by=established_by,
    )
    world.add_relationship(rel)
    return rel


def link_written_by(
    world: WorldModel,
    file_id: str,
    writer_id: str,  # Process or Identity
    evidence_ids: list[str],
    established_by: str = "",
) -> Relationship:
    """Create a WRITTEN_BY relationship (File written by Process/Identity)."""
    rel = Relationship(
        relationship_type=RelationshipType.WRITTEN_BY,
        source_entity_id=file_id,
        target_entity_id=writer_id,
        evidence_ids=evidence_ids,
        established_by=established_by,
    )
    world.add_relationship(rel)
    return rel


def link_connects_from(
    world: WorldModel,
    connection_id: str,
    process_id: str,
    evidence_ids: list[str],
    established_by: str = "",
) -> Relationship:
    """Create a CONNECTS_FROM relationship (Network connection from Process)."""
    rel = Relationship(
        relationship_type=RelationshipType.CONNECTS_FROM,
        source_entity_id=connection_id,
        target_entity_id=process_id,
        evidence_ids=evidence_ids,
        established_by=established_by,
    )
    world.add_relationship(rel)
    return rel


def link_connects_to_port(
    world: WorldModel,
    connection_id: str,
    target_port: str,  # Could be an Asset entity with port identifier
    evidence_ids: list[str],
    established_by: str = "",
) -> Relationship:
    """Create a CONNECTS_TO_PORT relationship."""
    rel = Relationship(
        relationship_type=RelationshipType.CONNECTS_TO_PORT,
        source_entity_id=connection_id,
        target_entity_id=target_port,
        evidence_ids=evidence_ids,
        established_by=established_by,
    )
    world.add_relationship(rel)
    return rel


def link_observed_in(
    world: WorldModel,
    evidence_id: str,  # Actually an Entity entity_id that was observed
    session_id: str,
    evidence_ids: list[str],
    established_by: str = "",
) -> Relationship:
    """Create an OBSERVED_IN relationship (Entity observed in ShellSession)."""
    rel = Relationship(
        relationship_type=RelationshipType.OBSERVED_IN,
        source_entity_id=evidence_id,
        target_entity_id=session_id,
        evidence_ids=evidence_ids,
        established_by=established_by,
    )
    world.add_relationship(rel)
    return rel


def link_indicates(
    world: WorldModel,
    vulnerability_id: str,
    target_entity_id: str,
    evidence_ids: list[str],
    established_by: str = "",
) -> Relationship:
    """Create an INDICATES relationship (Vulnerability indicates weakness in target)."""
    rel = Relationship(
        relationship_type=RelationshipType.INDICATES,
        source_entity_id=vulnerability_id,
        target_entity_id=target_entity_id,
        evidence_ids=evidence_ids,
        established_by=established_by,
    )
    world.add_relationship(rel)
    return rel