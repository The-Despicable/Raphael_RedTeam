from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class AffordanceType(str, Enum):
    NETWORK_ACCESS = "network_access"
    CREDENTIAL_ACCESS = "credential_access"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFILTRATION = "data_exfiltration"
    PERSISTENCE = "persistence"
    DEFENSE_EVASION = "defense_evasion"
    DISCOVERY = "discovery"
    COMMAND_CONTROL = "command_control"
    IMPACT = "impact"
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"


class ConstraintType(str, Enum):
    NETWORK_SEGMENTATION = "network_segmentation"
    CREDENTIAL_GUARD = "credential_guard"
    PRIVILEGE_BOUNDARY = "privilege_boundary"
    NETWORK_MONITORING = "network_monitoring"
    EDR = "edr"
    APPLICATION_CONTROL = "application_control"
    NETWORK_SEGMENTATION_FW = "network_segmentation_fw"
    PASSWORD_POLICY = "password_policy"
    MFA = "mfa"
    PRIVILEGED_ACCESS_MGMT = "privileged_access_mgmt"


@dataclass
class Affordance:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    type: AffordanceType = AffordanceType.DISCOVERY
    target_id: str = ""
    description: str = ""
    confidence: float = 0.5
    prerequisites: Set[str] = field(default_factory=set)
    provides: Set[str] = field(default_factory=set)
    cost: float = 1.0
    risk: float = 0.5
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Constraint:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    type: ConstraintType = ConstraintType.NETWORK_SEGMENTATION
    target_id: str = ""
    description: str = ""
    severity: float = 0.5
    mitigations: Set[str] = field(default_factory=set)
    metadata: Dict[str, Any] = field(default_factory=dict)


class CapabilityState(str, Enum):
    UNKNOWN = "unknown"
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    DEGRADED = "degraded"
    COMPROMISED = "compromised"


@dataclass
class Capability:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    type: AffordanceType = AffordanceType.DISCOVERY
    state: CapabilityState = CapabilityState.UNKNOWN
    description: str = ""
    prerequisites: Set[str] = field(default_factory=set)
    provides: Set[str] = field(default_factory=set)
    cost: float = 1.0
    risk: float = 0.5
    reliability: float = 0.8
    metadata: Dict[str, Any] = field(default_factory=dict)
    last_used: Optional[datetime] = None
    success_count: int = 0
    failure_count: int = 0


class CapabilityModel:
    def __init__(self):
        self.capabilities: Dict[str, Capability] = {}
        self._by_type: Dict[AffordanceType, Set[str]] = {t: set() for t in AffordanceType}
    
    def add(self, capability: Capability) -> None:
        self.capabilities[capability.id] = capability
        self._by_type[capability.type].add(capability.id)
    
    def get(self, capability_id: str) -> Optional[Capability]:
        return self.capabilities.get(capability_id)
    
    def get_by_type(self, cap_type: AffordanceType) -> List[Capability]:
        return [self.capabilities[cid] for cid in self._by_type.get(cap_type, set())]
    
    def get_available(self, cap_type: Optional[AffordanceType] = None) -> List[Capability]:
        caps = [c for c in self.capabilities.values() if c.state == CapabilityState.AVAILABLE]
        if cap_type:
            caps = [c for c in caps if c.type == cap_type]
        return caps
    
    def get_by_state(self, state: CapabilityState) -> List[Capability]:
        return [c for c in self.capabilities.values() if c.state == state]
    
    def update_state(self, capability_id: str, state: CapabilityState) -> None:
        if capability_id in self.capabilities:
            self.capabilities[capability_id].state = state
    
    def record_use(self, capability_id: str, success: bool) -> None:
        if capability_id in self.capabilities:
            cap = self.capabilities[capability_id]
            cap.last_used = datetime.now(timezone.utc)
            if success:
                cap.success_count += 1
            else:
                cap.failure_count += 1
            cap.reliability = cap.success_count / max(1, cap.success_count + cap.failure_count)
    
    def get_by_state(self, state: CapabilityState) -> List[Capability]:
        return [c for c in self.capabilities.values() if c.state == state]


@dataclass
class Unknown:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    target_id: str = ""
    description: str = ""
    confidence: float = 0.0
    potential_types: Set[AffordanceType] = field(default_factory=set)
    related_affordances: Set[str] = field(default_factory=set)
    discovered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TargetModel:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    identifier: str = ""
    type: str = "unknown"
    affordances: Dict[str, Affordance] = field(default_factory=dict)
    constraints: Dict[str, Constraint] = field(default_factory=dict)
    unknowns: Dict[str, Unknown] = field(default_factory=dict)
    capabilities: CapabilityModel = field(default_factory=CapabilityModel)
    metadata: Dict[str, Any] = field(default_factory=dict)
    discovered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_scanned: Optional[datetime] = None
    risk_score: float = 0.0
    value: float = 1.0
    
    def add_affordance(self, affordance: Affordance) -> None:
        self.affordances[affordance.id] = affordance
    
    def add_constraint(self, constraint: Constraint) -> None:
        self.constraints[constraint.id] = constraint
    
    def add_unknown(self, unknown: Unknown) -> None:
        self.unknowns[unknown.id] = unknown
    
    def add_capability(self, capability: Capability) -> None:
        self.capabilities.add(capability)
    
    def get_affordances_by_type(self, a_type: AffordanceType) -> List[Affordance]:
        return [a for a in self.affordances.values() if a.type == a_type]
    
    def get_constraints_by_type(self, c_type: ConstraintType) -> List[Constraint]:
        return [c for c in self.constraints.values() if c.type == c_type]
    
    def update_risk(self, risk_delta: float) -> None:
        self.risk_score = max(0.0, min(1.0, self.risk_score + risk_delta))