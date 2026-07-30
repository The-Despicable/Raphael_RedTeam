from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from raphael.cognitive.models import TargetModel, CapabilityModel, Affordance, Constraint, Unknown, AffordanceType, ConstraintType

logger = logging.getLogger(__name__)


@dataclass
class RefinementResult:
    new_affordances: List[str] = field(default_factory=list)
    new_constraints: List[str] = field(default_factory=list)
    new_unknowns: List[str] = field(default_factory=list)
    updated_confidence: Dict[str, float] = field(default_factory=dict)
    contradictions: List[str] = field(default_factory=list)


class ModelRefiner:
    """Inward recon - analyzes existing TargetModel to find gaps, contradictions, and infer new information."""
    
    def __init__(self, target_model: TargetModel, capability_model: CapabilityModel):
        self.target_model = target_model
        self.capability_model = capability_model
    
    def refine(self) -> RefinementResult:
        """Run full refinement cycle."""
        result = RefinementResult()
        
        result.new_affordances.extend(self._infer_affordances_from_constraints())
        result.new_constraints.extend(self._infer_constraints_from_affordances())
        result.contradictions.extend(self._find_contradictions())
        result.new_unknowns.extend(self._generate_unknowns_from_gaps())
        result.updated_confidence = self._update_confidence()
        
        return result
    
    def _infer_affordances_from_constraints(self) -> List[str]:
        """If we know certain constraints, what affordances must exist?"""
        new_affordances = []
        
        if self._has_affordance(AffordanceType.FILE_WRITE) and not self._has_affordance(AffordanceType.COMMAND_CONTROL):
            self.target_model.add_affordance(Affordance(
                type=AffordanceType.COMMAND_CONTROL,
                target_id=self.target_model.target_id,
                description="Inferred from file write capability",
                confidence=0.7,
            ))
            new_affordances.append("COMMAND_CONTROL_INFERRED")
        
        if self._has_affordance(AffordanceType.CREDENTIAL_ACCESS) and self._has_affordance(AffordanceType.NETWORK_ACCESS):
            if not self._has_affordance(AffordanceType.LATERAL_MOVEMENT):
                self.target_model.add_affordance(Affordance(
                    type=AffordanceType.LATERAL_MOVEMENT,
                    target_id=self.target_model.target_id,
                    description="Inferred from credential + network access",
                    confidence=0.8,
                ))
                new_affordances.append("LATERAL_MOVEMENT_INFERRED")
        
        if self._has_affordance(AffordanceType.PRIVILEGE_ESCALATION) and not self._has_affordance(AffordanceType.PERSISTENCE):
            if self._has_affordance(AffordanceType.COMMAND_CONTROL):
                self.target_model.add_affordance(Affordance(
                    type=AffordanceType.PERSISTENCE,
                    target_id=self.target_model.target_id,
                    description="Inferred from privilege escalation + command control",
                    confidence=0.6,
                ))
                new_affordances.append("PERSISTENCE_INFERRED")
        
        return new_affordances
    
    def _infer_constraints_from_affordances(self) -> List[str]:
        """If we have certain affordances, what constraints must exist?"""
        new_constraints = []
        
        if self._has_affordance(AffordanceType.COMMAND_CONTROL) and not self._has_affordance(AffordanceType.PERSISTENCE):
            constraint = Constraint(
                type=ConstraintType.APPLICATION_CONTROL,
                target_id=self.target_model.target_id,
                description="No persistence mechanism detected despite command execution",
                severity=0.6,
            )
            self.target_model.add_constraint(constraint)
            new_constraints.append("PERSISTENCE_BLOCKED")
        
        if self._has_affordance(AffordanceType.FILE_READ) and not self._has_affordance(AffordanceType.DATA_EXFILTRATION):
            constraint = Constraint(
                type=ConstraintType.NETWORK_MONITORING,
                target_id=self.target_model.target_id,
                description="Egress filtering likely present - data exfiltration blocked",
                severity=0.7,
            )
            self.target_model.add_constraint(constraint)
            new_constraints.append("EGRESS_FILTERING")
        
        if self._has_affordance(AffordanceType.CREDENTIAL_ACCESS) and not self._has_affordance(AffordanceType.LATERAL_MOVEMENT):
            constraint = Constraint(
                type=ConstraintType.NETWORK_SEGMENTATION,
                target_id=self.target_model.target_id,
                description="Network segmentation likely preventing lateral movement",
                severity=0.5,
            )
            self.target_model.add_constraint(constraint)
            new_constraints.append("SEGMENTATION_BLOCKING_LATERAL")
        
        return new_constraints
    
    def _find_contradictions(self) -> List[str]:
        """Find contradictions between affordances and constraints."""
        contradictions = []
        
        for constraint in self.target_model.constraints.values():
            for blocked_id in constraint.mitigations:
                if blocked_id in self.target_model.affordances:
                    contradiction = f"Constraint {constraint.id} mitigates {blocked_id} but affordance exists"
                    unknown = Unknown(
                        target_id=self.target_model.target_id,
                        description=contradiction,
                        priority=0.9,
                    )
                    self.target_model.add_unknown(unknown)
                    contradictions.append(contradiction)
        
        return contradictions
    
    def _generate_unknowns_from_gaps(self) -> List[str]:
        """Generate unknowns for things we should know but don't."""
        unknowns = []
        
        if self._has_affordance(AffordanceType.NETWORK_ACCESS) and "os" not in self.target_model.metadata:
            unknown = Unknown(
                target_id=self.target_model.target_id,
                description="What is the target operating system?",
                priority=0.8,
            )
            self.target_model.add_unknown(unknown)
            unknowns.append("OS_UNKNOWN")
        
        if self._has_affordance(AffordanceType.CREDENTIAL_ACCESS) and "privilege_level" not in self.target_model.metadata:
            unknown = Unknown(
                target_id=self.target_model.target_id,
                description="What privilege level do the credentials provide?",
                priority=0.9,
            )
            self.target_model.add_unknown(unknown)
            unknowns.append("PRIVILEGE_LEVEL_UNKNOWN")
        
        if self._has_affordance(AffordanceType.COMMAND_CONTROL) and "shell_type" not in self.target_model.metadata:
            unknown = Unknown(
                target_id=self.target_model.target_id,
                description="What shell type is available (bash, cmd, powershell)?",
                priority=0.7,
            )
            self.target_model.add_unknown(unknown)
            unknowns.append("SHELL_TYPE_UNKNOWN")
        
        return unknowns
    
    def _update_confidence(self) -> Dict[str, float]:
        """Update confidence scores based on capability alignment."""
        updated = {}
        
        for aff_id, affordance in self.target_model.affordances.items():
            aligned_caps = [
                c for c in self.capability_model.capabilities.values()
                if affordance.type in c.provides and c.state == CapabilityState.AVAILABLE
            ]
            
            if aligned_caps:
                new_conf = min(0.95, affordance.confidence + 0.1 * len(aligned_caps))
            else:
                new_conf = max(0.1, affordance.confidence - 0.05)
            
            if abs(new_conf - affordance.confidence) > 0.01:
                affordance.confidence = new_conf
                updated[aff_id] = new_conf
        
        return updated
    
    def _has_affordance(self, aff_type: AffordanceType) -> bool:
        return any(a.type == aff_type for a in self.target_model.affordances.values())