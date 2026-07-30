"""TargetModel — constraint-vector representation of a target."""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class DomainState:
    """State of a single domain (network, physical, human, supply_chain)."""
    constraints: set[str] = field(default_factory=set)
    affordances: set[str] = field(default_factory=set)
    unknowns: set[str] = field(default_factory=set)

    def has_affordance(self, name: str) -> bool:
        return name in self.affordances

    def has_constraint(self, name: str) -> bool:
        return name in self.constraints

    def to_dict(self) -> dict:
        return {
            "constraints": list(self.constraints),
            "affordances": list(self.affordances),
            "unknowns": list(self.unknowns),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "DomainState":
        return cls(
            constraints=set(d.get("constraints", [])),
            affordances=set(d.get("affordances", [])),
            unknowns=set(d.get("unknowns", [])),
        )


@dataclass
class ConstraintDelta:
    """What changed after executing a technique."""
    domain: str = "network"
    new_constraints: set[str] = field(default_factory=set)
    new_affordances: set[str] = field(default_factory=set)
    resolved_unknowns: set[str] = field(default_factory=set)
    new_unknowns: set[str] = field(default_factory=set)
    evidence: str = ""  # raw output for hippocampus

    def is_empty(self) -> bool:
        return not (self.new_constraints or self.new_affordances
                    or self.resolved_unknowns or self.new_unknowns)

    @classmethod
    def empty(cls) -> "ConstraintDelta":
        return cls()

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "new_constraints": list(self.new_constraints),
            "new_affordances": list(self.new_affordances),
            "resolved_unknowns": list(self.resolved_unknowns),
            "new_unknowns": list(self.new_unknowns),
            "evidence": self.evidence[:500],
        }


@dataclass
class FailureRecord:
    """Why a technique failed. Used for negative cache with resurrection."""
    cycle: int
    reason_class: str  # "permission" | "timeout" | "unavailable" | "server_error"
    is_permanent: bool


@dataclass
class TargetModel:
    """Constraint-vector representation of a target across all domains."""
    target_id: str
    domains: dict[str, DomainState] = field(default_factory=lambda: {
        "network": DomainState(),
        "physical": DomainState(),
        "human": DomainState(),
        "supply_chain": DomainState(),
    })
    failed_techniques: dict[str, FailureRecord] = field(default_factory=dict)
    last_new_info_cycle: int = 0

    def absorb(self, delta: ConstraintDelta, current_cycle: int) -> bool:
        """
        Add new constraints/affordances/resolved unknowns.
        Returns True if anything actually changed in the model.
        """
        if delta.is_empty():
            return False
        domain = delta.domain
        if domain not in self.domains:
            self.domains[domain] = DomainState()
        
        changed = False
        domain_state = self.domains[domain]
        
        # Check each field for actual new items (not already present)
        new_constraints = delta.new_constraints - domain_state.constraints
        new_affordances = delta.new_affordances - domain_state.affordances
        resolved_unknowns = delta.resolved_unknowns & domain_state.unknowns
        new_unknowns = delta.new_unknowns - domain_state.unknowns
        
        if new_constraints:
            domain_state.constraints.update(new_constraints)
            changed = True
        if new_affordances:
            domain_state.affordances.update(new_affordances)
            changed = True
        if resolved_unknowns:
            domain_state.unknowns.difference_update(resolved_unknowns)
            changed = True
        if new_unknowns:
            domain_state.unknowns.update(new_unknowns)
            changed = True
        
        if changed:
            self.last_new_info_cycle = current_cycle
        return changed

    def has_affordance(self, name: str, domain: str = "network") -> bool:
        return domain in self.domains and self.domains[domain].has_affordance(name)

    def has_constraint(self, name: str, domain: str = "network") -> bool:
        return domain in self.domains and self.domains[domain].has_constraint(name)

    def is_technique_dead(self, technique_name: str, current_cycle: int,
                          technique_prereqs: list[str],
                          technique_blockers: list[str]) -> bool:
        """Negative cache with resurrection."""
        if technique_name not in self.failed_techniques:
            return False
        record = self.failed_techniques[technique_name]
        if record.is_permanent:
            return True
        # Check if profile changed since failure
        domain = "network"  # simplified for Wave 1
        if domain in self.domains:
            state = self.domains[domain]
            for prereq in technique_prereqs:
                if prereq in state.affordances:
                    return False  # resurrected: new prerequisite met
            for blocker in technique_blockers:
                if blocker not in state.constraints:
                    return False  # resurrected: blocker removed
        return True

    def is_stuck(self, current_cycle: int) -> bool:
        """No new info for 5+ cycles."""
        return (current_cycle - self.last_new_info_cycle) > 5

    def to_dict(self) -> dict:
        return {
            "target_id": self.target_id,
            "domains": {k: v.to_dict() for k, v in self.domains.items()},
            "failed_techniques": {
                k: {"cycle": v.cycle, "reason_class": v.reason_class,
                    "is_permanent": v.is_permanent}
                for k, v in self.failed_techniques.items()
            },
            "last_new_info_cycle": self.last_new_info_cycle,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "TargetModel":
        model = cls(target_id=d.get("target_id", ""))
        model.domains = {
            k: DomainState.from_dict(v) for k, v in d.get("domains", {}).items()
        }
        model.failed_techniques = {
            k: FailureRecord(**v) for k, v in d.get("failed_techniques", {}).items()
        }
        model.last_new_info_cycle = d.get("last_new_info_cycle", 0)
        return model
