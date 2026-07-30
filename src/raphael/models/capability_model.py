"""CapabilityModel — tracks owned, acquiring, and gapped capabilities."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Capability:
    """A capability the attacker can have."""
    name: str
    status: str = "gap"  # "owned" | "acquiring" | "gap"
    acquisition_cost_hours: float = 0.0
    acquisition_strategy: list[str] = field(default_factory=list)
    expires_at: Optional[float] = None
    dependencies: list[str] = field(default_factory=list)


@dataclass
class AcquisitionExecution:
    """An in-progress capability acquisition."""
    capability_name: str
    strategy: list[str]
    started_at: float
    estimated_hours_remaining: float
    check_interval_seconds: float = 30.0


@dataclass
class CapabilityModel:
    """Tracks all capabilities and their acquisition status."""
    owned: dict[str, Capability] = field(default_factory=dict)
    acquisition_queue: list[AcquisitionExecution] = field(default_factory=list)
    gaps: dict[str, Capability] = field(default_factory=dict)

    def is_owned(self, name: str) -> bool:
        return name in self.owned

    def is_acquiring(self, name: str) -> bool:
        return any(a.capability_name == name for a in self.acquisition_queue)

    def eta(self, name: str) -> Optional[float]:
        if self.is_owned(name):
            return 0.0
        for a in self.acquisition_queue:
            if a.capability_name == name:
                return a.estimated_hours_remaining
        return None

    def ensure_owned(self, name: str, cost_hours: float = 0.0):
        """Mark a capability as owned, creating it if needed."""
        if name not in self.owned:
            self.owned[name] = Capability(
                name=name, status="owned",
                acquisition_cost_hours=cost_hours
            )
        else:
            self.owned[name].status = "owned"
        # Remove from acquisition queue and gaps
        self.acquisition_queue = [
            a for a in self.acquisition_queue if a.capability_name != name
        ]
        self.gaps.pop(name, None)

    def to_dict(self) -> dict:
        return {
            "owned": {k: v.name for k, v in self.owned.items()},
            "acquisition_queue": [
                {"capability_name": a.capability_name,
                 "estimated_hours_remaining": a.estimated_hours_remaining}
                for a in self.acquisition_queue
            ],
            "gaps": list(self.gaps.keys()),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "CapabilityModel":
        model = cls()
        for name in d.get("owned", {}):
            model.owned[name] = Capability(name=name, status="owned")
        for a in d.get("acquisition_queue", []):
            model.acquisition_queue.append(AcquisitionExecution(
                capability_name=a["capability_name"],
                strategy=[],
                started_at=0,
                estimated_hours_remaining=a.get("estimated_hours_remaining", 1.0),
            ))
        for name in d.get("gaps", []):
            model.gaps[name] = Capability(name=name, status="gap")
        return model
