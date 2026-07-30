"""EngagementState — the full state of a Raphael engagement at a point in time."""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Optional, Any
import json

from raphael.models.target_model import TargetModel
from raphael.models.capability_model import CapabilityModel


@dataclass
class EngagementState:
    """Full state snapshot. Serializable for checkpoint/restore."""
    engagement_id: str
    target: TargetModel
    capabilities: CapabilityModel
    current_cycle: int = 0
    sub_goals: list[str] = field(default_factory=list)
    target_address: str = ""  # IP or domain
    status: str = "running"  # "running" | "paused" | "completed" | "burned"

    def to_dict(self) -> dict:
        return {
            "engagement_id": self.engagement_id,
            "target": self.target.to_dict(),
            "capabilities": self.capabilities.to_dict(),
            "current_cycle": self.current_cycle,
            "sub_goals": self.sub_goals,
            "target_address": self.target_address,
            "status": self.status,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, d: dict) -> "EngagementState":
        return cls(
            engagement_id=d.get("engagement_id", "unknown"),
            target=TargetModel.from_dict(d.get("target", {})),
            capabilities=CapabilityModel.from_dict(d.get("capabilities", {})),
            current_cycle=d.get("current_cycle", 0),
            sub_goals=d.get("sub_goals", []),
            target_address=d.get("target_address", ""),
            status=d.get("status", "running"),
        )

    @classmethod
    def fresh(cls, engagement_id: str, target_address: str) -> "EngagementState":
        """Create a fresh engagement state for a new target."""
        return cls(
            engagement_id=engagement_id,
            target=TargetModel(target_id=target_address),
            capabilities=CapabilityModel(),
            target_address=target_address,
        )
