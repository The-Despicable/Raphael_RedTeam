"""trust.py — Trust provenance model for Raphael.

Defines the epistemic classification of information.
Every observation, inference, and instruction carries a trust level that
describes its *origin class* — not its truth value.

Trust levels are not a strict hierarchy. TARGET_CONTROLLED data may be true;
MODEL_INFERENCE may be correct. The classification describes *how the
information entered the system*, which determines how it should be handled
by downstream reasoning.

Schema version: 1
"""

from enum import Enum
from typing import Optional


class TrustLevel(str, Enum):
    """Epistemic origin class of a piece of information.

    SYSTEM_POLICY         — Hardcoded rules, configuration, constraints.
                           Highest epistemic authority: defines what Raphael
                           is allowed/permitted/required to do.
    OPERATOR_INSTRUCTION  — Direct command from the human operator.
                           Binding within the current engagement.
    ENGAGEMENT_CONFIG     — Engagement parameters (targets, scope, RoE).
                           Authoritative for this engagement only.
    TOOL_OBSERVATION      — Output from a security tool (nmap, nuclei, etc.).
                           Trusted as an accurate report of what the tool
                           observed, NOT as an accurate interpretation.
    TARGET_CONTROLLED     — Data originating from the target system (HTTP
                           response body, command output, file contents).
                           Epistemically untrusted: the target controls it.
    MODEL_INFERENCE       — Output from an LLM or other AI model.
                           Epistemically untrusted: models can hallucinate
                           regardless of input quality.
    """
    SYSTEM_POLICY = "system_policy"
    OPERATOR_INSTRUCTION = "operator_instruction"
    ENGAGEMENT_CONFIG = "engagement_config"
    TOOL_OBSERVATION = "tool_observation"
    TARGET_CONTROLLED = "target_controlled"
    MODEL_INFERENCE = "model_inference"


# ── Future Evidence object ──────────────────────────────────────
# This is the target structure for trust provenance migration.
# Currently TrustLevel is embedded in Finding (see models.py).
# When Evidence becomes a first-class object, it should carry these fields.
# For now, Finding.trust_level and Finding.source_detail serve as the
# compatibility bridge.

class Provenance:
    """Structured provenance metadata.

    Separates *what happened* (source_detail) from *what epistemic class
    it belongs to* (trust_level). A TOOL_OBSERVATION may contain
    TARGET_CONTROLLED bytes — the observation wrapper is trusted, the
    content inside is not.
    """
    def __init__(
        self,
        trust_level: TrustLevel,
        source_detail: str = "",
        tool_name: str = "",
        timestamp: float = 0.0,
    ):
        self.trust_level = trust_level
        self.source_detail = source_detail
        self.tool_name = tool_name
        self.timestamp = timestamp

    def to_dict(self) -> dict:
        return {
            "trust_level": self.trust_level.value,
            "source_detail": self.source_detail,
            "tool_name": self.tool_name,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Provenance":
        return cls(
            trust_level=TrustLevel(d.get("trust_level", "tool_observation")),
            source_detail=d.get("source_detail", ""),
            tool_name=d.get("tool_name", ""),
            timestamp=d.get("timestamp", 0.0),
        )

    def __repr__(self) -> str:
        return f"Provenance({self.trust_level.value}, {self.source_detail})"


# ── Invariant: nested trust levels ──────────────────────────────
# A TOOL_OBSERVATION can wrap TARGET_CONTROLLED content.
# The observation itself (e.g., "received HTTP 200 from 10.0.0.1")
# is trusted at TOOL_OBSERVATION level.
# The content of the response body is TARGET_CONTROLLED.
# Downstream consumers MUST NOT conflate the wrapper trust with
# the content trust. This is a semantic invariant, not an enforcement
# mechanism — enforcement belongs in the CapabilityBroker.
