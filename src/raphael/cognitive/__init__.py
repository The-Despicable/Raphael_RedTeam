from __future__ import annotations

from raphael.cognitive.models import (
    Affordance,
    AffordanceType,
    Capability,
    CapabilityModel,
    CapabilityState,
    Constraint,
    ConstraintType,
    TargetModel,
    Unknown,
)

from raphael.cognitive.planner import GreedyPlanner, MemoryPrior, TechniqueNode
from raphael.cognitive.thermoregulator import RiskLevel, Thermoregulator, ThermoregulatorConfig
from raphael.cognitive.negative_cache import NegativeCache, NegativeEntry
from raphael.cognitive.episodic_memory import (
    EpisodicMemory,
    ProceduralMemory,
    SemanticMemory,
    Episode,
    Skill,
)
from raphael.cognitive.model_refiner import ModelRefiner, RefinementResult
from raphael.cognitive.hypothesizer import Hypothesizer, Hypothesis
from raphael.cognitive.capability_acquisition import CapabilityAcquisitionPipeline, AcquisitionPlan
from raphael.cognitive.reflection import ReflectionEngine, ReflectionResult
from raphael.cognitive.protocol_inference import ProtocolInferenceEngine, ProtocolSignature
from raphael.cognitive.network_graph import NetworkGraph, NetworkNode, NetworkEdge
from raphael.cognitive.self_modification import SelfModificationEngine, ModificationProposal

__all__ = [
    # Models
    "Affordance",
    "AffordanceType",
    "Capability",
    "CapabilityModel",
    "CapabilityState",
    "Constraint",
    "ConstraintType",
    "TargetModel",
    "Unknown",
    # Core
    "GreedyPlanner",
    "MemoryPrior",
    "TechniqueNode",
    "RiskLevel",
    "Thermoregulator",
    "ThermoregulatorConfig",
    "NegativeCache",
    "NegativeEntry",
    "EpisodicMemory",
    "ProceduralMemory",
    "SemanticMemory",
    "Episode",
    "Skill",
    # New modules
    "ModelRefiner",
    "RefinementResult",
    "Hypothesizer",
    "Hypothesis",
    "CapabilityAcquisitionPipeline",
    "AcquisitionPlan",
    "ReflectionEngine",
    "ReflectionResult",
    "ProtocolInferenceEngine",
    "ProtocolSignature",
    "NetworkGraph",
    "NetworkNode",
    "NetworkEdge",
    "SelfModificationEngine",
    "ModificationProposal",
]