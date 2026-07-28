"""
ML Supply Chain Attack Module (P1 - FORGE Phase 1)

Attack surface for HuggingFace-level ML supply chain compromise.
Provides pickle/safetensors payload construction, model format analysis,
HF Hub API interaction, and supply chain injection.

Modules:
- pickle_payload_factory: Malicious pickle/safetensors payload generation
- model_format_analyzer: ML model file format analysis and classification
- hf_hub_api_client: HuggingFace Hub API client for model interaction
- supply_chain_injector: Pipeline injection for ML supply chain attacks
"""

from .pickle_payload_factory import PicklePayloadFactory, PayloadConfig, PayloadType, PayloadFormat
from .model_format_analyzer import ModelFormatAnalyzer, ModelFile, ModelFormat
from .hf_hub_api_client import HFHubAPIClient, ModelInfo, HFQueryResult
from .supply_chain_injector import SupplyChainInjector, InjectionPlan, InjectionVector

__all__ = [
    "PicklePayloadFactory", "PayloadConfig", "PayloadType", "PayloadFormat",
    "ModelFormatAnalyzer", "ModelFile", "ModelFormat",
    "HFHubAPIClient", "ModelInfo", "HFQueryResult",
    "SupplyChainInjector", "InjectionPlan", "InjectionVector",
]

__version__ = "0.1.0"
