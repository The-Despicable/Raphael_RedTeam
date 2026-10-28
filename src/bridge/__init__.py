"""src.bridge — external target access for Raphael 2.0.

The ExternalTargetManager is the single policy enforcement point for all
external (internet / VPN / Tor) operations issued by Raphael agents.
"""
from .external_target_manager import (
    CANARY_HOSTS,
    BridgeError,
    ComponentError,
    EgressPolicy,
    EgressProfile,
    ExternalTargetManager,
    NotConfiguredError,
    PolicyViolationError,
    RateLimitError,
    parse_ovpn_profile,
)

__all__ = [
    "CANARY_HOSTS",
    "BridgeError",
    "ComponentError",
    "EgressPolicy",
    "EgressProfile",
    "ExternalTargetManager",
    "NotConfiguredError",
    "PolicyViolationError",
    "RateLimitError",
    "parse_ovpn_profile",
]
