"""
Interactive Shell Capability Package — E1 Series.

Provides stateful, brokered interactive shell sessions (SSH, reverse shells, etc.)
with per-command authorization, command filtering, and TTY output normalization.

Components:
- InteractiveShellCapability: Abstract base capability
- SSHShellCapability: SSH-based shell sessions (paramiko)
- ReverseShellCapability: Reverse shell listener (pwntools)
- ShellSession: Brokered session state object
- CommandFilterPipeline: Tier 1 (static) + Tier 2 (LLM) command authorization
- TTYNormalizer: ANSI stripping, prompt detection, structured output parsing
- ListenerManager: Broker-exclusive reverse shell listener provisioning
"""

from .capability import (
    InteractiveShellCapability,
    ShellCapabilityType,
    ShellConnectionInfo,
)
from .ssh_shell import SSHShellCapability
from .reverse_shell import ReverseShellCapability
from .session import (
    ShellSession,
    ShellSessionStatus,
    ShellSessionProposal,
    SessionReceipt,
    CommandReceipt,
    CommandFilterDecision,
)
from .command_filter import (
    CommandFilterPipeline,
    FilterDecision,
    StaticAllowlist,
    LLMIntentClassifier,
)
from .tty_normalizer import (
    TTYNormalizer,
    ParsedOutput,
    EvidenceExtractor,
)
from .listener_manager import ListenerManager

__all__ = [
    "InteractiveShellCapability",
    "ShellCapabilityType",
    "ShellConnectionInfo",
    "SSHShellCapability",
    "ReverseShellCapability",
    "ShellSession",
    "ShellSessionStatus",
    "ShellSessionProposal",
    "SessionReceipt",
    "CommandReceipt",
    "CommandFilterDecision",
    "CommandFilterPipeline",
    "FilterDecision",
    "StaticAllowlist",
    "LLMIntentClassifier",
    "TTYNormalizer",
    "ParsedOutput",
    "EvidenceExtractor",
    "ListenerManager",
]