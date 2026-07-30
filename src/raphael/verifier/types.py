from __future__ import annotations

import uuid
import time
import secrets
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime


class ObservationChannel(str, Enum):
    """Observation channel types for verification."""
    TCP_LISTENER = "tcp_listener"
    HTTP_CANARY = "http_canary"
    DNS_CALLBACK = "dns_callback"
    PROCESS_CHECK = "process_check"


class VerificationResult(str, Enum):
    """Verification result categories."""
    SUCCESS = "success"
    PARTIAL = "partial"
    BLIND_RCE = "blind_rce"
    FAIL = "fail"
    TIMEOUT = "timeout"


class PayloadVariant(str, Enum):
    """Payload variant types for fallback chain."""
    REVERSE_SHELL = "reverse_shell"
    BIND_SHELL = "bind_shell"
    COMMAND_INJECTION = "command_injection"
    DNS_EXFIL = "dns_exfil"
    WEB_SHELL = "web_shell"


PAYLOAD_FALLBACK_CHAIN: list[PayloadVariant] = [
    PayloadVariant.REVERSE_SHELL,
    PayloadVariant.BIND_SHELL,
    PayloadVariant.COMMAND_INJECTION,
    PayloadVariant.DNS_EXFIL,
    PayloadVariant.WEB_SHELL,
]


@dataclass
class ChannelConfig:
    """Configuration for an observation channel."""
    channel: ObservationChannel
    enabled: bool = True
    timeout: float = 30.0
    params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PreflightRecord:
    """Preflight record with listener configuration."""
    preflight_id: str
    trace_id: str
    technique_id: str
    payload_variant: PayloadVariant
    channels: List[ChannelConfig] = field(default_factory=list)
    listener_port: Optional[int] = None
    canary_token: Optional[str] = None
    dns_domain: Optional[str] = None
    temp_files: List[str] = field(default_factory=list)
    callback_config: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class ChannelObservation:
    """Result from a single observation channel."""
    channel: ObservationChannel
    success: bool
    evidence: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    duration_ms: float = 0.0


@dataclass
class ObservationResult:
    """Aggregated observation result."""
    preflight_id: str
    trace_id: str
    technique_id: str
    channel_results: List[ChannelObservation] = field(default_factory=list)
    overall_result: VerificationResult = VerificationResult.TIMEOUT
    primary_evidence: Dict[str, Any] = field(default_factory=dict)
    duration_ms: float = 0.0
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class VerificationEvent:
    """Verification event to publish."""
    technique_id: str
    verified: bool
    method: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    access_type: str = "none"
    feedback: str = ""


@dataclass
class AdaptationDecision:
    """Decision on whether to retry with different variant."""
    should_retry: bool
    next_variant: Optional[PayloadVariant] = None
    reason: str = ""
    retry_config: Dict[str, Any] = field(default_factory=dict)


def generate_canary_token(length: int = 16) -> str:
    """Generate a random canary token."""
    return secrets.token_urlsafe(length)


def generate_preflight_id() -> str:
    """Generate a unique preflight ID."""
    return f"preflight_{uuid.uuid4().hex[:12]}"


def generate_trace_id() -> str:
    """Generate a unique trace ID."""
    return f"trace_{uuid.uuid4().hex[:16]}"