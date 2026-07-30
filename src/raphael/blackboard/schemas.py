from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator


class TechniqueType(str, Enum):
    RECON = "recon"
    EXPLOIT = "exploit"
    SCAN = "scan"
    ENUMERATE = "enumerate"

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class AccessType(str, Enum):
    REVERSE_SHELL = "reverse_shell"
    BIND_SHELL = "bind_shell"
    FILE_WRITE = "file_write"
    DNS_EXFIL = "dns_exfil"
    NONE = "none"

class EnvironmentType(str, Enum):
    CONTAINER = "container"
    VM = "vm"
    BARE_METAL = "bare_metal"
    K8S_POD = "k8s_pod"
    UNKNOWN = "unknown"


class TechniqueEvent(BaseModel):
    """Published when a technique executes."""
    technique_id: str
    technique_type: TechniqueType
    target: str
    success: bool
    output: Optional[str] = None
    error: Optional[str] = None
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    duration_ms: int
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ServiceNode(BaseModel):
    """A discovered service on a target."""
    host: str
    port: int
    service: str
    version: Optional[str] = None
    vhost: Optional[str] = None
    tech_stack: Dict[str, str] = Field(default_factory=dict)
    headers: Dict[str, str] = Field(default_factory=dict)
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    discovered_by: str = ""  # technique_id


class VulnerabilityEvent(BaseModel):
    """A discovered vulnerability."""
    cve_id: Optional[str] = None
    title: str
    description: str
    severity: Severity
    vector: str  # "pickle_deserialization", "sqli", "lfi", etc.
    evidence: Dict[str, Any]
    exploitable: bool = False
    target: str
    vhost: Optional[str] = None
    discovered_by: str = ""
    confidence: float = Field(ge=0.0, le=1.0, default=0.7)


class ListenerEvent(BaseModel):
    """Published when a listener starts/stops."""
    status: str  # "started", "stopped", "received_connection"
    protocol: str  # "tcp", "http", "dns"
    port: int
    bind_address: str
    connection_received: bool = False
    remote_ip: Optional[str] = None
    connection_time: Optional[datetime] = None


class ExploitDeliveryEvent(BaseModel):
    """Published when an exploit is delivered to target."""
    technique_id: str
    cve_id: Optional[str] = None
    payload_type: str  # "pickle", "shell", "deserialization", etc.
    delivery_vector: str  # "pdf", "http_post", "smb", etc.
    payload_path: Optional[str] = None
    target: str
    vhost: Optional[str] = None
    success: bool
    response_code: Optional[int] = None
    response_body: Optional[str] = None
    error: Optional[str] = None


class VerificationEvent(BaseModel):
    """Published when exploit result is verified."""
    technique_id: str
    verified: bool
    method: str  # "canary", "listener", "dns_callback"
    evidence: Dict[str, Any] = Field(default_factory=dict)
    access_type: AccessType = AccessType.NONE
    shell_pid: Optional[int] = None
    shell_type: Optional[str] = None  # "bash", "sh", "python", "php"
    user: Optional[str] = None
    hostname: Optional[str] = None
    feedback: Optional[str] = None  # Human-readable diagnosis


class EnvironmentProfile(BaseModel):
    """Published after post-access enumeration."""
    env_type: EnvironmentType = EnvironmentType.UNKNOWN
    is_container: bool = False
    container_runtime: Optional[str] = None
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    kernel_version: Optional[str] = None
    users: List[str] = Field(default_factory=list)
    groups: List[str] = Field(default_factory=list)
    network_interfaces: List[Dict[str, str]] = Field(default_factory=list)
    mount_points: List[Dict[str, str]] = Field(default_factory=list)
    internal_services: List[Dict[str, Any]] = Field(default_factory=list)
    sudo_rules: Optional[str] = None
    capabilities: List[str] = Field(default_factory=list)
    suid_binaries: List[str] = Field(default_factory=list)
    writable_dirs: List[str] = Field(default_factory=list)


class FlagCaptureEvent(BaseModel):
    """Published when a flag is captured."""
    flag_type: str  # "user", "root"
    flag_hash: str  # first 8 chars or hash prefix
    location: str
    method: str  # "rce", "lfi", "ssh", "privesc", "direct_read"
    target: str
    captured_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class PersonaSwitchEvent(BaseModel):
    """Published when the persona changes."""
    from_persona: str
    to_persona: str
    trigger: str  # "auto", "manual", "state_machine"
    reason: str
    switched_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class DetectionEvent(BaseModel):
    """Published when detection risk crosses threshold."""
    risk_level: float = Field(ge=0.0, le=1.0)
    threshold_exceeded: str  # "thermoregulator", "persona", "kill_switch"
    source: str  # "waf", "ids", "api_response", "kill_chain_analysis"
    evidence: Dict[str, Any] = Field(default_factory=dict)
    action_taken: Optional[str] = None  # "pause", "stealth", "kill_switch"


SCHEMA_REGISTRY = {
    "technique.result": TechniqueEvent,
    "service.discovered": ServiceNode,
    "vuln.found": VulnerabilityEvent,
    "listener.status": ListenerEvent,
    "exploit.delivered": ExploitDeliveryEvent,
    "exploit.verified": VerificationEvent,
    "environment.profiled": EnvironmentProfile,
    "flag.captured": FlagCaptureEvent,
    "persona.switched": PersonaSwitchEvent,
    "detection.triggered": DetectionEvent,
}