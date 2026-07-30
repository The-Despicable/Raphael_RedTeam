from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse


class EnumMethod(str, Enum):
    """VHOST enumeration methods."""
    DNS_BRUTE = "dns_brute"
    CT_LOGS = "ct_logs"
    HOST_FUZZ = "host_fuzz"
    SSL_SAN = "ssl_san"
    RECURSIVE = "recursive"


class EnumStatus(str, Enum):
    """Status of enumeration."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass(slots=True)
class VHOSTTarget:
    """Target for VHOST enumeration."""
    ip: str
    port: int = 80
    hostname: Optional[str] = None
    ssl: bool = False
    scope: Optional[str] = None
    custom_wordlist: Optional[str] = None


@dataclass(slots=True)
class DiscoveredHost:
    """A discovered virtual host."""
    host: str
    ip: str
    port: int
    method: EnumMethod
    status_code: int
    content_length: int
    content_hash: str
    headers: Dict[str, str] = field(default_factory=dict)
    ssl_info: Optional[Dict[str, Any]] = None
    discovered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    confidence: float = 1.0
    technique_id: str = ""


@dataclass(slots=True)
class EnumSession:
    """State of an enumeration session."""
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    target: VHOSTTarget = None
    methods: List[EnumMethod] = field(default_factory=list)
    discovered: List[DiscoveredHost] = field(default_factory=list)
    status: EnumStatus = EnumStatus.PENDING
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    errors: List[str] = field(default_factory=list)
    seen_hashes: Set[str] = field(default_factory=set)
    recursive_queue: List[DiscoveredHost] = field(default_factory=list)


@dataclass(slots=True)
class EnumConfig:
    """Configuration for VHOST enumeration."""
    target: VHOSTTarget
    methods: List[EnumMethod] = field(default_factory=lambda: [
        EnumMethod.DNS_BRUTE, EnumMethod.CT_LOGS, EnumMethod.HOST_FUZZ, EnumMethod.SSL_SAN
    ])
    wordlist: Optional[str] = None
    wordlist_inline: Optional[List[str]] = None
    threads: int = 50
    timeout: float = 10.0
    recursive: bool = True
    recursive_depth: int = 2
    rate_limit: int = 100
    follow_redirects: bool = True
    deduplicate: bool = True
    min_confidence: float = 0.5
    output_format: str = "event"