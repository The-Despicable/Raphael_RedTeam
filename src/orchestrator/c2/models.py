from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


class SessionStatus(str, Enum):
    ALIVE = "alive"
    DEAD = "dead"
    STALE = "stale"


@dataclass
class C2Session:
    id: str
    hostname: str
    address: str
    os: str
    arch: str
    transport: str
    status: SessionStatus
    last_checkin: float
    socks_port: Optional[int] = None
    proxy_url: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "hostname": self.hostname,
            "address": self.address,
            "os": self.os,
            "arch": self.arch,
            "transport": self.transport,
            "status": self.status.value,
            "last_checkin": self.last_checkin,
            "socks_port": self.socks_port,
            "proxy_url": self.proxy_url,
        }


@dataclass
class ImplantConfig:
    os: str
    arch: str
    name: str
    limit_domain: Optional[str] = None
    limit_hostname: Optional[str] = None
    format: str = "exe"
    transport: str = "mtls"


@dataclass
class TaskResult:
    session_id: str
    task_id: str
    output: str
    error: Optional[str] = None
    completed: bool = True
    duration: float = 0.0
