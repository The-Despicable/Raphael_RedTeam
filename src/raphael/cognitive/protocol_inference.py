from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from raphael.cognitive.models import TargetModel, Affordance, AffordanceType
from raphael.models.target_model import DomainState

logger = logging.getLogger(__name__)


@dataclass
class ProtocolSignature:
    name: str
    port: int
    banner_patterns: List[str] = field(default_factory=list)
    version_pattern: Optional[str] = None
    implied_affordances: List[AffordanceType] = field(default_factory=list)
    common_vulnerabilities: List[str] = field(default_factory=list)


class ProtocolInferenceEngine:
    """Infers protocols and affordances from service banners and behavior."""
    
    SIGNATURES = [
        ProtocolSignature(
            name="ssh",
            port=22,
            banner_patterns=[r"SSH-(\d+\.\d+)"],
            implied_affordances=[AffordanceType.COMMAND_CONTROL, AffordanceType.CREDENTIAL_ACCESS],
            common_vulnerabilities=["CVE-2023-25136", "CVE-2020-14145"],
        ),
        ProtocolSignature(
            name="http",
            port=80,
            banner_patterns=[r"HTTP/1\.[01]", r"Server:\s*([^\r\n]+)"],
            implied_affordances=[AffordanceType.DISCOVERY, AffordanceType.FILE_READ],
            common_vulnerabilities=["CVE-2021-41773", "CVE-2021-42013"],
        ),
        ProtocolSignature(
            name="https",
            port=443,
            banner_patterns=[r"HTTP/1\.[01]", r"Server:\s*([^\r\n]+)"],
            implied_affordances=[AffordanceType.DISCOVERY, AffordanceType.FILE_READ],
            common_vulnerabilities=[],
        ),
        ProtocolSignature(
            name="smb",
            port=445,
            banner_patterns=[r"SMB", r"Windows\s+(\d+)"],
            implied_affordances=[
                AffordanceType.FILE_READ, AffordanceType.FILE_WRITE,
                AffordanceType.CREDENTIAL_ACCESS, AffordanceType.LATERAL_MOVEMENT
            ],
            common_vulnerabilities=["MS17-010", "CVE-2020-0796"],
        ),
        ProtocolSignature(
            name="ldap",
            port=389,
            banner_patterns=[r"LDAP", r"Active Directory"],
            implied_affordances=[AffordanceType.CREDENTIAL_ACCESS, AffordanceType.DISCOVERY, AffordanceType.LATERAL_MOVEMENT],
            common_vulnerabilities=["CVE-2020-1472"],
        ),
        ProtocolSignature(
            name="rdp",
            port=3389,
            banner_patterns=[r"RDP", r"Terminal Services"],
            implied_affordances=[AffordanceType.COMMAND_CONTROL, AffordanceType.CREDENTIAL_ACCESS],
            common_vulnerabilities=["CVE-2019-0708", "CVE-2019-1182"],
        ),
        ProtocolSignature(
            name="mysql",
            port=3306,
            banner_patterns=[r"MySQL", r"MariaDB"],
            implied_affordances=[AffordanceType.DATA_EXFILTRATION, AffordanceType.CREDENTIAL_ACCESS],
            common_vulnerabilities=["CVE-2016-6663"],
        ),
        ProtocolSignature(
            name="postgresql",
            port=5432,
            banner_patterns=[r"PostgreSQL"],
            implied_affordances=[AffordanceType.DATA_EXFILTRATION, AffordanceType.COMMAND_CONTROL],
            common_vulnerabilities=["CVE-2019-9193"],
        ),
        ProtocolSignature(
            name="redis",
            port=6379,
            banner_patterns=[r"Redis"],
            implied_affordances=[AffordanceType.FILE_WRITE, AffordanceType.COMMAND_CONTROL, AffordanceType.DATA_EXFILTRATION],
            common_vulnerabilities=["CVE-2022-0543"],
        ),
        ProtocolSignature(
            name="mongodb",
            port=27017,
            banner_patterns=[r"MongoDB"],
            implied_affordances=[AffordanceType.DATA_EXFILTRATION, AffordanceType.COMMAND_CONTROL],
            common_vulnerabilities=["CVE-2019-2389"],
        ),
        ProtocolSignature(
            name="ftp",
            port=21,
            banner_patterns=[r"FTP", r"220\s"],
            implied_affordances=[AffordanceType.FILE_READ, AffordanceType.FILE_WRITE],
            common_vulnerabilities=["CVE-2015-1419"],
        ),
        ProtocolSignature(
            name="dns",
            port=53,
            banner_patterns=[],
            implied_affordances=[AffordanceType.DISCOVERY, AffordanceType.DATA_EXFILTRATION],
            common_vulnerabilities=[],
        ),
    ]
    
    SERVICE_AFFORDANCE_MAP = {
        "ssh": ["ssh_service"],
        "http": ["http_service"],
        "https": ["https_service", "http_service"],
        "smb": ["smb_service"],
        "netbios": ["netbios_service"],
        "ldap": ["ldap_service"],
        "rdp": ["rdp_service"],
        "mysql": ["mysql_service"],
        "postgresql": ["postgresql_service"],
        "redis": ["redis_service"],
        "mongodb": ["mongodb_service"],
        "ftp": ["ftp_service"],
        "dns": ["dns_service"],
        "msrpc": ["msrpc_service"],
        "rpc": ["msrpc_service"],
        "nfs": ["nfs_service"],
        "snmp": ["snmp_service"],
    }
    
    PORT_SERVICE_MAP = {
        22: "ssh",
        80: "http",
        443: "https",
        445: "smb",
        139: "netbios",
        389: "ldap",
        636: "ldap",
        3389: "rdp",
        3306: "mysql",
        5432: "postgresql",
        6379: "redis",
        27017: "mongodb",
        21: "ftp",
        53: "dns",
        135: "msrpc",
        111: "rpc",
        2049: "nfs",
        161: "snmp",
        8080: "http",
        8443: "https",
    }
    
    def __init__(self, target_model: TargetModel):
        self.target_model = target_model
    
    def infer_from_banner(self, port: int, banner: str) -> List[AffordanceType]:
        affordances = set()
        for sig in self.SIGNATURES:
            if sig.port == port:
                for pattern in sig.banner_patterns:
                    if re.search(pattern, banner, re.IGNORECASE):
                        affordances.update(sig.implied_affordances)
                        break
        return list(affordances)
    
    def infer_from_port(self, port: int) -> List[AffordanceType]:
        affordances = set()
        for sig in self.SIGNATURES:
            if sig.port == port:
                affordances.update(sig.implied_affordances)
        return list(affordances)
    
    def get_common_vulnerabilities(self, port: int) -> List[str]:
        vulns = []
        for sig in self.SIGNATURES:
            if sig.port == port:
                vulns.extend(sig.common_vulnerabilities)
        return vulns
    
    def infer_from_service_info(self, service: str, version: str) -> List[AffordanceType]:
        affordances = set()
        for sig in self.SIGNATURES:
            if sig.name.lower() in service.lower():
                affordances.update(sig.implied_affordances)
        return list(affordances)
    
    def update_target_model(self, port: int, banner: str = "", service: str = "", version: str = "") -> List[str]:
        new_affordances = []
        if banner:
            inferred = self.infer_from_banner(port, banner)
            new_affordances.extend(inferred)
        inferred = self.infer_from_port(port)
        new_affordances.extend(inferred)
        if service:
            inferred = self.infer_from_service_info(service, version or "")
            new_affordances.extend(inferred)
        for aff_type in set(new_affordances):
            if not any(a.type == aff_type for a in self.target_model.affordances.values()):
                self.target_model.add_affordance(Affordance(
                    type=aff_type,
                    target_id=self.target_model.target_id,
                    description=f"Inferred from {service or 'banner'} on port {port}",
                    confidence=0.7,
                ))
        return list(set(new_affordances))
    
    @classmethod
    def infer_affordances_for_domain_state(
        cls,
        domain_state: DomainState,
        port: int,
        banner: str = "",
        service: str = "",
        version: str = "",
        min_confidence: float = 0.5
    ) -> List[str]:
        added = []
        port_affordances = cls._infer_from_port_static(port)
        for aff in port_affordances:
            if aff not in domain_state.affordances:
                domain_state.affordances.add(aff)
                added.append(aff)
        if banner:
            banner_affordances = cls._infer_from_banner_static(port, banner)
            for aff in banner_affordances:
                if aff not in domain_state.affordances:
                    domain_state.affordances.add(aff)
                    added.append(aff)
        if service:
            service_affordances = cls._infer_from_service_static(service, version or "")
            for aff in service_affordances:
                if aff not in domain_state.affordances:
                    domain_state.affordances.add(aff)
                    added.append(aff)
        if added:
            logger.info(f"ProtocolInference: port {port} -> added {len(added)} affordances: {added[:5]}...")
        return added
    
    @classmethod
    def _infer_from_port_static(cls, port: int) -> List[str]:
        affordances = []
        if port in cls.PORT_SERVICE_MAP:
            svc = cls.PORT_SERVICE_MAP[port]
            if svc in cls.SERVICE_AFFORDANCE_MAP:
                affordances.extend(cls.SERVICE_AFFORDANCE_MAP[svc])
        for sig in cls.SIGNATURES:
            if sig.port == port:
                for aff_type in sig.implied_affordances:
                    affordances.append(aff_type.value)
        return list(set(affordances))
    
    @classmethod
    def _infer_from_banner_static(cls, port: int, banner: str) -> List[str]:
        affordances = []
        for sig in cls.SIGNATURES:
            if sig.port == port:
                for pattern in sig.banner_patterns:
                    if re.search(pattern, banner, re.IGNORECASE):
                        for aff_type in sig.implied_affordances:
                            affordances.append(aff_type.value)
                        break
        return affordances
    
    @classmethod
    def _infer_from_service_static(cls, service: str, version: str) -> List[str]:
        affordances = []
        for sig in cls.SIGNATURES:
            if sig.name.lower() in service.lower():
                for aff_type in sig.implied_affordances:
                    affordances.append(aff_type.value)
        for svc_name, affs in cls.SERVICE_AFFORDANCE_MAP.items():
            if svc_name in service.lower():
                affordances.extend(affs)
        return list(set(affordances))
