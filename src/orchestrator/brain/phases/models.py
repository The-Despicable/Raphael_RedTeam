from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any

from orchestrator.brain.trust import TrustLevel


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Finding:
    phase: str = ""
    type: str = ""
    severity: Severity = Severity.INFO
    description: str = ""
    evidence: str = ""
    target: str = ""
    port: int = 0
    service: str = ""
    # ── Trust provenance (A1) ─────────────────────────────────────
    # trust_level describes the epistemic class of this finding.
    # Default TOOL_OBSERVATION preserves backward compatibility with
    # existing code that creates Finding without specifying trust.
    # source_detail provides provenance context (e.g., tool name, URL).
    # These fields will migrate to a future Evidence object.
    trust_level: TrustLevel = TrustLevel.TOOL_OBSERVATION
    source_detail: str = ""

    def to_dict(self) -> dict:
        return {
            "phase": self.phase,
            "type": self.type,
            "severity": self.severity.value,
            "description": self.description,
            "evidence": self.evidence,
            "target": self.target,
            "port": self.port,
            "service": self.service,
            "trust_level": self.trust_level.value,
            "source_detail": self.source_detail,
        }


@dataclass
class PhaseResult:
    phase: str = ""
    success: bool = False
    status: str = "implemented"  # "implemented", "not_implemented", "partial", "failed", "unavailable"
    findings: list[Finding] = field(default_factory=list)
    summary: str = ""
    error: str = ""
    latency: float = 0.0


# ── NOT IMPLEMENTED STUBS ──────────────────────────────────────
# These 9 phase executors are declared but have no implementation.
# They return success=False with status="not_implemented" and a
# descriptive error message. This is HONEST — the system does NOT
# claim capability it doesn't have.
#
# To implement one: replace the stub with actual execution code that
# populates findings, sets success=True on real success, and updates
# status to "implemented".

async def _exec_harvest(target: str, findings: list[Finding]) -> PhaseResult:
    return PhaseResult(
        phase="harvest", success=False, status="not_implemented",
        summary="Harvest phase is not implemented",
        error="NOT_IMPLEMENTED: _exec_harvest is a stub. Replace with actual harvest logic (subdomain enumeration, OSINT, ASN lookup, etc.)",
    )


async def _exec_recon(target: str, findings: list[Finding]) -> PhaseResult:
    return PhaseResult(
        phase="recon", success=False, status="not_implemented",
        summary="Recon phase is not implemented",
        error="NOT_IMPLEMENTED: _exec_recon is a stub. Replace with actual recon logic (port scanning, service detection, passive recon)",
    )


async def _exec_scan(target: str, findings: list[Finding]) -> PhaseResult:
    return PhaseResult(
        phase="scan", success=False, status="not_implemented",
        summary="Scan phase is not implemented",
        error="NOT_IMPLEMENTED: _exec_scan is a stub. Replace with actual scanning logic (nmap, nuclei, custom probes)",
    )


async def _exec_exploit(target: str, findings: list[Finding]) -> PhaseResult:
    return PhaseResult(
        phase="exploit", success=False, status="not_implemented",
        summary="Exploit phase is not implemented",
        error="NOT_IMPLEMENTED: _exec_exploit is a stub. Replace with actual exploitation logic (CVE matching, payload delivery, shell acquisition)",
    )


async def _exec_postex(target: str, findings: list[Finding]) -> PhaseResult:
    return PhaseResult(
        phase="postex", success=False, status="not_implemented",
        summary="Post-exploitation phase is not implemented",
        error="NOT_IMPLEMENTED: _exec_postex is a stub. Replace with actual post-ex logic (privilege escalation, persistence, credential dumping)",
    )


async def _exec_lateral(target: str, findings: list[Finding]) -> PhaseResult:
    return PhaseResult(
        phase="lateral", success=False, status="not_implemented",
        summary="Lateral movement phase is not implemented",
        error="NOT_IMPLEMENTED: _exec_lateral is a stub. Replace with actual lateral movement logic (pass-the-hash, SSH hopping, RDP/WMI)",
    )


async def _exec_credential(target: str, findings: list[Finding]) -> PhaseResult:
    return PhaseResult(
        phase="credential", success=False, status="not_implemented",
        summary="Credential phase is not implemented",
        error="NOT_IMPLEMENTED: _exec_credential is a stub. Replace with actual credential logic (brute-force, spraying, honey-token capture)",
    )


async def _exec_exfil(target: str, findings: list[Finding]) -> PhaseResult:
    return PhaseResult(
        phase="exfil", success=False, status="not_implemented",
        summary="Exfiltration phase is not implemented",
        error="NOT_IMPLEMENTED: _exec_exfil is a stub. Replace with actual exfil logic (data discovery, staging, C2 transfer)",
    )


async def _exec_phish(target: str, findings: list[Finding]) -> PhaseResult:
    return PhaseResult(
        phase="phish", success=False, status="not_implemented",
        summary="Phishing phase is not implemented",
        error="NOT_IMPLEMENTED: _exec_phish is a stub. Replace with actual phishing logic (template generation, SMTP relay, tracking pixel)",
    )


async def _exec_cicd(target: str, findings: list[Finding]) -> PhaseResult:
    from orchestrator.brain.phases.cicd_executor import exec_cicd_phase
    return await exec_cicd_phase(target, findings)


async def _exec_ml_attack(target: str, findings: list[Finding]) -> PhaseResult:
    from orchestrator.brain.phases.ml_attack_executor import exec_ml_attack_phase
    return await exec_ml_attack_phase(target, findings)


async def _exec_cloud_abuse(target: str, findings: list[Finding]) -> PhaseResult:
    from orchestrator.brain.phases.cloud_executor import exec_cloud_phase
    return await exec_cloud_phase(target, findings)


async def _exec_container_escape(target: str, findings: list[Finding]) -> PhaseResult:
    from orchestrator.brain.phases.container_escape_executor import exec_container_escape_phase
    return await exec_container_escape_phase(target, findings)


PHASE_EXECUTORS: dict[str, Any] = {
    "harvest": _exec_harvest,
    "recon": _exec_recon,
    "scan": _exec_scan,
    "exploit": _exec_exploit,
    "postex": _exec_postex,
    "lateral": _exec_lateral,
    "credential": _exec_credential,
    "exfil": _exec_exfil,
    "phish": _exec_phish,
    "cicd": _exec_cicd,
    "ml_attack": _exec_ml_attack,
    "cloud_abuse": _exec_cloud_abuse,
    "container_escape": _exec_container_escape,
}
