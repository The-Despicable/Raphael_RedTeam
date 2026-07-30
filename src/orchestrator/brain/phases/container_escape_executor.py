"""
Container/Sandbox Escape Phase Executor (P3 — FORGE Phase 3)

Wraps the container_escape module into the autonomous phase system.
Executes Docker, Kubernetes, and sandbox escape detection as a
standard Raphael phase.
"""

from __future__ import annotations

import os
import json
import logging
import asyncio
from typing import Optional

from orchestrator.brain.phases.models import Finding, PhaseResult, Severity

logger = logging.getLogger(__name__)

_DockerEscapeScanner = None
_K8sEscapeScanner = None
_SandboxDetector = None


def _lazy_imports():
    global _DockerEscapeScanner, _K8sEscapeScanner, _SandboxDetector
    if _DockerEscapeScanner is None:
        from orchestrator.container_escape.docker_escape import DockerEscapeScanner
        _DockerEscapeScanner = DockerEscapeScanner
    if _K8sEscapeScanner is None:
        from orchestrator.container_escape.k8s_escape import K8sEscapeScanner
        _K8sEscapeScanner = K8sEscapeScanner
    if _SandboxDetector is None:
        from orchestrator.container_escape.sandbox_detection import SandboxDetector
        _SandboxDetector = SandboxDetector


async def _exec_container_escape(target: str, findings: list[Finding]) -> PhaseResult:
    """Execute container/sandbox escape phase.

    Phase actions:
    1. Detect if running inside a container
    2. Scan for Docker escape vectors (privileged, caps, cgroup, /proc/1/root)
    3. Detect sandbox environment (gVisor, kata, Firejail)
    4. Analyze LSM/AppArmor/SELinux status
    5. Check Kubernetes escape vectors (service account, RBAC, API)
    6. Assess overall escape potential
    """
    _lazy_imports()

    phase_start = asyncio.get_event_loop().time()
    result = PhaseResult(phase="container_escape", success=True, summary="Container escape scan started")
    escape_findings: list[Finding] = []

    try:
        # --- STEP 1: Container detection ---
        container_findings = await _detect_container(target)
        escape_findings.extend(container_findings)

        is_container = any(f.type == "container_detected" for f in container_findings)

        if is_container:
            # --- STEP 2: Docker escape scan ---
            docker_findings = await _scan_docker_escape(target)
            escape_findings.extend(docker_findings)

            # --- STEP 3: Sandbox detection ---
            sandbox_findings = await _detect_sandbox(target)
            escape_findings.extend(sandbox_findings)

            # --- STEP 4: K8s escape scan ---
            k8s_findings = await _scan_k8s_escape(target)
            escape_findings.extend(k8s_findings)

        else:
            escape_findings.append(Finding(
                phase="container_escape", type="not_in_container",
                severity=Severity.INFO,
                description="Not running inside a container — escape scan skipped",
                target=target,
            ))

        # --- STEP 5: Overall risk assessment ---
        risk_findings = _assess_escape_risk(escape_findings, target)
        escape_findings.extend(risk_findings)

        # Compile summary
        critical = len([f for f in escape_findings if f.severity == Severity.CRITICAL])
        high = len([f for f in escape_findings if f.severity == Severity.HIGH])
        vectors = len([f for f in escape_findings if f.type in ("escape_vector", "escape_path")])

        summary_parts = []
        if critical:
            summary_parts.append(f"{critical} critical")
        if high:
            summary_parts.append(f"{high} high")
        if vectors:
            summary_parts.append(f"{vectors} vectors")
        if not any(f.type == "container_detected" for f in escape_findings):
            summary_parts.append("not in container")
        if not summary_parts:
            summary_parts.append("no issues found")

        result.summary = f"Container escape — {' | '.join(summary_parts)}"
        result.success = bool(critical or high or vectors)

    except Exception as e:
        logger.error(f"[CONTAINER_ESCAPE] Phase execution failed: {e}", exc_info=True)
        result.success = False
        result.error = str(e)
        escape_findings.append(Finding(
            phase="container_escape", type="escape_error",
            severity=Severity.LOW,
            description=f"Container escape phase error: {e}",
            target=target,
        ))

    result.findings = escape_findings
    latency = round(asyncio.get_event_loop().time() - phase_start, 2)
    result.latency = latency
    logger.info(f"[CONTAINER_ESCAPE] Phase complete in {latency}s — {len(escape_findings)} findings")
    return result


async def _detect_container(target: str) -> list[Finding]:
    """Detect if running inside a container."""
    findings = []

    # Check for common container indicators
    indicators = {
        "/.dockerenv": "Docker container (.dockerenv)",
        "/run/.containerenv": "Container environment file",
        "/proc/1/cgroup": "cgroup hierarchy",
    }

    for path, desc in indicators.items():
        if os.path.exists(path):
            findings.append(Finding(
                phase="container_escape", type="container_detected",
                severity=Severity.INFO,
                description=f"Running inside container: {desc}",
                evidence=json.dumps({"indicator": path}),
                target=target,
            ))

            # Read cgroup for runtime type
            if path == "/proc/1/cgroup":
                try:
                    with open(path, "r") as f:
                        cgroup_data = f.read(1024)
                    runtime = "unknown"
                    if "docker" in cgroup_data.lower():
                        runtime = "docker"
                    elif "kubepods" in cgroup_data.lower():
                        runtime = "kubernetes"
                    elif "lxc" in cgroup_data.lower():
                        runtime = "lxc"
                    findings.append(Finding(
                        phase="container_escape", type="container_runtime",
                        severity=Severity.INFO,
                        description=f"Container runtime: {runtime}",
                        evidence=json.dumps({"runtime": runtime, "cgroup_preview": cgroup_data[:200]}),
                        target=target,
                    ))
                except Exception:
                    pass
            break

    return findings


async def _scan_docker_escape(target: str) -> list[Finding]:
    """Scan for Docker container escape vectors."""
    findings = []

    try:
        scanner = _DockerEscapeScanner()
        escape_result = scanner.scan()

        # Container info
        if escape_result.container_info.inside_container:
            findings.append(Finding(
                phase="container_escape", type="container_info",
                severity=Severity.INFO,
                description=f"Container: {escape_result.container_info.runtime.value}, "
                            f"privileged: {escape_result.container_info.privileged}, "
                            f"caps: {len(escape_result.container_info.capabilities)}",
                evidence=json.dumps(escape_result.container_info.to_dict()),
                target=target,
            ))

        # Escape vectors
        for vector in escape_result.vectors:
            severity = Severity.CRITICAL if vector.severity == "CRITICAL" else \
                       Severity.HIGH if vector.severity == "HIGH" else Severity.MEDIUM

            findings.append(Finding(
                phase="container_escape", type="escape_vector",
                severity=severity,
                description=f"Docker escape: {vector.description}",
                evidence=json.dumps(vector.to_dict()),
                target=target,
            ))

        # Docker socket
        if escape_result.docker_socket_present:
            findings.append(Finding(
                phase="container_escape", type="docker_socket",
                severity=Severity.CRITICAL,
                description="Docker socket accessible — full host container control",
                evidence=json.dumps({"api_accessible": escape_result.docker_api_accessible,
                                      "containers": len(escape_result.docker_containers)}),
                target=target,
            ))

        # Host files accessible
        if escape_result.host_files_accesssible:
            findings.append(Finding(
                phase="container_escape", type="host_files_accessible",
                severity=Severity.HIGH,
                description=f"Host files accessible via /proc/1/root: {escape_result.host_files_accesssible}",
                evidence=json.dumps({"files": escape_result.host_files_accesssible}),
                target=target,
            ))

    except Exception as e:
        logger.debug(f"docker_escape scan failed: {e}")

    return findings


async def _detect_sandbox(target: str) -> list[Finding]:
    """Detect sandbox environment and security mechanisms."""
    findings = []

    try:
        detector = _SandboxDetector()
        sandbox_result = detector.detect()

        if sandbox_result.sandbox.sandbox_type.value != "none_detected":
            findings.append(Finding(
                phase="container_escape", type="sandbox_detected",
                severity=Severity.INFO,
                description=f"Sandbox: {sandbox_result.sandbox.sandbox_type.value} "
                            f"(confidence: {sandbox_result.sandbox.confidence:.0%})",
                evidence=json.dumps(sandbox_result.sandbox.to_dict()),
                target=target,
            ))

        # LSM analysis
        if sandbox_result.lsm.enabled:
            findings.append(Finding(
                phase="container_escape", type="lsm_analysis",
                severity=Severity.INFO,
                description=f"LSM: {sandbox_result.lsm.lsm_type.value} — {sandbox_result.lsm.profile_mode}",
                evidence=json.dumps(sandbox_result.lsm.to_dict()),
                target=target,
            ))

        # Seccomp analysis
        if sandbox_result.seccomp.enabled:
            severity = Severity.INFO if sandbox_result.seccomp.mode.value == "filter" else Severity.LOW
            findings.append(Finding(
                phase="container_escape", type="seccomp_analysis",
                severity=severity,
                description=f"Seccomp: {sandbox_result.seccomp.mode.value}",
                evidence=json.dumps(sandbox_result.seccomp.to_dict()),
                target=target,
            ))

        # Namespace analysis
        if sandbox_result.namespaces.shared:
            findings.append(Finding(
                phase="container_escape", type="namespace_shared",
                severity=Severity.MEDIUM,
                description=f"Namespaces shared with host: {', '.join(sandbox_result.namespaces.shared)}",
                evidence=json.dumps(sandbox_result.namespaces.to_dict()),
                target=target,
            ))

        # Escape paths
        if sandbox_result.escape_paths:
            for path in sandbox_result.escape_paths:
                findings.append(Finding(
                    phase="container_escape", type="escape_path",
                    severity=Severity.HIGH,
                    description=f"Sandbox escape path: {path}",
                    evidence=json.dumps({"path": path}),
                    target=target,
                ))

    except Exception as e:
        logger.debug(f"sandbox detection failed: {e}")

    return findings


async def _scan_k8s_escape(target: str) -> list[Finding]:
    """Scan for Kubernetes escape vectors."""
    findings = []

    try:
        scanner = _K8sEscapeScanner()
        k8s_result = scanner.scan()

        # Service account
        if k8s_result.service_account.token_present:
            findings.append(Finding(
                phase="container_escape", type="k8s_service_account",
                severity=Severity.INFO,
                description=f"K8s SA token present in namespace: {k8s_result.service_account.namespace}",
                evidence=json.dumps(k8s_result.service_account.to_dict()),
                target=target,
            ))

        # API access
        if k8s_result.api_access.accessible:
            severity = Severity.CRITICAL if k8s_result.api_access.authenticated else Severity.HIGH
            findings.append(Finding(
                phase="container_escape", type="k8s_api_access",
                severity=severity,
                description=f"K8s API server accessible: {k8s_result.api_access.api_url} "
                            f"(auth: {k8s_result.api_access.auth_method})",
                evidence=json.dumps(k8s_result.api_access.to_dict()),
                target=target,
            ))

        # RBAC checks
        for rbac in k8s_result.rbac_checks:
            if rbac.allowed:
                findings.append(Finding(
                    phase="container_escape", type="k8s_rbac_permission",
                    severity=Severity.MEDIUM,
                    description=f"RBAC: can {rbac.verb} {rbac.resource} in {rbac.namespace or 'cluster'}",
                    evidence=json.dumps(rbac.to_dict()),
                    target=target,
                ))

        # Escalation paths
        for path in k8s_result.escalation_paths:
            severity = Severity.CRITICAL if path.risk.value == "immediate_escalation" else \
                       Severity.HIGH if path.risk.value in ("high_privilege",) else Severity.MEDIUM
            findings.append(Finding(
                phase="container_escape", type="k8s_escalation_path",
                severity=severity,
                description=f"K8s escalation: {path.description}",
                evidence=json.dumps(path.to_dict()),
                target=target,
            ))

        # Secrets
        if k8s_result.secrets:
            findings.append(Finding(
                phase="container_escape", type="k8s_secrets_accessible",
                severity=Severity.CRITICAL,
                description=f"K8s secrets accessible ({len(k8s_result.secrets)} found)",
                evidence=json.dumps({"secret_count": len(k8s_result.secrets),
                                      "namespaces": list(set(s.get("metadata", {}).get("namespace", "") for s in k8s_result.secrets))}),
                target=target,
            ))

        # Nodes
        if k8s_result.nodes_accessible:
            findings.append(Finding(
                phase="container_escape", type="k8s_nodes_accessible",
                severity=Severity.HIGH,
                description=f"K8s nodes enumerable: {len(k8s_result.nodes_accessible)} nodes",
                evidence=json.dumps({"nodes": k8s_result.nodes_accessible}),
                target=target,
            ))

        # Cloud metadata
        if k8s_result.cloud_metadata_access:
            findings.append(Finding(
                phase="container_escape", type="cloud_metadata_from_pod",
                severity=Severity.HIGH,
                description="Cloud metadata service accessible from pod — credential theft risk",
                evidence=json.dumps({"accessible": True}),
                target=target,
            ))

    except Exception as e:
        logger.debug(f"k8s_escape scan failed: {e}")

    return findings


def _assess_escape_risk(findings: list[Finding], target: str) -> list[Finding]:
    """Assess overall container escape risk."""
    risk_findings = []

    has_critical_vector = any(f.type == "escape_vector" and f.severity == Severity.CRITICAL for f in findings)
    has_high_vector = any(f.type == "escape_vector" and f.severity == Severity.HIGH for f in findings)
    has_docker_socket = any(f.type == "docker_socket" for f in findings)
    has_host_files = any(f.type == "host_files_accessible" for f in findings)
    has_k8s_api = any(f.type == "k8s_api_access" and f.severity == Severity.CRITICAL for f in findings)
    has_k8s_secrets = any(f.type == "k8s_secrets_accessible" for f in findings)
    has_k8s_escalation = any(f.type == "k8s_escalation_path" for f in findings)
    has_sandbox_escape = any(f.type == "escape_path" for f in findings)
    has_shared_ns = any(f.type == "namespace_shared" for f in findings)

    risk_score = 0.0
    factors = []

    if has_critical_vector:
        risk_score += 3.0
        factors.append("critical escape vector")
    if has_high_vector:
        risk_score += 2.0
        factors.append("high-risk escape vector")
    if has_docker_socket:
        risk_score += 3.0
        factors.append("docker socket")
    if has_host_files:
        risk_score += 2.0
        factors.append("host files accessible")
    if has_k8s_api:
        risk_score += 3.0
        factors.append("K8s API with auth")
    if has_k8s_secrets:
        risk_score += 3.0
        factors.append("K8s secrets")
    if has_k8s_escalation:
        risk_score += 2.0
        factors.append("K8s escalation path")
    if has_sandbox_escape:
        risk_score += 2.0
        factors.append("sandbox escape possible")
    if has_shared_ns:
        risk_score += 1.0
        factors.append("shared namespaces")

    if factors:
        risk_level = "CRITICAL" if risk_score >= 8.0 else "HIGH" if risk_score >= 5.0 else "MEDIUM"
        risk_findings.append(Finding(
            phase="container_escape", type="container_escape_risk",
            severity=Severity[risk_level] if risk_level in Severity.__members__ else Severity.MEDIUM,
            description=f"Container escape risk: {risk_level} ({risk_score:.1f}/10) — {', '.join(factors)}",
            evidence=json.dumps({"risk_score": risk_score, "risk_level": risk_level, "factors": factors}),
            target=target,
        ))

    return risk_findings


async def exec_container_escape_phase(target: str, findings: list[Finding]) -> PhaseResult:
    """Entry point for the container escape phase executor."""
    return await _exec_container_escape(target, findings)
