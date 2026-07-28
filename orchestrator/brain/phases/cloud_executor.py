"""
Cloud API Abuse Phase Executor (P2 - FORGE Phase 2)

Wraps the cloud_abuse module into the autonomous phase system.
Executes cloud service enumeration, IAM pathfinding, metadata abuse,
and API gateway exploitation as a standard Raphael phase.
"""

from __future__ import annotations

import os
import re
import json
import logging
import asyncio
from typing import Optional

from orchestrator.brain.phases.models import Finding, PhaseResult, Severity

logger = logging.getLogger(__name__)

_CloudEnumerator = None
_IAMPathfinder = None
_MetadataAbuser = None
_APIGatewayExploiter = None


def _lazy_imports():
    global _CloudEnumerator, _IAMPathfinder, _MetadataAbuser, _APIGatewayExploiter
    if _CloudEnumerator is None:
        from orchestrator.cloud_abuse.cloud_enum import CloudEnumerator as CE
        _CloudEnumerator = CE
    if _IAMPathfinder is None:
        from orchestrator.cloud_abuse.iam_pathfinder import IAMPathfinder as IP
        _IAMPathfinder = IP
    if _MetadataAbuser is None:
        from orchestrator.cloud_abuse.metadata_abuse import MetadataAbuser as MA
        _MetadataAbuser = MA
    if _APIGatewayExploiter is None:
        from orchestrator.cloud_abuse.api_gateway_exploit import APIGatewayExploiter as AGE
        _APIGatewayExploiter = AGE


async def _exec_cloud(target: str, findings: list[Finding]) -> PhaseResult:
    """Execute cloud API abuse phase.

    Phase actions:
    1. Detect available cloud credentials in environment
    2. Enumerate cloud services (AWS/GCP/Azure)
    3. Analyze IAM for privilege escalation paths
    4. Check for metadata service accessibility (IMDS)
    5. Probe API gateway endpoints if URL provided
    6. Assess cloud attack surface
    """
    _lazy_imports()

    phase_start = asyncio.get_event_loop().time()
    result = PhaseResult(phase="cloud", success=True, summary="Cloud abuse analysis started")
    cloud_findings: list[Finding] = []

    try:
        # --- STEP 1: Detect cloud credentials ---
        cred_findings = _detect_credentials(target)
        cloud_findings.extend(cred_findings)

        # --- STEP 2: Enumerate cloud services ---
        enum_findings = await _enumerate_cloud(target)
        cloud_findings.extend(enum_findings)

        # --- STEP 3: IAM analysis (if AWS creds available) ---
        iam_findings = await _analyze_iam(target)
        cloud_findings.extend(iam_findings)

        # --- STEP 4: Metadata service check ---
        imds_findings = await _check_metadata(target)
        cloud_findings.extend(imds_findings)

        # --- STEP 5: API gateway probe (if URL target) ---
        if target.startswith(("http://", "https://")):
            gateway_findings = await _probe_gateway(target)
            cloud_findings.extend(gateway_findings)

        # --- STEP 6: Risk assessment ---
        risk_findings = _assess_cloud_risk(cloud_findings, target)
        cloud_findings.extend(risk_findings)

        # Compile summary
        services_found = len([f for f in cloud_findings if f.type == "cloud_service"])
        iam_paths = len([f for f in cloud_findings if f.type == "iam_escalation_path"])
        creds_detected = len([f for f in cloud_findings if f.type == "cloud_credential"])
        high_risk = len([f for f in cloud_findings if f.severity in (Severity.CRITICAL, Severity.HIGH)])

        summary_parts = []
        if services_found:
            summary_parts.append(f"Services: {services_found}")
        if iam_paths:
            summary_parts.append(f"IAM paths: {iam_paths}")
        if creds_detected:
            summary_parts.append(f"Creds: {creds_detected}")
        if high_risk:
            summary_parts.append(f"High-risk: {high_risk}")
        if not summary_parts:
            summary_parts.append("No cloud services detected")

        result.summary = f"Cloud phase — {' | '.join(summary_parts)}"
        result.success = bool(services_found or iam_paths or creds_detected)

    except Exception as e:
        logger.error(f"[CLOUD] Phase execution failed: {e}", exc_info=True)
        result.success = False
        result.error = str(e)
        cloud_findings.append(Finding(
            phase="cloud", type="cloud_error",
            severity=Severity.LOW,
            description=f"Cloud phase error: {e}",
            target=target,
        ))

    result.findings = cloud_findings
    latency = round(asyncio.get_event_loop().time() - phase_start, 2)
    result.latency = latency
    logger.info(f"[CLOUD] Phase complete in {latency}s — {len(cloud_findings)} findings")
    return result


def _detect_credentials(target: str) -> list[Finding]:
    """Detect cloud credentials in environment."""
    findings = []

    providers = {
        "AWS": ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_PROFILE"],
        "GCP": ["GOOGLE_APPLICATION_CREDENTIALS"],
        "Azure": ["AZURE_CLIENT_ID", "AZURE_TENANT_ID", "AZURE_CLIENT_SECRET"],
    }

    detected = []
    for provider_name, vars in providers.items():
        found_vars = [v for v in vars if os.environ.get(v)]
        if found_vars:
            detected.append(provider_name)
            findings.append(Finding(
                phase="cloud", type="cloud_credential",
                severity=Severity.HIGH,
                description=f"{provider_name} credentials detected in environment",
                evidence=json.dumps({"provider": provider_name, "vars": found_vars}),
                target=target,
            ))

    # Also check credential files
    cred_paths = [
        ("AWS", os.path.expanduser("~/.aws/credentials")),
        ("GCP", os.path.expanduser("~/.config/gcloud/application_default_credentials.json")),
        ("Azure", os.path.expanduser("~/.azure/azureProfile.json")),
    ]
    for provider_name, path in cred_paths:
        if os.path.exists(path):
            if provider_name not in detected:
                findings.append(Finding(
                    phase="cloud", type="cloud_credential",
                    severity=Severity.HIGH,
                    description=f"{provider_name} credential file found: {path}",
                    evidence=json.dumps({"provider": provider_name, "path": path}),
                    target=target,
                ))

    return findings


async def _enumerate_cloud(target: str) -> list[Finding]:
    """Enumerate cloud services."""
    findings = []

    try:
        enumerator = _CloudEnumerator()
        result = enumerator.enumerate_all()

        for service in result.services:
            if service.accessible:
                severity = Severity.CRITICAL if service.public else Severity.MEDIUM
                findings.append(Finding(
                    phase="cloud", type="cloud_service",
                    severity=severity,
                    description=f"Cloud service: {service.name} ({service.provider.value})",
                    evidence=json.dumps(service.to_dict()),
                    target=target,
                ))

        if result.credentials_found:
            findings.append(Finding(
                phase="cloud", type="cloud_credentials_available",
                severity=Severity.INFO,
                description=f"Cloud credentials available: {', '.join(result.credentials_found)}",
                evidence=json.dumps({"credentials": result.credentials_found}),
                target=target,
            ))

    except Exception as e:
        logger.warning(f"[CLOUD] Enumeration failed: {e}")

    return findings


async def _analyze_iam(target: str) -> list[Finding]:
    """Analyze IAM for privilege escalation paths."""
    findings = []

    try:
        pathfinder = _IAMPathfinder()
        result = pathfinder.analyze_aws()

        for path in result.escalation_paths:
            severity = Severity.CRITICAL if path.risk == "CRITICAL" else Severity.HIGH if path.risk == "HIGH" else Severity.MEDIUM
            findings.append(Finding(
                phase="cloud", type="iam_escalation_path",
                severity=severity,
                description=f"IAM escalation: {path.technique.value} from {path.source}",
                evidence=json.dumps(path.to_dict()),
                target=target,
            ))

        for role in result.high_risk_roles:
            findings.append(Finding(
                phase="cloud", type="iam_high_risk_role",
                severity=Severity.CRITICAL,
                description=f"High-risk IAM role: {role.name} (risk: {role.risk_score}/10)",
                evidence=json.dumps(role.to_dict()),
                target=target,
            ))

    except Exception as e:
        logger.debug(f"[CLOUD] IAM analysis failed: {e}")

    return findings


async def _check_metadata(target: str) -> list[Finding]:
    """Check for accessible cloud metadata services."""
    findings = []

    try:
        abuser = _MetadataAbuser()
        result = abuser.abuse_all()

        for resp in result.responses:
            if resp.success:
                findings.append(Finding(
                    phase="cloud", type="imds_accessible",
                    severity=Severity.CRITICAL,
                    description=f"Metadata service accessible: {resp.provider.value} ({resp.imds_version})",
                    evidence=json.dumps(resp.to_dict()),
                    target=target,
                ))

        for cred in result.credentials_extracted:
            findings.append(Finding(
                phase="cloud", type="imds_credentials",
                severity=Severity.CRITICAL,
                description=f"Cloud credentials extracted from IMDS: {cred.get('provider', 'unknown')}/{cred.get('type', 'unknown')}",
                evidence=json.dumps(cred),
                target=target,
            ))

    except Exception as e:
        logger.debug(f"[CLOUD] Metadata check failed: {e}")

    return findings


async def _probe_gateway(target: str) -> list[Finding]:
    """Probe API gateway endpoints."""
    findings = []

    try:
        exploiter = _APIGatewayExploiter()
        result = exploiter.enumerate_gateway(target)

        for ep in result.endpoints:
            severity = Severity.CRITICAL if ep.vulnerable else Severity.MEDIUM if ep.accessible else Severity.INFO
            findings.append(Finding(
                phase="cloud", type="api_gateway_endpoint",
                severity=severity,
                description=f"API endpoint: {ep.url} ({ep.status_code})",
                evidence=json.dumps(ep.to_dict()),
                target=target,
            ))

        if result.api_keys_found:
            findings.append(Finding(
                phase="cloud", type="api_key_found",
                severity=Severity.CRITICAL,
                description=f"API keys found in environment: {len(result.api_keys_found)}",
                evidence=json.dumps({"api_keys": result.api_keys_found}),
                target=target,
            ))

    except Exception as e:
        logger.debug(f"[CLOUD] Gateway probe failed: {e}")

    return findings


def _assess_cloud_risk(findings: list[Finding], target: str) -> list[Finding]:
    """Assess overall cloud attack surface."""
    risk_findings = []

    has_creds = any(f.type == "cloud_credential" for f in findings)
    has_services = any(f.type == "cloud_service" for f in findings)
    has_iam_paths = any(f.type == "iam_escalation_path" for f in findings)
    has_imds = any(f.type == "imds_accessible" for f in findings)
    has_vulnerable_gateway = any(f.type == "api_gateway_endpoint" and f.severity == Severity.CRITICAL for f in findings)

    risk_score = 0.0
    factors = []

    if has_creds:
        risk_score += 2.0
        factors.append("cloud credentials available")
    if has_services:
        risk_score += 2.0
        factors.append("cloud services enumerated")
    if has_iam_paths:
        risk_score += 3.0
        factors.append("IAM escalation paths found")
    if has_imds:
        risk_score += 3.0
        factors.append("metadata service accessible")
    if has_vulnerable_gateway:
        risk_score += 2.0
        factors.append("vulnerable API gateway")

    if factors:
        risk_level = "CRITICAL" if risk_score >= 8.0 else "HIGH" if risk_score >= 5.0 else "MEDIUM"
        risk_findings.append(Finding(
            phase="cloud", type="cloud_attack_surface",
            severity=Severity[risk_level] if risk_level in Severity.__members__ else Severity.MEDIUM,
            description=f"Cloud attack surface: {risk_level} ({risk_score:.1f}/10) — {', '.join(factors)}",
            evidence=json.dumps({"risk_score": risk_score, "risk_level": risk_level, "factors": factors}),
            target=target,
        ))

    return risk_findings


async def exec_cloud_phase(target: str, findings: list[Finding]) -> PhaseResult:
    """Entry point for the cloud abuse phase executor."""
    return await _exec_cloud(target, findings)
