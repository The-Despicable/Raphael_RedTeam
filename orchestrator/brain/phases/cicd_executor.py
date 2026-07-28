"""
CI/CD Pipeline Phase Executor (P0 - FORGE Phase 0)

Wraps the CI/CD module into the autonomous phase system.
Executes workflow parsing, runner fingerprinting, token harvesting,
and pipeline poisoning as a standard Raphael phase.

Integrates with:
- orchestrator.cicd.workflow_parser
- orchestrator.cicd.runner_fingerprinter
- orchestrator.cicd.token_harvester
- orchestrator.cicd.pipeline_poisoner
"""

from __future__ import annotations

import os
import re
import json
import asyncio
import logging
import tempfile
from pathlib import Path
from typing import Optional, Any
from urllib.parse import urlparse

from orchestrator.brain.phases.models import Finding, PhaseResult, Severity

logger = logging.getLogger(__name__)

# Lazy imports to avoid circular deps at module level
_WorkflowParser = None
_RunnerFingerprinter = None
_TokenHarvester = None
_PipelinePoisoner = None


def _lazy_imports():
    global _WorkflowParser, _RunnerFingerprinter, _TokenHarvester, _PipelinePoisoner
    if _WorkflowParser is None:
        from orchestrator.cicd.workflow_parser import WorkflowParser as WP
        _WorkflowParser = WP
    if _RunnerFingerprinter is None:
        from orchestrator.cicd.runner_fingerprinter import RunnerFingerprinter as RF
        _RunnerFingerprinter = RF
    if _TokenHarvester is None:
        from orchestrator.cicd.token_harvester import TokenHarvester as TH
        _TokenHarvester = TH
    if _PipelinePoisoner is None:
        from orchestrator.cicd.pipeline_poisoner import PipelinePoisoner as PP
        _PipelinePoisoner = PP


def _resolve_repo_path(target: str) -> tuple[str, str]:
    """Resolve target to a local repo path and a display name.

    Handles:
    - Local filesystem paths
    - GitHub repo URLs (gh:owner/repo, https://github.com/owner/repo)
    - GitLab repo URLs
    - Raw repo names (tries to clone)
    """
    # Already a local path
    if os.path.isdir(target):
        return target, target

    # GitHub shorthand
    gh_match = re.match(r'^(?:gh:)?([\w.-]+/[\w.-]+)$', target)
    if gh_match:
        repo = gh_match.group(1)
        clone_path = os.path.join(tempfile.gettempdir(), 'raphael_cicd', repo.replace('/', '__'))
        return clone_path, f"github.com/{repo}"

    # Full GitHub URL
    gh_url_match = re.match(r'https?://github\.com/([\w.-]+/[\w.-]+?)(?:\.git)?$', target)
    if gh_url_match:
        repo = gh_url_match.group(1)
        clone_path = os.path.join(tempfile.gettempdir(), 'raphael_cicd', repo.replace('/', '__'))
        return clone_path, f"github.com/{repo}"

    # It's a URL but not recognized — return as-is for API-based scanning
    if target.startswith(('http://', 'https://')):
        return target, target

    # Fallback: treat as local path
    return target, target


async def _exec_cicd(target: str, findings: list[Finding]) -> PhaseResult:
    """Execute CI/CD pipeline analysis phase.

    Phase actions:
    1. Resolve target (local path or clone repo URL)
    2. Parse all CI/CD workflows (GitHub Actions, GitLab CI, Azure Pipelines)
    3. Fingerprint runners (label analysis, env detection)
    4. Harvest tokens (env vars, OIDC, metadata services)
    5. Assess attack surface and generate findings
    6. Optionally generate poison payloads (dry-run only)
    """
    _lazy_imports()

    phase_start = asyncio.get_event_loop().time()
    result = PhaseResult(phase="cicd", success=True, summary="CI/CD pipeline analysis started")
    cicd_findings: list[Finding] = []
    repo_name = target

    try:
        repo_path, display_name = _resolve_repo_path(target)
        repo_name = display_name

        # --- STEP 1: Discover and parse workflows ---
        logger.info(f"[CICD] Parsing workflows in: {repo_path}")
        workflow_findings, workflow_count, job_count, self_hosted_count = (
            await _parse_workflows(repo_path, repo_name)
        )
        cicd_findings.extend(workflow_findings)

        # --- STEP 2: Detect CI provider from environment (if running in CI) ---
        ci_provider = None
        if os.environ.get("GITHUB_ACTIONS"):
            ci_provider = "github_actions"
        elif os.environ.get("GITLAB_CI"):
            ci_provider = "gitlab_ci"
        elif os.environ.get("TF_BUILD"):
            ci_provider = "azure_pipelines"

        # --- STEP 3: Fingerprint environment (if running inside CI) ---
        runner_findings = await _fingerprint_environment(repo_name)
        cicd_findings.extend(runner_findings)

        # --- STEP 4: Harvest tokens from environment ---
        token_findings = await _harvest_tokens(repo_name)
        cicd_findings.extend(token_findings)

        # --- STEP 5: Assess attack surface ---
        surface_findings = _assess_attack_surface(
            repo_name, workflow_count, job_count,
            self_hosted_count, runner_findings, token_findings
        )
        cicd_findings.extend(surface_findings)

        # --- Compile summary ---
        token_count = len([f for f in cicd_findings if f.type == "cicd_token"])
        secret_count = len([f for f in cicd_findings if f.type == "cicd_secret"])
        self_hosted_jobs = len([f for f in cicd_findings if f.type == "self_hosted_runner"])

        summary_parts = [
            f"Workflows: {workflow_count}",
            f"Jobs: {job_count}",
        ]
        if self_hosted_jobs:
            summary_parts.append(f"Self-hosted: {self_hosted_jobs}")
        if token_count:
            summary_parts.append(f"Tokens: {token_count}")
        if secret_count:
            summary_parts.append(f"Secrets: {secret_count}")

        result.summary = f"CI/CD phase — {' | '.join(summary_parts)}"
        if token_count or secret_count or self_hosted_jobs:
            result.success = True
        else:
            result.summary += " | No high-value targets found"

    except Exception as e:
        logger.error(f"[CICD] Phase execution failed: {e}", exc_info=True)
        result.success = False
        result.error = str(e)
        cicd_findings.append(Finding(
            phase="cicd", type="cicd_error",
            severity=Severity.LOW,
            description=f"CI/CD phase execution error: {e}",
            target=repo_name,
        ))

    result.findings = cicd_findings
    latency = round(asyncio.get_event_loop().time() - phase_start, 2)
    result.latency = latency
    logger.info(f"[CICD] Phase complete in {latency}s — {len(cicd_findings)} findings")
    return result


async def _parse_workflows(repo_path: str, repo_name: str) -> tuple[list[Finding], int, int, int]:
    """Parse workflow files and generate findings."""
    _lazy_imports()
    findings: list[Finding] = []
    workflow_count = 0
    job_count = 0
    self_hosted_count = 0

    # Check if path exists locally
    local_path = Path(repo_path)
    if not local_path.exists():
        # Try GitHub API-based discovery
        api_findings = await _discover_via_api(repo_name, findings)
        return api_findings, 0, 0, 0

    parser = _WorkflowParser(str(local_path))
    workflows = parser.parse_all()
    workflow_count = len(workflows)

    for wf in workflows:
        # Add workflow-level finding
        findings.append(Finding(
            phase="cicd", type="cicd_workflow",
            severity=Severity.INFO,
            description=f"CI/CD workflow: {wf.name or wf.path} ({wf.provider.value})",
            evidence=json.dumps({
                "path": wf.path,
                "provider": wf.provider.value,
                "triggers": [t.value for t in wf.get_trigger_types()],
                "job_count": len(wf.jobs),
            }),
            target=repo_name,
        ))

        for job_id, job in wf.jobs.items():
            job_count += 1

            # Self-hosted runner finding
            if job.is_self_hosted():
                self_hosted_count += 1
                findings.append(Finding(
                    phase="cicd", type="self_hosted_runner",
                    severity=Severity.HIGH,
                    description=f"Self-hosted runner: {job_id} in {wf.path}",
                    evidence=json.dumps({
                        "workflow": wf.path,
                        "job": job_id,
                        "labels": job.runs_on_labels,
                    }),
                    target=repo_name,
                ))

            # Token extraction
            tokens = job.extracts_tokens()
            for token in tokens:
                findings.append(Finding(
                    phase="cicd", type="cicd_token",
                    severity=Severity.CRITICAL,
                    description=f"CI/CD token reference: {token} in {job_id}",
                    evidence=json.dumps({
                        "workflow": wf.path,
                        "job": job_id,
                        "token_name": token,
                    }),
                    target=repo_name,
                ))

            # Secrets
            secrets = job.extracts_secrets()
            for secret in secrets:
                if secret not in tokens:  # Avoid duplicating token references
                    findings.append(Finding(
                        phase="cicd", type="cicd_secret",
                        severity=Severity.MEDIUM,
                        description=f"Secret reference: {secret} in {job_id}",
                        evidence=json.dumps({
                            "workflow": wf.path,
                            "job": job_id,
                            "secret_name": secret,
                        }),
                        target=repo_name,
                    ))

            # Actions used
            actions = job.get_actions_used()
            if actions:
                findings.append(Finding(
                    phase="cicd", type="cicd_action",
                    severity=Severity.INFO,
                    description=f"Actions in {job_id}: {', '.join(actions[:5])}",
                    evidence=json.dumps({"workflow": wf.path, "job": job_id, "actions": actions}),
                    target=repo_name,
                ))

    return findings, workflow_count, job_count, self_hosted_count


async def _discover_via_api(repo_identifier: str, findings: list[Finding]) -> list[Finding]:
    """Attempt to discover CI/CD config via GitHub/GitLab API."""
    import urllib.request
    import urllib.error

    # Try common CI/CD config paths via raw.githubusercontent.com
    gh_match = re.match(r'github\.com/([\w.-]+/[\w.-]+)', repo_identifier)
    if not gh_match:
        return findings

    repo_path = gh_match.group(1)
    common_paths = [
        f".github/workflows/main.yml",
        f".github/workflows/ci.yml",
        f".gitlab-ci.yml",
        f"azure-pipelines.yml",
    ]

    for ci_path in common_paths:
        url = f"https://raw.githubusercontent.com/{repo_path}/main/{ci_path}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Raphael-CICD/1.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status == 200:
                    findings.append(Finding(
                        phase="cicd", type="cicd_remote_workflow",
                        severity=Severity.INFO,
                        description=f"Remote CI/CD config found: {ci_path}",
                        evidence=json.dumps({"url": url, "path": ci_path}),
                        target=repo_identifier,
                    ))
        except (urllib.error.HTTPError, urllib.error.URLError, OSError):
            continue

    return findings


async def _fingerprint_environment(repo_name: str) -> list[Finding]:
    """Fingerprint the current environment for CI/CD context."""
    _lazy_imports()
    findings: list[Finding] = []

    # Only fingerprint if we're in a CI environment
    if not (os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS") or
            os.environ.get("GITLAB_CI") or os.environ.get("TF_BUILD")):
        return findings

    try:
        fingerprinter = _RunnerFingerprinter()
        result = fingerprinter.fingerprint_local()
        info = result.runner_info

        if info.ci_provider:
            findings.append(Finding(
                phase="cicd", type="ci_provider_detected",
                severity=Severity.INFO,
                description=f"Running in CI: {info.ci_provider}",
                evidence=json.dumps({
                    "provider": info.ci_provider,
                    "runner_version": info.runner_version,
                    "platform": info.platform.value,
                }),
                target=repo_name,
            ))

        # Self-hosted runner detection
        if info.is_self_hosted():
            findings.append(Finding(
                phase="cicd", type="self_hosted_runner_active",
                severity=Severity.CRITICAL,
                description="Running on a self-hosted CI runner — higher attack value",
                evidence=json.dumps(info.to_dict()),
                target=repo_name,
            ))

        # Container detection
        if info.is_container:
            findings.append(Finding(
                phase="cicd", type="containerized_runner",
                severity=Severity.MEDIUM,
                description="Runner is containerized — container escape surface",
                evidence=json.dumps({"container": True, "docker_version": info.docker_version}),
                target=repo_name,
            ))

        # Attack surface assessment
        if result.attack_surface.get("has_docker_socket"):
            findings.append(Finding(
                phase="cicd", type="docker_socket_exposed",
                severity=Severity.CRITICAL,
                description="Docker socket exposed on runner — container escape possible",
                evidence="",
                target=repo_name,
            ))

        if result.attack_surface.get("has_metadata_service"):
            findings.append(Finding(
                phase="cicd", type="cloud_metadata_accessible",
                severity=Severity.CRITICAL,
                description="Cloud metadata service accessible from runner",
                evidence=json.dumps({"services": result.detected_services}),
                target=repo_name,
            ))

        # Cloud CLI tools
        for tool_name in ["has_aws_cli", "has_gcloud_cli", "has_azure_cli"]:
            if getattr(info, tool_name, False):
                cloud_name = tool_name.replace("has_", "").replace("_cli", "").upper()
                findings.append(Finding(
                    phase="cicd", type="cloud_cli_available",
                    severity=Severity.HIGH,
                    description=f"{cloud_name} CLI available on runner",
                    evidence="",
                    target=repo_name,
                ))

        if result.detected_credentials:
            findings.append(Finding(
                phase="cicd", type="runner_credentials",
                severity=Severity.CRITICAL,
                description=f"Credential files found on runner: {', '.join(result.detected_credentials)}",
                evidence=json.dumps({"credentials": result.detected_credentials}),
                target=repo_name,
            ))

        # Generate runner profile finding
        findings.append(Finding(
            phase="cicd", type="runner_profile",
            severity=Severity.INFO,
            description=f"Runner profile — {info.platform.value}/{info.architecture.value}, "
                        f"risk score: {result.risk_score}/10",
            evidence=json.dumps({
                "risk_score": result.risk_score,
                "attack_surface": result.attack_surface,
                "cpu_count": info.cpu_count,
                "memory_mb": info.total_memory_mb,
                "has_gpu": info.has_nvidia_gpu,
            }),
            target=repo_name,
        ))

    except Exception as e:
        logger.warning(f"[CICD] Environment fingerprinting failed: {e}")

    return findings


async def _harvest_tokens(repo_name: str) -> list[Finding]:
    """Harvest tokens from environment and OIDC endpoints."""
    _lazy_imports()
    findings: list[Finding] = []

    try:
        harvester = _TokenHarvester()
        result = harvester.harvest_all()

        for token in result.tokens:
            severity_map = {
                "critical": Severity.CRITICAL,
                "high": Severity.HIGH,
                "medium": Severity.MEDIUM,
                "low": Severity.LOW,
            }
            findings.append(Finding(
                phase="cicd", type="cicd_token_harvested",
                severity=severity_map.get(token.risk.value, Severity.MEDIUM),
                description=f"Harvested token: {token.name} ({token.provider.value}/{token.scope.value})",
                evidence=json.dumps({
                    "name": token.name,
                    "provider": token.provider.value,
                    "scope": token.scope.value,
                    "risk": token.risk.value,
                    "source": token.source,
                    "is_oidc": token.is_oidc,
                    "masked_value": token.masked_value(),
                }),
                target=repo_name,
            ))

        # OIDC endpoint availability
        for ep in result.oidc_endpoints:
            if ep.get("success"):
                findings.append(Finding(
                    phase="cicd", type="oidc_endpoint_accessible",
                    severity=Severity.CRITICAL,
                    description=f"OIDC token endpoint accessible: {ep['provider']}",
                    evidence=json.dumps(ep),
                    target=repo_name,
                ))

        # Metadata service findings
        for ep in result.metadata_endpoints:
            if ep.get("success"):
                findings.append(Finding(
                    phase="cicd", type="metadata_service_accessible",
                    severity=Severity.CRITICAL,
                    description=f"Cloud metadata service accessible: {ep['provider']}",
                    evidence=json.dumps(ep),
                    target=repo_name,
                ))

    except Exception as e:
        logger.warning(f"[CICD] Token harvest failed: {e}")

    return findings


def _assess_attack_surface(
    repo_name: str,
    workflow_count: int,
    job_count: int,
    self_hosted_count: int,
    runner_findings: list[Finding],
    token_findings: list[Finding],
) -> list[Finding]:
    """Assess overall CI/CD attack surface and generate strategic findings."""
    findings: list[Finding] = []

    # Determine high-value signals
    has_self_hosted = self_hosted_count > 0
    has_tokens = any(f.type == "cicd_token" for f in token_findings)
    has_oidc = any(f.type == "oidc_endpoint_accessible" for f in runner_findings)
    has_metadata = any(f.type == "cloud_metadata_accessible" for f in runner_findings)
    has_creds = any(f.type == "runner_credentials" for f in runner_findings)
    has_docker = any(f.type == "docker_socket_exposed" for f in runner_findings)

    # Risk scoring
    risk_score = 0.0
    risk_factors = []

    if has_self_hosted:
        risk_score += 3.0
        risk_factors.append("self-hosted runners")
    if has_tokens:
        risk_score += 2.0
        risk_factors.append("CI/CD tokens exposed")
    if has_oidc:
        risk_score += 2.0
        risk_factors.append("OIDC accessible")
    if has_metadata:
        risk_score += 2.0
        risk_factors.append("cloud metadata accessible")
    if has_creds:
        risk_score += 2.0
        risk_factors.append("runner credentials exposed")
    if has_docker:
        risk_score += 1.5
        risk_factors.append("Docker socket exposed")
    if workflow_count > 5:
        risk_score += 1.0
        risk_factors.append(f"{workflow_count} workflows")
    if job_count > 10:
        risk_score += 0.5
        risk_factors.append(f"{job_count} jobs")

    risk_level = "CRITICAL" if risk_score >= 8.0 else "HIGH" if risk_score >= 5.0 else "MEDIUM" if risk_score >= 2.0 else "LOW"

    if risk_factors:
        findings.append(Finding(
            phase="cicd", type="cicd_attack_surface",
            severity=Severity[risk_level] if risk_level in Severity.__members__ else Severity.MEDIUM,
            description=f"CI/CD attack surface: {risk_level} ({risk_score:.1f}/10) — {', '.join(risk_factors)}",
            evidence=json.dumps({
                "risk_score": risk_score,
                "risk_level": risk_level,
                "risk_factors": risk_factors,
                "workflow_count": workflow_count,
                "job_count": job_count,
                "self_hosted_count": self_hosted_count,
            }),
            target=repo_name,
        ))

    return findings


async def exec_cicd_phase(target: str, findings: list[Finding]) -> PhaseResult:
    """Entry point for the CI/CD phase executor.

    Called by PHASE_EXECUTORS dispatch in autonomous.py
    """
    return await _exec_cicd(target, findings)
