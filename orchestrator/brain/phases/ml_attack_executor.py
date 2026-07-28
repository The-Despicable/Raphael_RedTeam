"""
ML Supply Chain Attack Phase Executor (P1 - FORGE Phase 1)

Wraps the ml_attack module into the autonomous phase system.
Executes model format analysis, payload generation, HF Hub recon,
and supply chain injection planning as a standard Raphael phase.
"""

from __future__ import annotations

import os
import re
import json
import logging
import asyncio
from pathlib import Path
from typing import Optional

from orchestrator.brain.phases.models import Finding, PhaseResult, Severity

logger = logging.getLogger(__name__)

# Lazy imports
_PicklePayloadFactory = None
_ModelFormatAnalyzer = None
_HFHubAPIClient = None
_SupplyChainInjector = None


def _lazy_imports():
    global _PicklePayloadFactory, _ModelFormatAnalyzer, _HFHubAPIClient, _SupplyChainInjector
    if _PicklePayloadFactory is None:
        from orchestrator.ml_attack.pickle_payload_factory import PicklePayloadFactory as PF
        _PicklePayloadFactory = PF
    if _ModelFormatAnalyzer is None:
        from orchestrator.ml_attack.model_format_analyzer import ModelFormatAnalyzer as MFA
        _ModelFormatAnalyzer = MFA
    if _HFHubAPIClient is None:
        from orchestrator.ml_attack.hf_hub_api_client import HFHubAPIClient as HF
        _HFHubAPIClient = HF
    if _SupplyChainInjector is None:
        from orchestrator.ml_attack.supply_chain_injector import SupplyChainInjector as SCI
        _SupplyChainInjector = SCI


async def _exec_ml_attack(target: str, findings: list[Finding]) -> PhaseResult:
    """Execute ML supply chain attack phase.

    Phase actions:
    1. Analyze ML model files in target directory (format, risk, dangerous ops)
    2. If target is an HF model ID, query HF Hub API for metadata
    3. Generate attack payloads based on findings
    4. Create injection plans for high-value targets
    5. Assess overall ML supply chain risk
    """
    _lazy_imports()

    phase_start = asyncio.get_event_loop().time()
    result = PhaseResult(phase="ml_attack", success=True, summary="ML supply chain analysis started")
    ml_findings: list[Finding] = []

    try:
        target_path = Path(target)
        is_hf_model = "/" in target and not target_path.exists()

        # --- STEP 1: Format analysis (local path or HF model) ---
        if is_hf_model:
            hf_findings = await _analyze_hf_model(target, ml_findings)
            ml_findings.extend(hf_findings)
        elif target_path.is_dir():
            local_findings = await _analyze_local_models(target, ml_findings)
            ml_findings.extend(local_findings)
        elif target_path.is_file():
            file_findings = await _analyze_single_file(target, ml_findings)
            ml_findings.extend(file_findings)
        else:
            logger.warning(f"[ML_ATTACK] Target not found: {target}")

        # --- STEP 2: Payload capability assessment ---
        payload_findings = _assess_payload_capabilities(target)
        ml_findings.extend(payload_findings)

        # --- STEP 3: Supply chain risk assessment ---
        supply_chain_findings = _assess_supply_chain_risk(ml_findings, target)
        ml_findings.extend(supply_chain_findings)

        # Compile summary
        high_risk_files = len([f for f in ml_findings if f.severity == Severity.CRITICAL])
        total_files = len([f for f in ml_findings if f.type == "ml_model_file"])
        payloads_generated = len([f for f in ml_findings if f.type == "ml_payload"])

        summary_parts = [f"Files analyzed: {total_files}"]
        if high_risk_files:
            summary_parts.append(f"High-risk: {high_risk_files}")
        if payloads_generated:
            summary_parts.append(f"Payloads: {payloads_generated}")

        result.summary = f"ML attack phase — {' | '.join(summary_parts)}"
        result.success = True

    except Exception as e:
        logger.error(f"[ML_ATTACK] Phase execution failed: {e}", exc_info=True)
        result.success = False
        result.error = str(e)
        ml_findings.append(Finding(
            phase="ml_attack", type="ml_error",
            severity=Severity.LOW,
            description=f"ML attack phase error: {e}",
            target=target,
        ))

    result.findings = ml_findings
    latency = round(asyncio.get_event_loop().time() - phase_start, 2)
    result.latency = latency
    logger.info(f"[ML_ATTACK] Phase complete in {latency}s — {len(ml_findings)} findings")
    return result


async def _analyze_hf_model(model_id: str, findings: list[Finding]) -> list[Finding]:
    """Analyze a HuggingFace model via the Hub API."""
    hf_findings = []

    try:
        client = _HFHubAPIClient()
        info = client.get_model(model_id)

        hf_findings.append(Finding(
            phase="ml_attack", type="hf_model_info",
            severity=Severity.INFO,
            description=f"HF model: {info.model_id} ({info.pipeline_tag}) — {info.downloads} downloads, {info.likes} likes",
            evidence=json.dumps({
                "model_id": info.model_id,
                "pipeline_tag": info.pipeline_tag,
                "downloads": info.downloads,
                "likes": info.likes,
                "is_safetensors": info.is_safetensors,
                "has_pickle": info.has_pickle(),
            }),
            target=model_id,
        ))

        # Check for pickle (RCE risk)
        if info.has_pickle() and not info.has_safetensors():
            hf_findings.append(Finding(
                phase="ml_attack", type="ml_pickle_model",
                severity=Severity.CRITICAL,
                description=f"Model uses pickle format without safetensors — RCE risk: {info.model_id}",
                evidence=json.dumps({
                    "model_id": info.model_id,
                    "downloads": info.downloads,
                    "recommendation": "Replace pickle files with safetensors to mitigate RCE risk",
                }),
                target=model_id,
            ))

        # High download volume = high impact target
        if info.downloads > 100000 and info.has_pickle():
            hf_findings.append(Finding(
                phase="ml_attack", type="ml_high_impact_target",
                severity=Severity.CRITICAL,
                description=f"High-impact ML attack target: {info.model_id} ({info.downloads} downloads, pickle format)",
                evidence=json.dumps({"model_id": info.model_id, "downloads": info.downloads}),
                target=model_id,
            ))

    except Exception as e:
        hf_findings.append(Finding(
            phase="ml_attack", type="hf_api_error",
            severity=Severity.LOW,
            description=f"HF Hub API error for {model_id}: {e}",
            target=model_id,
        ))

    return hf_findings


async def _analyze_local_models(directory: str, findings: list[Finding]) -> list[Finding]:
    """Analyze all ML model files in a local directory."""
    local_findings = []

    try:
        analyzer = _ModelFormatAnalyzer()
        results = analyzer.analyze_directory(directory)

        for model_file in results:
            local_findings.append(Finding(
                phase="ml_attack", type="ml_model_file",
                severity=Severity[model_file.risk.value.upper()] if model_file.risk.value.upper() in Severity.__members__ else Severity.MEDIUM,
                description=f"Model file: {Path(model_file.path).name} ({model_file.format.value}) — risk: {model_file.risk.value}",
                evidence=json.dumps(model_file.to_dict()),
                target=directory,
            ))

            if model_file.has_dangerous_ops:
                local_findings.append(Finding(
                    phase="ml_attack", type="ml_dangerous_ops",
                    severity=Severity.CRITICAL,
                    description=f"Dangerous pickle opcodes in {Path(model_file.path).name}: {model_file.dangerous_ops}",
                    evidence=json.dumps({"file": model_file.path, "ops": model_file.dangerous_ops}),
                    target=directory,
                ))

            if model_file.has_custom_code:
                local_findings.append(Finding(
                    phase="ml_attack", type="ml_custom_code",
                    severity=Severity.HIGH,
                    description=f"Custom code detected in model: {Path(model_file.path).name}",
                    evidence=json.dumps({"file": model_file.path}),
                    target=directory,
                ))

    except Exception as e:
        logger.warning(f"[ML_ATTACK] Local model analysis failed: {e}")

    return local_findings


async def _analyze_single_file(file_path: str, findings: list[Finding]) -> list[Finding]:
    """Analyze a single ML model file."""
    try:
        analyzer = _ModelFormatAnalyzer()
        model_file = analyzer.analyze_file(file_path)

        return [Finding(
            phase="ml_attack", type="ml_model_file",
            severity=Severity[model_file.risk.value.upper()] if model_file.risk.value.upper() in Severity.__members__ else Severity.MEDIUM,
            description=f"Model file: {Path(model_file.path).name} ({model_file.format.value}) — risk: {model_file.risk.value}",
            evidence=json.dumps(model_file.to_dict()),
            target=file_path,
        )]
    except Exception as e:
        return [Finding(
            phase="ml_attack", type="ml_analysis_error",
            severity=Severity.LOW,
            description=f"Failed to analyze {file_path}: {e}",
            target=file_path,
        )]


def _assess_payload_capabilities(target: str) -> list[Finding]:
    """Assess available payload generation capabilities."""
    payload_findings = []

    try:
        factory = _PicklePayloadFactory(dry_run=True)
        templates = factory.list_templates()

        payload_findings.append(Finding(
            phase="ml_attack", type="ml_payload_capabilities",
            severity=Severity.INFO,
            description=f"ML payload factory ready: {len(templates)} templates available",
            evidence=json.dumps({
                "formats": ["pickle", "safetensors", "raw_python"],
                "payload_types": [t.value for t in _PicklePayloadFactory.PayloadType],
                "templates": list(templates.keys()),
            }),
            target=target,
        ))

    except Exception as e:
        logger.warning(f"[ML_ATTACK] Payload capability assessment failed: {e}")

    return payload_findings


def _assess_supply_chain_risk(findings: list[Finding], target: str) -> list[Finding]:
    """Assess overall ML supply chain risk from collected findings."""
    risk_findings = []

    has_pickle_models = any(f.type == "ml_pickle_model" for f in findings)
    has_dangerous_ops = any(f.type == "ml_dangerous_ops" for f in findings)
    has_high_impact = any(f.type == "ml_high_impact_target" for f in findings)
    has_custom_code = any(f.type == "ml_custom_code" for f in findings)
    model_count = len([f for f in findings if f.type == "ml_model_file"])

    risk_score = 0.0
    risk_factors = []

    if has_pickle_models:
        risk_score += 3.0
        risk_factors.append("pickle format models (RCE vector)")
    if has_dangerous_ops:
        risk_score += 2.0
        risk_factors.append("dangerous pickle opcodes")
    if has_high_impact:
        risk_score += 3.0
        risk_factors.append("high-download models")
    if has_custom_code:
        risk_score += 2.0
        risk_factors.append("custom code in models")
    if model_count > 10:
        risk_score += 1.0
        risk_factors.append(f"{model_count} model files")

    risk_level = "CRITICAL" if risk_score >= 8.0 else "HIGH" if risk_score >= 5.0 else "MEDIUM" if risk_score >= 2.0 else "LOW"

    if risk_factors:
        risk_findings.append(Finding(
            phase="ml_attack", type="ml_supply_chain_risk",
            severity=Severity[risk_level] if risk_level in Severity.__members__ else Severity.MEDIUM,
            description=f"ML supply chain risk: {risk_level} ({risk_score:.1f}/10) — {', '.join(risk_factors)}",
            evidence=json.dumps({
                "risk_score": risk_score,
                "risk_level": risk_level,
                "risk_factors": risk_factors,
                "model_count": model_count,
            }),
            target=target,
        ))

    return risk_findings


async def exec_ml_attack_phase(target: str, findings: list[Finding]) -> PhaseResult:
    """Entry point for the ML attack phase executor."""
    return await _exec_ml_attack(target, findings)
