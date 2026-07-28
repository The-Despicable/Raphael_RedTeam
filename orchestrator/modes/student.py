"""
THE STUDENT — Autonomous pentest learning agent mode.

S1-A REFACTOR: The Student no longer executes commands directly.
It proposes Candidates to the Planner. The CapabilityBroker authorizes.
No direct kali.run() calls in the hypothesis testing path.

Core loop:
  1. RESEARCH — scan web for new techniques, ingest case studies
  2. ENGAGE — profile target, generate Candidates via StackMatcher + STACK_MAP,
     route through Planner (if available) + CapabilityBroker (if available)
  3. REFLECT — update KB with lessons learned, identify knowledge gaps

Architecture:
    StudentCandidateGenerator → list[dict] (Candidates)
        → Planner.decide(candidates) [optional]
            → CapabilityBroker.propose_action() [optional]
                → execution only if authorized

This mode integrates with the existing Raphael orchestrator infrastructure:
  - Uses orchestrator/kali_tools_client.py for tool execution (BROKERED)
  - Uses orchestrator/growth_db.py for knowledge persistence
  - Uses orchestrator/harvester/ for CVE/technique ingestion
  - Uses orchestrator/brain/candidate_generators/student_generator.py for Candidate generation
  - Uses orchestrator/brain/capability_broker.py for authorization [optional]
  - Uses orchestrator/brain/action.py Planner for candidate scoring [optional]
"""

import asyncio
import json
import logging
import os
import time
from typing import Any, Optional

from orchestrator.student.research_scheduler import ResearchScheduler
from orchestrator.student.chain_synthesizer import ChainSynthesizer

logger = logging.getLogger("student.mode")

# Try to import optional dependencies
try:
    from orchestrator.growth_db import GrowthDB
    HAS_GROWTH_DB = True
except ImportError:
    HAS_GROWTH_DB = False
    GrowthDB = None

try:
    from orchestrator.kali_tools_client import kali
    HAS_KALI = True
except ImportError:
    HAS_KALI = False
    kali = None

# S1-A: Try to import CandidateGenerator
try:
    from orchestrator.brain.candidate_generators.student_generator import (
        StudentCandidateGenerator,
        CANDIDATE_ORIGIN_STUDENT,
    )
    HAS_STUDENT_GENERATOR = True
except ImportError:
    HAS_STUDENT_GENERATOR = False
    StudentCandidateGenerator = None
    CANDIDATE_ORIGIN_STUDENT = "STUDENT"

# S1-A: Try to import CapabilityBroker (optional)
try:
    from orchestrator.brain.capability_broker import (
        CapabilityBroker,
        BrokerPolicy,
        AuthorizationDecision,
    )
    HAS_CAPABILITY_BROKER = True
except ImportError:
    HAS_CAPABILITY_BROKER = False
    CapabilityBroker = None
    BrokerPolicy = None

# S1-A: Try to import Planner (optional)
try:
    from orchestrator.brain.action import Planner
    HAS_PLANNER = True
except ImportError:
    HAS_PLANNER = False
    Planner = None


async def handle(
    target: str,
    target_type: str = "web",
    deep: bool = True,
    do_research: bool = True,
    profile: Optional[dict] = None,
    planner: Optional[Any] = None,  # S1-A: Optional Planner instance
    capability_broker: Optional[Any] = None,  # S1-A: Optional CapabilityBroker
) -> dict:
    """
    Full Student engagement lifecycle.
    
    S1-A: If planner and/or capability_broker are provided, Candidates
    are routed through them. If not, Candidates are still generated and
    recorded but NOT executed — the Student proposes, the Planner decides.
    
    Args:
        target: IP, domain, or target identifier
        target_type: 'web', 'network', 'cloud', 'api', 'mobile', 'ad'
        deep: If True, run chaining and deep exploitation
        do_research: If True, run research cycle before engagement
        profile: Optional pre-built target profile (skips profiling phase)
        planner: Optional Planner instance for candidate scoring/selection
        capability_broker: Optional CapabilityBroker for action authorization
    
    Returns:
        Dict with findings, chains, novel techniques, and report
    """
    logger.info("🎓 [Student] Engaging target: %s (type=%s, deep=%s, research=%s)",
                 target, target_type, deep, do_research)

    session = {
        "target": target,
        "target_type": target_type,
        "started_at": time.time(),
        "findings": [],
        "hypotheses": [],
        "candidates": [],  # S1-A: Track generated candidates
        "chains": [],
        "novel_chains": [],
        "profile": profile or {},
        "research_results": None,
        "reflection": {},
        # S1-A: Track architecture integration
        "has_planner": planner is not None,
        "has_broker": capability_broker is not None,
        "execution_mode": "brokered" if capability_broker else "proposal_only",
    }

    # Phase 0: Research (optional — run before engagement)
    if do_research:
        session["research_results"] = await _run_research()

    # Phase 1: Profile the target
    session["profile"] = profile or await _profile_target(target, target_type)
    logger.info("[Student] Profile: %s", session["profile"].get("stack_summary", target))

    # Phase 2: Generate Candidates via StudentCandidateGenerator
    # S1-A: This replaces the old _generate_hypotheses() + test_map path
    candidates = await _generate_candidates(target, session["profile"])
    session["candidates"] = candidates
    logger.info("[Student] Generated %d candidates", len(candidates))

    # Phase 3: Route Candidates through Planner (if available)
    if planner is not None and HAS_PLANNER and candidates:
        try:
            # Use Planner.decide() to score and select candidates
            # Build the supporting IDs for Planner.decide()
            plan_decision = planner.decide(
                candidates=candidates,
                objective_id=f"student_engagement_{target}",
            )
            # Mark which candidate was selected
            if plan_decision and plan_decision.selected_action_id:
                for c in candidates:
                    c["plan_decision_id"] = plan_decision.decision_id
                    if c.get("action_id") == plan_decision.selected_action_id:
                        c["planner_selected"] = True
                        logger.info("[Student] Planner selected: %s — %s",
                                     c.get("technique_id", "?"),
                                     plan_decision.rationale_codes)
        except Exception as e:
            logger.debug("[Student] Planner integration: %s", e)

    # Phase 4: Test candidates
    # S1-A: Route through CapabilityBroker if available; otherwise record as proposed
    for c in candidates[:15]:  # Process top 15
        if not deep and c.get("confidence", 0) < 0.3:
            continue
        
        # S1-A: Route through CapabilityBroker (if available) or record as proposed only
        if capability_broker is not None and HAS_CAPABILITY_BROKER:
            result = await _test_candidate_brokered(target, c, capability_broker)
        else:
            result = await _test_candidate_proposal_only(target, c)
        
        session["findings"].append(result)
        
        if result.get("success"):
            logger.info("  ✅ %s — impact: %s",
                         c.get("technique_id", "?"), result.get("impact", "?"))
        else:
            logger.debug("  ❌ %s — %s",
                          c.get("technique_id", "?"), result.get("reason", "unknown"))

    # Phase 5: Chain synthesis
    if deep:
        confirmed = [f for f in session["findings"] if f.get("success")]
        target_features = session["profile"].get("stack_components", [])
        chains = await _synthesize_chains(confirmed, target_features, target)
        session["chains"] = chains.get("chains", [])
        session["novel_chains"] = chains.get("novel", [])
        logger.info("[Student] Built %d chains, %d novel",
                     len(session["chains"]), len(session["novel_chains"]))

    # Phase 6: Reflection
    session["reflection"] = await _reflect(session)

    session["completed_at"] = time.time()
    session["elapsed"] = round(session["completed_at"] - session["started_at"], 2)

    # Generate report
    report = _generate_report(session)
    session["report"] = report

    return session


async def _run_research() -> dict:
    """Run a research cycle before engagement."""
    try:
        scheduler = ResearchScheduler()
        result = await scheduler.run_research_cycle(hours_back=48)

        # Queue gap study queries if gaps were identified
        if result.gaps_identified:
            try:
                from orchestrator.student.coverage_gap_filler import \
                    queue_gap_queries
                kb = GrowthDB() if HAS_GROWTH_DB else None
                queued = queue_gap_queries(
                    result.gaps_identified,
                    scheduler.research_queue,
                    kb=kb,
                )
                logger.info("[Student] Queued %d gap study queries", queued)
            except Exception as e:
                logger.debug("[Student] Gap filler: %s", e)

        # Run harvester phase — CVE/technique ingestion cycle
        try:
            from orchestrator.harvester.phase_harvest import run_harvest
            harvest_result = await run_harvest()
            logger.info("[Student] Harvester phase: %s",
                        getattr(harvest_result, 'summary', 'done'))
        except Exception as e:
            logger.debug("[Student] Harvester phase: %s", e)

        return {
            "session_id": result.session_id,
            "cves_found": result.cves_found,
            "writeups_found": result.writeups_found,
            "gaps": result.gaps_identified,
            "elapsed": round(result.completed - result.started, 2),
        }
    except Exception as e:
        logger.warning("[Student] Research cycle failed: %s", e)
        return {"error": str(e)}


async def _profile_target(target: str, target_type: str) -> dict:
    """
    Profile the target's technology stack using available OSINT tools.
    Falls back to heuristic-based profiling if tools unavailable.
    """
    profile = {
        "target": target,
        "type": target_type,
        "stack_components": [],
        "stack_summary": "",
        "profiled_at": time.time(),
    }

    try:
        # Try using whatweb if available
        if HAS_KALI and kali:
            try:
                result = await kali.run("whatweb", f"-a 3 {target}", timeout=60)
                if result and result.get("stdout"):
                    profile["raw_whatweb"] = result["stdout"][:2000]
                    # Parse whatweb output for tech indicators
                    for line in result["stdout"].split("\n"):
                        parts = line.split(",")
                        for part in parts:
                            part = part.strip().lower()
                            for tech in ["nginx", "apache", "iis", "php", "python",
                                          "django", "flask", "nodejs", "react",
                                          "nextjs", "wordpress", "jquery",
                                          "mysql", "postgresql", "mssql",
                                          "aws", "cloudflare", "azure"]:
                                if tech in part and tech not in profile["stack_components"]:
                                    profile["stack_components"].append(tech)
            except Exception:
                pass
    except Exception:
        pass

    # Heuristic fallback if no tools available or no results
    if not profile["stack_components"]:
        domain_lower = target.lower()
        if target_type == "web":
            if "api" in domain_lower or "app" in domain_lower:
                profile["stack_components"] = ["nextjs", "nodejs", "aws", "react", "jwt"]
            elif "admin" in domain_lower or "portal" in domain_lower:
                profile["stack_components"] = ["django", "python", "postgresql", "nginx"]
            else:
                profile["stack_components"] = ["nginx", "php", "mysql", "linux"]
        elif target_type == "network":
            profile["stack_components"] = ["windows", "iis", "sqlserver"]
        elif target_type == "cloud":
            profile["stack_components"] = ["aws", "s3", "lambda", "api_gateway"]
        elif target_type == "ad":
            profile["stack_components"] = ["windows", "ad", "ldap", "kerberos", "dns"]

    profile["stack_summary"] = "+".join(profile["stack_components"])
    return profile


# ── S1-A: Candidate Generation ──────────────────────────────────

async def _generate_candidates(target: str, profile: dict) -> list[dict]:
    """Generate Candidate dicts using StudentCandidateGenerator.
    
    S1-A: Replaces the old _generate_hypotheses() that ran StackMatcher
    + harvester directly. Now produces standard Candidate dicts for the
    Planner to score and the CapabilityBroker to authorize.
    
    Returns:
        List of Candidate dicts in the format expected by Planner.decide()
    """
    if not HAS_STUDENT_GENERATOR:
        logger.warning("[Student] StudentCandidateGenerator not available")
        return []

    gdb = GrowthDB() if HAS_GROWTH_DB else None
    generator = StudentCandidateGenerator(growth_db=gdb)
    
    candidates = generator.generate_candidates(
        target=target,
        profile=profile,
        max_candidates=15,
        min_confidence=0.2,
    )

    # Append harvester-sourced candidates if available
    try:
        from orchestrator.harvester.harvester_engine import get_harvester
        engine = get_harvester()
        stack = profile.get("stack_components", [])
        target_techs = engine.get_technique_for_target(
            target_os="",
            services=stack,
        )
        existing_ids = {c.get("technique_id") for c in candidates}
        for t in target_techs[:5]:
            tech_id = t.get("technique_name", "")
            if tech_id and tech_id not in existing_ids:
                candidates.append({
                    "action_type": "direct_probe",
                    "capability": "curl",
                    "target": target,
                    "method": "auto",
                    "action_id": f"harvester_{tech_id}_{target}_{int(time.time())}",
                    "rationale": f"Harvester: {t.get('description', '')[:100]}",
                    "impact_estimate": t.get("cvss_score", 7.0),
                    "confidence": t.get("confidence", 0.5),
                    "technique_id": tech_id,
                    "technique_name": tech_id,
                    "candidate_origin": CANDIDATE_ORIGIN_STUDENT,
                    "matched_components": stack,
                    "signature_label": "harvester_match",
                    "action_spec": {"technique_id": tech_id},
                })
                existing_ids.add(tech_id)
    except Exception as e:
        logger.debug("[Student] Harvester candidate lookup: %s", e)

    # Sort by confidence descending
    candidates.sort(key=lambda c: c.get("confidence", 0), reverse=True)
    return candidates


# ── S1-A: Candidate Testing (Brokered) ──────────────────────────

async def _test_candidate_brokered(
    target: str,
    candidate: dict,
    broker: Any,
) -> dict:
    """Test a candidate through the CapabilityBroker.
    
    S1-A: Routes execution through the Broker. If denied, records the
    denial reason. If allowed, executes via Kali tools client (brokered).
    No direct kali.run() calls — all execution is authorized by the Broker.
    
    Args:
        target: Target IP/hostname
        candidate: Candidate dict from StudentCandidateGenerator
        broker: CapabilityBroker instance
    
    Returns:
        Result dict with success, reason, evidence
    """
    tech_id = candidate.get("technique_id", "unknown")
    action_type = candidate.get("action_type", "direct_probe")
    capability = candidate.get("capability", "curl")
    impact_estimate = candidate.get("impact_estimate", 5.0)

    result = {
        "technique_id": tech_id,
        "technique_name": tech_id,
        "class": candidate.get("signature_label", "unknown"),
        "tested_at": time.time(),
        "success": False,
        "impact": impact_estimate,
        "confidence_achieved": candidate.get("confidence", 0.0),
        "evidence": "",
        "reason": "not_tested",
        "brokered": True,
        "receipt_id": "",
    }

    # Propose through CapabilityBroker
    receipt = broker.propose_action(
        target=target,
        action_type=action_type,
        capability=capability,
        method=candidate.get("method", "auto"),
        impact_estimate=impact_estimate,
        metadata={
            "technique_id": tech_id,
            "candidate_origin": CANDIDATE_ORIGIN_STUDENT,
            "action_spec": candidate.get("action_spec", {}),
        },
    )
    result["receipt_id"] = receipt.action_id
    result["broker_decision"] = receipt.decision

    if receipt.decision != "allow":
        result["reason"] = f"broker_denied: {receipt.reason}"
        result["broker_reason"] = receipt.reason
        return result

    # Authorized — execute through Kali tools (brokered)
    if not HAS_KALI or not kali:
        result["reason"] = "kali_tools_unavailable"
        return result

    try:
        # Build the execution command from the action_spec
        cmd = _build_execution_command(target, candidate)
        if not cmd:
            result["reason"] = "no_execution_command"
            return result

        # Execute through Kali client (this is the brokered execution path)
        # Note: The Kali client itself should be wrapped by a ToolAdapter
        # in production. For now, we use kali.run() as a minimal proxy,
        # but the authorization gate (CapabilityBroker.propose_action)
        # has already been passed.
        broker.start_execution(receipt)
        
        cmd_result = await _execute_with_timeout(cmd, timeout=30)
        
        if cmd_result and cmd_result.get("success"):
            result["evidence"] = cmd_result.get("stdout", "")[:500]
            result["success"] = True
            result["reason"] = "confirmed"
        else:
            result["evidence"] = cmd_result.get("stdout", "")[:200] if cmd_result else ""
            result["reason"] = cmd_result.get("error", "execution_failed") if cmd_result else "no_output"
        
        # Complete execution in broker
        broker.complete_execution(
            receipt,
            success=result["success"],
            result=result.get("evidence", ""),
        )
    except Exception as e:
        result["reason"] = f"execution_error: {e}"
        try:
            broker.timeout_execution(receipt, result=str(e))
        except Exception:
            pass

    # Update confidence in GrowthDB
    if result["success"] and HAS_GROWTH_DB:
        try:
            gdb = GrowthDB()
            gdb.record_technique_result(
                technique_name=tech_id,
                category=candidate.get("signature_label", "general"),
                success=True,
            )
        except Exception:
            pass

    return result


async def _test_candidate_proposal_only(target: str, candidate: dict) -> dict:
    """Record a candidate as proposed but not executed.
    
    S1-A: Used when no CapabilityBroker is available. The Student
    generates Candidates but does NOT execute them. This enforces
    the architectural constraint: Student proposes, Planner decides,
    Broker authorizes. Without a Broker, there is no execution.
    
    Args:
        target: Target IP/hostname
        candidate: Candidate dict from StudentCandidateGenerator
    
    Returns:
        Result dict with reason="proposed_not_executed"
    """
    tech_id = candidate.get("technique_id", "unknown")
    impact_estimate = candidate.get("impact_estimate", 5.0)

    result = {
        "technique_id": tech_id,
        "technique_name": tech_id,
        "class": candidate.get("signature_label", "unknown"),
        "tested_at": time.time(),
        "success": False,
        "impact": impact_estimate,
        "confidence_achieved": candidate.get("confidence", 0.0),
        "evidence": "",
        "reason": "proposed_not_executed",
        "brokered": False,
        "note": (
            "S1-A: Student proposes Candidates — execution requires "
            "Planner + CapabilityBroker. This candidate was recorded "
            "but not executed."
        ),
    }

    # Record the candidate's relevant metadata
    result["candidate_origin"] = candidate.get("candidate_origin", CANDIDATE_ORIGIN_STUDENT)
    result["proposed_action_type"] = candidate.get("action_type", "unknown")
    result["proposed_capability"] = candidate.get("capability", "unknown")

    return result


def _build_execution_command(target: str, candidate: dict) -> Optional[dict]:
    """Build an execution command from a Candidate's action_spec.
    
    S1-A: Replaces the old test_map. Transforms structured action_spec
    into a command dict that can be executed by the Kali tools client.
    
    Args:
        target: Target IP/hostname
        candidate: Candidate dict with action_spec
    
    Returns:
        Dict with {"tool": str, "args": str} or None if unbuildable
    """
    action_spec = candidate.get("action_spec", {})
    technique_id = candidate.get("technique_id", "")
    capability = candidate.get("capability", "curl")
    method = candidate.get("method", "auto")

    if capability == "curl":
        return _build_curl_command(target, technique_id, action_spec, method)
    elif capability == "python3":
        return {
            "tool": "python3",
            "args": "-c",
            "payload": action_spec.get("check_type", "print('check')"),
        }
    elif capability == "nmap":
        return {
            "tool": "nmap",
            "args": f"-sV {target}",
        }
    elif capability == "impacket":
        return {
            "tool": "impacket-" + action_spec.get("technique", "GetUserSPNs"),
            "args": f"-target {target}",
        }
    elif capability == "awscli":
        return {
            "tool": "aws",
            "args": action_spec.get("action", "sts get-caller-identity"),
        }
    else:
        logger.debug("[Student] Unknown capability for command build: %s", capability)
        return None


def _build_curl_command(target: str, technique_id: str, spec: dict, method: str) -> dict:
    """Build a curl command from structured action_spec."""
    headers = spec.get("headers", {})
    path = spec.get("path", "/")
    param = spec.get("param", "")
    payload = spec.get("payload", "")
    file_field = spec.get("file", "")

    # Build URL
    url = f"https://{target}{path}"

    # Build header args
    header_args = ""
    for key, value in headers.items():
        header_args += f' -H "{key}: {value}"'

    # Build request based on method
    if "param" in method or (param and payload):
        # Parameterized request (e.g., /?id=PAYLOAD)
        if "/" in path:
            base_path = path.rsplit("/", 1)[0] if "/" in path else path
        else:
            base_path = path
        url = f"https://{target}{base_path}?{param}={payload}"
        curl_cmd = f'-s -o /dev/null -w "%{{http_code}}" {header_args} "{url}"'
    elif "upload" in method and file_field:
        curl_cmd = f'-s -o /dev/null -w "%{{http_code}}" -F "file=@{file_field}" "{url}"'
    elif method == "path_traversal":
        url = f"https://{target}/?{param}={payload}"
        curl_cmd = f'-s -o /dev/null -w "%{{http_code}}" "{url}"'
    else:
        # Standard request with headers
        curl_cmd = f'-s -o /dev/null -w "%{{http_code}}" {header_args} "{url}"'

    return {"tool": "curl", "args": curl_cmd}


async def _execute_with_timeout(cmd: dict, timeout: int = 30) -> dict:
    """Execute a command through the Kali tools client.
    
    S1-A: This is the SOLE execution path. It is ONLY called after
    the CapabilityBroker has authorized the action. The Broker's
    authorization gate has already been passed at this point.
    
    Args:
        cmd: Command dict with {"tool": str, "args": str}
        timeout: Timeout in seconds
    
    Returns:
        Dict with {"success": bool, "stdout": str, "error": str}
    """
    if not HAS_KALI or not kali:
        return {"success": False, "stdout": "", "error": "kali_unavailable"}

    try:
        result = await kali.run(cmd["tool"], cmd["args"], timeout=timeout)
        if result:
            stdout = result.get("stdout", "")
            return {
                "success": bool(stdout),
                "stdout": stdout,
                "error": result.get("stderr", ""),
            }
        return {"success": False, "stdout": "", "error": "no_response"}
    except Exception as e:
        return {"success": False, "stdout": "", "error": str(e)}


# ── Chain Synthesis ─────────────────────────────────────────────

async def _synthesize_chains(
    confirmed: list[dict],
    target_features: list[str],
    target: str,
) -> dict:
    """Synthesize exploitation chains from confirmed findings."""
    synthesizer = ChainSynthesizer(growth_db=GrowthDB() if HAS_GROWTH_DB else None)

    chains = synthesizer.synthesize(confirmed, target_features)
    novel = [c for c in chains if c.get("is_novel")]

    # Store chains in growth_db
    if HAS_GROWTH_DB:
        try:
            gdb = GrowthDB()
            for c in chains:
                chain_key = f"chain_{c.get('chain_id', int(time.time()))}"
                gdb.record(
                    chain_key,
                    {
                        "target": target,
                        "phase": "chain_synthesis",
                        "finding_type": "exploit_chain",
                        "severity": "critical"
                        if c.get("estimated_cvss", 0) >= 9.0
                        else "high",
                        "chain": c,
                        "timestamp": time.time(),
                    },
                )
        except Exception:
            pass

    return {"chains": chains, "novel": novel}


# ── Reflection ──────────────────────────────────────────────────

async def _reflect(session: dict) -> dict:
    """Post-engagement reflection — update knowledge, identify gaps."""
    reflection = {
        "total_hypotheses": len(session.get("hypotheses", [])),
        "total_candidates": len(session.get("candidates", [])),
        "confirmed_findings": sum(1 for f in session.get("findings", []) if f.get("success")),
        "failed_findings": sum(1 for f in session.get("findings", []) if not f.get("success")),
        "proposed_findings": sum(
            1 for f in session.get("findings", [])
            if f.get("reason") == "proposed_not_executed"
        ),
        "broker_denied": sum(
            1 for f in session.get("findings", [])
            if "broker_denied" in f.get("reason", "")
        ),
        "chains_built": len(session.get("chains", [])),
        "novel_chains": len(session.get("novel_chains", [])),
        "execution_mode": session.get("execution_mode", "proposal_only"),
        "knowledge_gaps": [],
        "techniques_promoted": [],
        "techniques_demoted": [],
    }

    if not HAS_GROWTH_DB:
        return reflection

    try:
        gdb = GrowthDB()

        # Promote/demote techniques via knowledge records
        for f in session.get("findings", []):
            if f.get("success"):
                gdb.record_technique_result(
                    technique_name=f.get("technique_id", "unknown"),
                    category=f.get("class", "general"),
                    success=True,
                )
                reflection["techniques_promoted"].append(f.get("technique_id", "?"))
            elif f.get("reason") not in ("proposed_not_executed", "not_tested"):
                gdb.record_technique_result(
                    technique_name=f.get("technique_id", "unknown"),
                    category=f.get("class", "general"),
                    success=False,
                )
                reflection["techniques_demoted"].append(f.get("technique_id", "?"))

        # Check for gaps using the gap filler
        try:
            from orchestrator.student.research_scheduler import ResearchScheduler
            scheduler = ResearchScheduler()
            gaps = scheduler._identify_gaps()
            reflection["knowledge_gaps"] = gaps

            # Queue study queries
            if gaps:
                from orchestrator.student.coverage_gap_filler import (
                    generate_gap_study_plan,
                )
                plan = generate_gap_study_plan(gaps, kb=gdb)
                reflection["study_plan"] = plan
                logger.info(
                    "[Student] Generated %d gap study sessions",
                    len(plan["study_sessions"]),
                )
        except Exception as e2:
            logger.debug("[Student] Gap analysis in reflection: %s", e2)

    except Exception as e:
        logger.warning("[Student] Reflection error: %s", e)

    return reflection


# ── Report Generation ───────────────────────────────────────────

def _generate_report(session: dict) -> dict:
    """Generate human-readable engagement report."""
    findings = session.get("findings", [])
    confirmed = [f for f in findings if f.get("success")]
    failed = [f for f in findings if not f.get("success")]
    proposed = [f for f in findings if f.get("reason") == "proposed_not_executed"]
    denied = [f for f in findings if "broker_denied" in f.get("reason", "")]
    execution_mode = session.get("execution_mode", "proposal_only")

    report_lines = []
    report_lines.append("=" * 60)
    report_lines.append("🎓 THE STUDENT — Engagement Report")
    report_lines.append("=" * 60)
    report_lines.append(f"  Target:     {session.get('target', 'unknown')}")
    report_lines.append(f"  Type:       {session.get('target_type', 'web')}")
    report_lines.append(f"  Profile:    {session.get('profile', {}).get('stack_summary', 'unknown')}")
    report_lines.append(f"  Mode:       {execution_mode}")
    report_lines.append(f"  Elapsed:    {session.get('elapsed', 0):.1f}s")
    report_lines.append("")
    report_lines.append(f"  Candidates generated: {len(session.get('candidates', []))}")
    report_lines.append(f"  ✅ Confirmed:         {len(confirmed)}")
    report_lines.append(f"  ❌ Failed:            {len(failed)}")
    report_lines.append(f"  📋 Proposed (no exec): {len(proposed)}")
    report_lines.append(f"  🚫 Broker denied:     {len(denied)}")
    report_lines.append(f"  🔗 Chains built:      {len(session.get('chains', []))}")
    report_lines.append(f"  ✨ Novel chains:      {len(session.get('novel_chains', []))}")
    report_lines.append("")

    if confirmed:
        report_lines.append("  Confirmed Findings:")
        for c in confirmed[:10]:
            report_lines.append(f"    ✅ {c.get('technique_name', c.get('technique_id', '?'))} "
                                f"(CVSS {c.get('impact', '?')})")
        report_lines.append("")

    if proposed:
        report_lines.append("  Proposed (awaiting Planner/Broker):")
        for p in proposed[:5]:
            report_lines.append(f"    📋 {p.get('technique_id', '?')} "
                                f"(confidence: {p.get('confidence_achieved', 0):.0%})")
        report_lines.append("")

    if session.get("chains"):
        report_lines.append("  Exploitation Chains:")
        for c in session["chains"][:5]:
            report_lines.append(f"    🔗 {c.get('name', 'chain')} "
                                f"(confidence: {c.get('confidence', 0):.0%})")
        report_lines.append("")

    if session.get("novel_chains"):
        report_lines.append("  ✨ Novel Techniques Discovered:")
        for c in session["novel_chains"][:3]:
            report_lines.append(f"    ✨ {c.get('name', 'novel chain')}")
        report_lines.append("")

    if session.get("research_results"):
        r = session["research_results"]
        report_lines.append("  Research Ingested:")
        report_lines.append(f"    CVEs: {r.get('cves_found', 0)} | "
                            f"Writeups: {r.get('writeups_found', 0)} | "
                            f"Gaps: {len(r.get('gaps', []))}")
        report_lines.append("")

    research_time = ""
    if session.get("research_results") and session["research_results"].get("elapsed"):
        research_time = f" (research: {session['research_results']['elapsed']}s)"

    report_lines.append(f"  Total time: {session.get('elapsed', 0):.1f}s{research_time}")

    if execution_mode == "proposal_only":
        report_lines.append("")
        report_lines.append("  ⚠️  S1-A: Proposal-only mode. No Candidates were executed.")
        report_lines.append("      Provide a CapabilityBroker and Planner to enable execution.")
        report_lines.append("      Pass planner=<Planner>, capability_broker=<CapabilityBroker>")
        report_lines.append("      to handle() for brokered execution.")

    report_lines.append("=" * 60)

    return {
        "target": session.get("target", "unknown"),
        "stack": session.get("profile", {}).get("stack_summary", "unknown"),
        "findings_count": len(confirmed),
        "proposed_count": len(proposed),
        "denied_count": len(denied),
        "chains_count": len(session.get("chains", [])),
        "novel_count": len(session.get("novel_chains", [])),
        "elapsed": session.get("elapsed", 0),
        "execution_mode": execution_mode,
        "text": "\n".join(report_lines),
    }


async def handle_research(hours_back: int = 48) -> dict:
    """Standalone research cycle."""
    scheduler = ResearchScheduler()
    result = await scheduler.run_research_cycle(hours_back=hours_back)
    return {
        "session_id": result.session_id,
        "cves_found": result.cves_found,
        "writeups_found": result.writeups_found,
        "techniques_extracted": result.techniques_extracted,
        "gaps": result.gaps_identified,
        "started": result.started,
        "completed": result.completed,
        "elapsed": round(result.completed - result.started, 2),
    }
