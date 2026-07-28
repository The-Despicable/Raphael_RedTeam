import asyncio, json, time, hashlib, os, sys, logging

sys.path.insert(0, str(os.path.join(os.path.dirname(__file__), "..", "..")))

from orchestrator.providers import call_model
from orchestrator.brain.adaptive_brain import get_analytics
from orchestrator.brain.neural_memory import (
    store_episodic, retrieve_episodic, store_semantic,
    store_target_profile, update_target_stats,
)
from orchestrator.brain.target_profiler import profile_target
from orchestrator.audit_trail import record_event
from orchestrator.brain.target_state import (
    build_target_state, summarize_target_state,
    AttackGraph, CompromiseLevel,
)
from orchestrator.brain.phases import PHASE_EXECUTORS, Finding, PhaseResult
from orchestrator.engagement_queue import get_queue
from orchestrator.chains.credential_spray import spray, _extract_creds, _extract_targets
from orchestrator.chains.ad_kill_chain import run_chain as run_ad_kill_chain
from orchestrator.hardening.circuit_breaker import get_breaker
from orchestrator.hardening.rate_limiter import get_limiter
from orchestrator.hardening.timeout_guard import get_timeout_guard

logger = logging.getLogger("autonomous")

PHASES = ["harvest", "recon", "cicd", "ml_attack", "cloud_abuse", "container_escape", "scan", "exploit", "postex", "lateral", "credential", "exfil", "phish"]

_RL_ACTIVE = os.getenv("RAPHAEL_RL_STRATEGY", "1") == "1"


async def handle(target: str, phases: list = None, **kwargs) -> dict:
    if phases is None:
        phases = PHASES

    persona = kwargs.get("persona", "blackhat")
    os.environ["RAPHAEL_PERSONA"] = persona
    if persona:
        from orchestrator.providers import resolve_persona_override
        system_override = resolve_persona_override(persona)
    else:
        system_override = None

    results = {
        "target": target, "phases": {}, "analytics": {},
        "profile": {}, "timestamp": time.time(),
        "chain_hash": hashlib.sha256(f"{target}:{time.time()}".encode()).hexdigest()[:12],
    }

    try:
        profile = await asyncio.wait_for(
            asyncio.get_event_loop().run_in_executor(None, profile_target, target),
            timeout=30.0
        )
        results["profile"] = profile
        store_target_profile(target, profile.get("classification", {}))
    except asyncio.TimeoutError:
        results["profile"] = {"error": "profile_target timed out (30s)", "target": target}
    except Exception as e:
        results["profile"] = {"error": str(e), "target": target}

    attack_graph = AttackGraph(target)
    attack_graph.add_host(target, criticality=9.0)

    from orchestrator.harvester.harvester_engine import get_harvester
    harvester = get_harvester()

    record_event("engagement_start", target=target, phase="init", verdict="started")

    all_findings: list[Finding] = []

    if _RL_ACTIVE:
        from orchestrator.brain.strategy_learner import get_strategy_learner
        from orchestrator.conductor import select_strategy, record_strategy_outcome

    if _RL_ACTIVE and phases is None:
        sl = get_strategy_learner()
        rl_strategy = sl.get_best_strategy("none", all_findings)
        if rl_strategy:
            logger.info(f"  [RL] Strategy plan ({len(rl_strategy)} phases): "
                        f"{' → '.join(rl_strategy[:6])}...")
            phases = rl_strategy

    phases_run = set()
    max_phases = len(phases) + 5
    phase_index = 0

    while phase_index < len(phases) and len(phases_run) < max_phases:
        phase_name = phases[phase_index]
        phase_index += 1

        executor = PHASE_EXECUTORS.get(phase_name)
        if not executor:
            results["phases"][phase_name] = {
                "success": False, "error": f"No executor for phase: {phase_name}",
            }
            continue

        if phase_name in phases_run:
            continue
        phases_run.add(phase_name)

        breaker_key = f"{target}:{phase_name}"
        if not get_breaker().allow(breaker_key):
            logger.info(f"  ⛔ {phase_name.upper()} PHASE — circuit breaker OPEN, skipping")
            results["phases"][phase_name] = {
                "success": False, "error": "circuit breaker open",
                "latency": 0, "skipped": True,
            }
            if _RL_ACTIVE:
                record_strategy_outcome(False, all_findings, phase_name, 0.0, breaker=True)
            continue

        logger.info(f"  ▶ {phase_name.upper()} PHASE ({phase_index}/{len(phases)})")
        guard = get_timeout_guard()
        t0 = time.time()
        timeout_hit = False
        try:
            phase_result = await guard.run(
                f"phase_{phase_name}",
                executor(target, all_findings),
                timeout=guard.get_timeout(f"phase_{phase_name}"),
            )
        except Exception as e:
            phase_result = PhaseResult(
                phase=phase_name, success=False,
                error=str(e), latency=time.time() - t0,
            )
            timeout_hit = "timed out" in str(e).lower()

        all_findings.extend(phase_result.findings)

        if phase_result.success:
            get_breaker().record_success(breaker_key)
        else:
            get_breaker().record_failure(breaker_key)

        if _RL_ACTIVE:
            record_strategy_outcome(
                phase_result.success, phase_result.findings, phase_name,
                time.time() - t0, timeout=timeout_hit,
            )

        strategist_output = ""
        if phase_result.success and phase_result.findings:
            try:
                finding_summary = "\n".join(
                    f"- [{f.severity.value}] {f.type}: {f.description[:200]}"
                    for f in phase_result.findings[:10]
                )
                strat_msgs = [{"role": "user", "content": (
                    f"[STRATEGIST — {phase_name.upper()} RESULTS]\n"
                    f"Target: {target}\n\n"
                    f"Findings:\n{finding_summary}\n\n"
                    f"The next phase is one of: {[p for p in phases if p != phase_name]}\n"
                    "Based on these results, what should the next phase focus on?\n"
                    "Be specific: which ports, endpoints, or vulnerabilities to prioritize."
                )}]
                strategist_output = await call_model("auto", strat_msgs, max_tokens=512, temperature=0.3, system_override=system_override)
            except Exception:
                logger.debug("Non-critical error", exc_info=True)

        latency = time.time() - t0
        results["phases"][phase_name] = {
            "success": phase_result.success,
            "findings": [f.to_dict() for f in phase_result.findings],
            "summary": phase_result.summary,
            "latency": round(latency, 2),
            "error": phase_result.error,
            "strategist": strategist_output[:1000] if strategist_output else "",
        }

        store_episodic(
            event_type=phase_name, target=target, model="executor",
            context=phase_name, input_data=target,
            output_summary=phase_result.summary,
            success=phase_result.success, score=1.0 if phase_result.success else 0.0,
            latency=latency,
        )
        update_target_stats(target, phase_result.success)
        record_event(f"phase:{phase_name}", target=target, phase=phase_name,
                     verdict="pass" if phase_result.success else "fail")

        if phase_result.success and phase_name in ("exploit", "postex"):
            attack_graph.compromise(target, CompromiseLevel.LOW_PRIVILEGE)

        if _RL_ACTIVE and phase_result.success and phase_name in (
            "lpd_exploit", "pjl_exploit", "exploit_chain", "relay_chain",
            "craft_exploit", "generic_exploit", "anonymous_ttp",
        ):
            from orchestrator.conductor import get_strategy_plan
            new_strategy = get_strategy_plan("low_priv", all_findings)
            if new_strategy:
                remaining = [p for p in new_strategy if p not in phases_run]
                if remaining:
                    phases = phases[:phase_index] + remaining
                    logger.info(f"  [RL] Strategy re-planned ({len(remaining)} new phases added)")

        if phase_name in ("credential", "lateral") and phase_result.success:
            creds = _extract_creds(all_findings)
            hosts = _extract_targets(all_findings)
            if creds:
                spray_findings = await spray(creds, hosts, primary_target=target, findings=all_findings)
                all_findings.extend(spray_findings)
                results["phases"].setdefault("credential_spray", {}).update({
                    "success": len(spray_findings) > 0,
                    "findings": [f.to_dict() for f in spray_findings],
                    "creds_tested": len(creds),
                    "hosts_tested": len(hosts),
                })

            is_ad = any("domain" in (f.description + f.evidence).lower() or
                        f.type in ("domain_info", "domain_controller", "kerberos")
                        for f in all_findings)
            if is_ad and (creds or hosts):
                logger.info(f"  ▶ AD KILL CHAIN — target appears to be AD domain")
                ad_chain_result = await run_ad_kill_chain(target, all_findings)
                results["phases"]["ad_kill_chain"] = ad_chain_result
                for fd in ad_chain_result.get("findings", []):
                    all_findings.append(Finding(**fd) if isinstance(fd, dict) else fd)
                if ad_chain_result.get("dominion_achieved"):
                    attack_graph.compromise(target, CompromiseLevel.DOMAIN_ADMIN)

    results["analytics"] = get_analytics()
    history = retrieve_episodic(target=target, limit=20)
    results["memory"] = {"episodes_retrieved": len(history)}
    try:
        results["harvester_stats"] = harvester.stats()
    except Exception:
        results["harvester_stats"] = {"error": "unavailable"}
    results["total_findings"] = len(all_findings)

    flags = {}
    for f in all_findings:
        if f.type == "root_flag":
            flags["root_flag"] = f.evidence or f.description
            flags["root_flag_found"] = True
        elif f.type == "user_flag":
            flags["user_flag"] = f.evidence or f.description
            flags["user_flag_found"] = True
    flags["all_flags_captured"] = flags.get("user_flag_found") and flags.get("root_flag_found")
    results["flags"] = flags

    return results


async def handle_multi(targets: list[str], phases: list = None, parallel: bool = False) -> dict:
    queue = get_queue()
    for target in targets:
        queue.enqueue(target, phases or PHASES)

    if parallel:
        tasks = [handle(t, phases) for t in targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        combined = {}
        for t, r in zip(targets, results):
            if isinstance(r, Exception):
                combined[t] = {"error": str(r)}
            else:
                combined[t] = r
        return multi_results(targets, combined)
    else:
        results = {}
        for target in targets:
            r = await handle(target, phases)
            results[target] = r
            queue.update(
                next((e.id for e in queue.list() if e.target == target), ""),
                status="complete", result=r,
                findings_count=r.get("total_findings", 0),
            )
        return multi_results(targets, results)


async def handle_queue_loop():
    queue = get_queue()
    await queue.run_loop(handle)


def multi_results(targets: list[str], results: dict) -> dict:
    total_findings = sum(r.get("total_findings", 0) for r in results.values() if isinstance(r, dict))
    return {
        "targets": targets,
        "total_targets": len(targets),
        "total_findings": total_findings,
        "results": results,
        "timestamp": time.time(),
    }
