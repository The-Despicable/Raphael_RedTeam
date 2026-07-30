"""Phase executor for the harvest cycle — ingests CVEs, GitHub PoCs, and web feeds into the technique database."""
import asyncio
import logging
import time

logger = logging.getLogger("phase.harvest")


async def run_harvest(target: str = "", findings: list = None) -> "PhaseResult":
    from orchestrator.brain.phases.models import Finding, PhaseResult, Severity
    from orchestrator.harvester.harvester_engine import get_harvester

    findings = findings or []
    t0 = time.time()
    harvester = get_harvester()

    cycle = await harvester.run_full_cycle(target=target)

    phase_findings = []
    if cycle.techniques_extracted > 0:
        phase_findings.append(Finding(
            phase="harvest",
            type="techniques_extracted",
            target=target or "global",
            severity=Severity.INFO,
            description=f"Extracted {cycle.techniques_extracted} new techniques from web sources",
            evidence=f"cycle={cycle.cycle_id}",
        ))
    if cycle.techniques_integrated > 0:
        phase_findings.append(Finding(
            phase="harvest",
            type="techniques_integrated",
            target=target or "global",
            severity=Severity.INFO,
            description=f"Integrated {cycle.techniques_integrated} techniques into knowledge base",
            evidence=f"cycle={cycle.cycle_id}",
        ))

    cve_new = sum(
        v.get("new", 0) for v in cycle.cve_results.values() if isinstance(v, dict)
    )
    if cve_new > 0:
        phase_findings.append(Finding(
            phase="harvest",
            type="new_cves",
            target=target or "global",
            severity=Severity.LOW,
            description=f"Found {cve_new} new CVEs from feed ingestion",
            evidence=str(cycle.cve_results),
        ))

    repo_new = cycle.repo_results.get("new", 0)
    if repo_new > 0:
        phase_findings.append(Finding(
            phase="harvest",
            type="new_github_repos",
            target=target or "global",
            severity=Severity.LOW,
            description=f"Discovered {repo_new} new GitHub PoC repositories",
            evidence=str(cycle.repo_results),
        ))

    errors = cycle.errors or []
    success = cycle.techniques_extracted > 0 or cycle.techniques_integrated > 0
    summary = (
        f"Harvest: {cycle.techniques_extracted} extracted, {cycle.techniques_integrated} integrated, "
        f"{cve_new} new CVEs, {repo_new} new repos"
        + (f", {len(errors)} errors" if errors else "")
    )

    return PhaseResult(
        phase="harvest",
        success=success,
        findings=phase_findings,
        summary=summary,
        latency=time.time() - t0,
    )
