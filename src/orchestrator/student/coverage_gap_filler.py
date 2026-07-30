"""
Coverage Gap Filler — Targeted remediation for weak knowledge areas.
Generates structured study plans and research queries.

Based on the 6 knowledge gaps identified by the Student's gap analysis:
  SQL Injection, SSRF, Privilege Escalation, Broken Access Control,
  API Security, Supply Chain

Each study plan includes:
  - Priority ranking
  - Targeted web/queries for the research scheduler
  - Target stack profiles to practice against
  - Chain targets (what the technique chains to)
"""

import asyncio
import logging
from datetime import datetime
from typing import Optional

logger = logging.getLogger("student.gap_filler")

# ═══════════════════════════════════════════════════════════════
# GAP STUDY PLANS
# ═══════════════════════════════════════════════════════════════
# Each plan is a structured curriculum for filling a coverage gap.
# ═══════════════════════════════════════════════════════════════

GAP_STUDY_PLANS = {
    "ssrf": {
        "name": "Server-Side Request Forgery",
        "priority": "CRITICAL — 0 techniques. Directly chainable to cloud credential exposure.",
        "study_queries": [
            "SSRF exploitation techniques blind OOB 2025 2026",
            "SSRF to cloud metadata service AWS GCP Azure bypass",
            "SSRF chaining to RCE internal service exploitation",
            "SSRF via XML parser XXE SSRF combined attack",
            "SSRF bypass filter evasion techniques 2025 2026",
            "SSRF in modern frameworks Next.js Django SSRF",
            "SSRF port scan via URL parameter techniques",
            "SSRF to LDAP gopher protocol exploitation",
        ],
        "target_stacks": [
            "any+forward_proxy",
            "nginx+internal_service",
            "python+requests_lib",
        ],
        "chain_targets": [
            "cloud_cred_exposure",
            "internal_service_rce",
            "network_pivot",
        ],
    },
    "sql injection": {
        "name": "SQL Injection",
        "priority": "HIGH — 1 writeup ingested but 0 techniques in KB.",
        "study_queries": [
            "SQL injection modern WAF bypass techniques 2025 2026",
            "SQL injection second order blind time-based advanced",
            "SQL injection NoSQL MongoDB injection techniques",
            "SQL injection automation sqlmap tamper scripts",
            "SQL injection to RCE via xp_cmdshell postgresql COPY",
            "SQL injection ORM bypass Hibernate Django parameterized",
        ],
        "target_stacks": [
            "nginx+postgresql+python",
            "apache+mysql+php",
            "iis+mssql+dotnet",
        ],
        "chain_targets": [
            "database_data_exfil",
            "rce_via_sql",
            "credential_harvest",
        ],
    },
    "privilege escalation": {
        "name": "Privilege Escalation",
        "priority": "HIGH — 0 techniques. Cannot elevate after initial foothold.",
        "study_queries": [
            "Linux privilege escalation kernel exploit 2025 2026 CVE",
            "Windows privilege escalation SeImpersonate potato techniques 2025",
            "sudo privilege escalation misconfiguration exploitation",
            "SUID binary exploitation GTFOBins techniques 2025",
            "container escape Docker containerd privilege escalation",
            "Windows kernel exploit privilege escalation 2025 2026",
            "service permission abuse privilege escalation Windows",
            "Linux capabilities privilege escalation exploitation",
        ],
        "target_stacks": [
            "linux+shell_access",
            "windows+cmd_access",
            "container+shell",
        ],
        "chain_targets": [
            "root_access",
            "system_access",
            "full_control",
        ],
    },
    "broken access control": {
        "name": "Broken Access Control / IDOR",
        "priority": "HIGH — #1 on OWASP Top 10. 0 techniques in KB.",
        "study_queries": [
            "IDOR parameter manipulation techniques bypass 2025 2026",
            "mass assignment vulnerability API exploitation",
            "role-based access control bypass techniques",
            "horizontal privilege escalation API testing",
            "vertical privilege escalation admin bypass",
            "insecure direct object reference UUID enumeration",
            "GraphQL access control bypass batching techniques",
            "HTTP method override access control bypass",
        ],
        "target_stacks": [
            "rest_api+jwt",
            "graphql_api",
            "spring_boot+rbac",
        ],
        "chain_targets": [
            "data_exfil",
            "admin_access",
            "account_takeover",
        ],
    },
    "api security": {
        "name": "API Security",
        "priority": "HIGH — Modern targets are API-first. 0 techniques.",
        "study_queries": [
            "GraphQL injection introspection attack techniques",
            "REST API parameter pollution bypass 2025 2026",
            "API rate limiting bypass enumeration techniques",
            "JWT token forgery RS256 to HS256 confusion attack",
            "API gateway misconfiguration exploitation",
            "WebSocket API security testing methodology",
            "gRPC API penetration testing techniques",
            "OAuth 2.0 implicit flow security issues",
        ],
        "target_stacks": [
            "graphql+nodejs",
            "rest+python",
            "grpc+go",
        ],
        "chain_targets": [
            "data_exfil",
            "account_takeover",
            "pivot_to_internal",
        ],
    },
    "supply chain": {
        "name": "Supply Chain Security",
        "priority": "MEDIUM — Growing attack vector. 0 techniques.",
        "study_queries": [
            "dependency confusion attack techniques 2025 2026",
            "malicious npm package typosquatting techniques",
            "CI/CD pipeline compromise techniques 2025",
            "GitHub Actions poisoning supply chain attack",
            "malicious PyPI package dependency hijacking",
            "malware in open source supply chain detection",
        ],
        "target_stacks": [
            "nodejs+npm",
            "python+pip",
            "github_actions",
        ],
        "chain_targets": [
            "supply_chain_compromise",
            "downstream_infection",
        ],
    },
    "general security": {
        "name": "General Security (catch-all)",
        "priority": "LOW — Techniques exist but not classified.",
        "study_queries": [
            "general web application security testing methodology",
            "bug bounty methodology 2026",
        ],
        "target_stacks": ["generic+webapp"],
        "chain_targets": ["general_compromise"],
    },
}


def generate_gap_study_plan(gaps: list[str], kb=None) -> dict:
    """
    Given identified gaps from the Student's gap analysis,
    generate a structured study plan with prioritized research queries.
    
    Args:
        gaps: List of gap descriptions from the ResearchScheduler
              e.g. "Low coverage in SSRF — no techniques or writeups found"
        kb: Optional StudentKB for checking existing coverage
    
    Returns:
        Dict with study plan ready for insertion into the research queue.
    """
    study_plan = {
        "generated": datetime.now().isoformat(),
        "total_gaps": len(gaps),
        "study_sessions": [],
    }

    for gap in gaps:
        gap_lower = gap.lower()
        matched = False

        for key, plan in GAP_STUDY_PLANS.items():
            if key in gap_lower or plan["name"].lower() in gap_lower:
                # Check KB for existing coverage
                existing_count = 0
                if kb:
                    try:
                        existing = kb.get_techniques(
                            class_filter=plan["name"]
                        ) if hasattr(kb, 'get_techniques') else []
                        existing_count = len(existing)
                    except Exception:
                        pass

                study_plan["study_sessions"].append({
                    "topic": plan["name"],
                    "priority": plan["priority"],
                    "existing_techniques": existing_count,
                    "queries_needed": len(plan["study_queries"]),
                    "queries": plan["study_queries"],
                    "target_stacks_to_learn": plan["target_stacks"],
                    "chain_targets": plan["chain_targets"],
                    "estimated_sessions": max(
                        1, len(plan["study_queries"]) // 3
                    ),
                })
                matched = True
                break

        if not matched:
            # Catch-all: treat as general security gap
            plan = GAP_STUDY_PLANS["general security"]
            study_plan["study_sessions"].append({
                "topic": gap[:60],
                "priority": "LOW — Unclassified gap",
                "existing_techniques": 0,
                "queries_needed": len(plan["study_queries"]),
                "queries": plan["study_queries"],
                "target_stacks_to_learn": plan["target_stacks"],
                "chain_targets": plan["chain_targets"],
                "estimated_sessions": 1,
            })

    # Sort by priority: CRITICAL > HIGH > MEDIUM > LOW
    priority_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

    def sort_key(session):
        prio = session.get("priority", "LOW").split("—")[0].strip()
        return priority_order.get(prio, 99)

    study_plan["study_sessions"].sort(key=sort_key)

    logger.info(
        "Gap filler: Generated study plan with %d sessions for %d gaps",
        len(study_plan["study_sessions"]),
        len(gaps),
    )

    return study_plan


def queue_gap_queries(gaps: list[str], research_queue: list, kb=None) -> int:
    """
    Queue study queries directly into a research_queue (list).
    Returns number of queries queued.
    """
    plan = generate_gap_study_plan(gaps, kb)
    queued = 0
    for session in plan["study_sessions"]:
        for query in session["queries"]:
            if query not in research_queue:
                research_queue.append(query)
                queued += 1
    logger.info("Gap filler: Queued %d study queries into research queue", queued)
    return queued


async def trigger_immediate_research(
    gaps: list[str],
    scheduler,
    background_service,
    kb=None,
) -> dict:
    """
    Queue gap queries and trigger an immediate research cycle.

    This is the async bridge between CoverageGapFiller and KnowledgeBackgroundService.
    It queues gap-specific web search queries, then signals the background service
    to run an immediate cycle (outside its normal interval).

    Args:
        gaps: List of gap descriptions from gap analysis
        scheduler: ResearchScheduler instance (queries are queued here)
        background_service: KnowledgeBackgroundService instance (triggered here)
        kb: Optional StudentKB for existing coverage check

    Returns:
        Dict with counts of queries queued and trigger status.
    """
    # Phase 1: Queue gap-specific study queries into the research scheduler
    queries_queued = queue_gap_queries(gaps, scheduler.research_queue, kb)

    # Phase 2: Trigger immediate research cycle on the background service
    if background_service and background_service.is_running:
        background_service.request_immediate_cycle()
        trigger_status = "triggered"
    else:
        trigger_status = "service_not_running"
        logger.warning(
            "Cannot trigger immediate research - background service not running"
        )

    result = {
        "gaps_processed": len(gaps),
        "queries_queued": queries_queued,
        "trigger_status": trigger_status,
        "timestamp": datetime.now().isoformat(),
    }

    logger.info(
        "Gap filler: Immediate research triggered - %d gaps, %d queries (%s)",
        len(gaps),
        queries_queued,
        trigger_status,
    )

    return result
