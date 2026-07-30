import json, logging, time
from typing import Optional

from orchestrator.agents.base import (
    BaseAgent, GoalType, Task, TaskStatus, AgentContext, Finding, ToolDef,
)
from orchestrator.agents.goal_tree import GoalValidator
from orchestrator.events import EventBus, event_bus
from orchestrator.providers import call_model, resolve_persona_override

logger = logging.getLogger("recon_agent")

RECON_PROMPT = (
    "You are an OSINT analyst. Your job is to discover everything about the target "
    "before any tool touches it.\n\n"
    "Available tools:\n"
    "  - dns_enum: DNS zone transfer, SRV records, nameserver lookup\n"
    "  - whois: WHOIS lookup for domain registration\n"
    "  - web_fingerprint: HTTP header + technology detection via whatweb\n"
    "  - subdomain_scan: Gobuster DNS subdomain enumeration\n"
    "  - port_scan: TCP port scan (top 1000 ports)\n"
    "  - directory_scan: Gobuster directory enumeration\n\n"
    "Output ONLY valid JSON:\n"
    '{"actions": [{"tool": "tool_name", "args": {"target": "...", ...}}]}\n\n'
    "Start with passive recon (dns_enum, whois), then move to active (port_scan, web_fingerprint). "
    "Max 4 actions per cycle."
)

RECON_TOOLS = {
    "dns_enum": ToolDef(name="dns_enum", description="DNS zone transfer, SRV records, NS lookup"),
    "whois": ToolDef(name="whois", description="WHOIS registration lookup"),
    "web_fingerprint": ToolDef(name="web_fingerprint", description="HTTP header + tech detection"),
    "subdomain_scan": ToolDef(name="subdomain_scan", description="Gobuster DNS subdomain enum"),
    "port_scan": ToolDef(name="port_scan", description="TCP port scan top 1000"),
    "directory_scan": ToolDef(name="directory_scan", description="Gobuster directory enum"),
}


class ReconAgent(BaseAgent):
    name: str = "recon"
    system_prompt: str = RECON_PROMPT
    tools: list[ToolDef] = list(RECON_TOOLS.values())
    max_iterations: int = 10
    max_consecutive_failures: int = 2

    def __init__(self, bus: Optional[EventBus] = None, persona: str = ""):
        super().__init__(bus)
        self.persona = persona
        self._system_override = resolve_persona_override(persona) if persona else None

    async def think(self, task: Task, context: AgentContext,
                    system_override: Optional[str] = None) -> "Thought":
        from orchestrator.agents.base import Thought

        # Deterministic recon phase: cycle through tools by iteration
        # No LLM call needed - LLMs in this env are too slow for tool planning
        iteration = context.iteration
        recon_plan = [
            {"tool": "dns_enum", "args": {"target": task.target}},
            {"tool": "whois", "args": {"target": task.target}},
            {"tool": "web_fingerprint", "args": {"target": task.target}},
            {"tool": "port_scan", "args": {"target": task.target, "ports": "1-1000"}},
            {"tool": "subdomain_scan", "args": {"target": task.target}},
            {"tool": "directory_scan", "args": {"target": task.target}},
        ]

        if iteration <= len(recon_plan):
            return Thought(actions=[recon_plan[iteration - 1]], reasoning="Deterministic recon phase")
        else:
            return Thought(actions=[], reasoning="Recon complete")

        # Also override max_iterations to prevent infinite loops

    async def execute(self, action: dict) -> list[Finding]:
        tool = action.get("tool", "")
        args = action.get("args", {})
        target = args.get("target", "")
        findings = []

        try:
            if tool == "dns_enum":
                findings = await self._run_dns_enum(target)
            elif tool == "whois":
                findings = await self._run_whois(target)
            elif tool == "web_fingerprint":
                findings = await self._run_web_fingerprint(target)
            elif tool == "subdomain_scan":
                findings = await self._run_subdomain_scan(target)
            elif tool == "port_scan":
                findings = await self._run_port_scan(target, args.get("ports", "1-1000"))
            elif tool == "directory_scan":
                findings = await self._run_directory_scan(target)
            else:
                logger.warning(f"[recon] Unknown tool: {tool}")
        except Exception as e:
            logger.warning(f"[recon] Tool {tool} failed: {e}")

        return findings

    async def _run_dns_enum(self, target: str) -> list[Finding]:
        from orchestrator.scanners.dns_wrappers import DNSWrapper
        dns = DNSWrapper()
        findings = []

        for method, label in [
            (dns.ns_lookup, "NS lookup"),
            (dns.srv_records, "SRV records"),
        ]:
            try:
                result = await method(target)
                if result.get("success"):
                    findings.append(Finding(
                        agent=self.name, goal_type=GoalType.RECON,
                        target=target, description=label,
                        severity="info",
                        evidence=str(result.get("records", result.get("lines", []))[:5]),
                    ))
            except Exception as e:
                logger.debug(f"[recon] {label} failed: {e}")

        return findings

    async def _run_whois(self, target: str) -> list[Finding]:
        from orchestrator.scanners.dns_wrappers import WhoIsWrapper
        whois = WhoIsWrapper()
        try:
            result = await whois.lookup(target)
            if result.get("registrant"):
                return [Finding(
                    agent=self.name, goal_type=GoalType.RECON,
                    target=target, description="WHOIS registrant info",
                    severity="info",
                    evidence=str(result["registrant"]),
                )]
        except Exception:
            logger.debug("Non-critical error", exc_info=True)
        return []

    async def _run_web_fingerprint(self, target: str) -> list[Finding]:
        from orchestrator.scanners.whatweb_scanner import WhatwebScanner
        ww = WhatwebScanner()
        try:
            result = ww.fingerprint(target)
            if result:
                return [Finding(
                    agent=self.name, goal_type=GoalType.RECON,
                    target=target, description="Web technology fingerprint",
                    severity="info",
                    evidence=str(result),
                )]
        except Exception:
            logger.debug("Non-critical error", exc_info=True)
        return []

    async def _run_subdomain_scan(self, target: str) -> list[Finding]:
        from orchestrator.scanners.gobuster_wrapper import GobusterWrapper
        gb = GobusterWrapper()
        try:
            result = await gb.dns(target)
            if result.get("subdomains"):
                return [Finding(
                    agent=self.name, goal_type=GoalType.RECON,
                    target=target, description=f"Subdomains: {result['count']} found",
                    severity="medium" if result["count"] > 5 else "low",
                    evidence=str(result["subdomains"][:20]),
                )]
        except Exception:
            logger.debug("Non-critical error", exc_info=True)
        return []

    async def _run_port_scan(self, target: str, ports: str = "1-1000") -> list[Finding]:
        from orchestrator.scanners.nmap_scanner import NmapScanner
        nmap = NmapScanner()
        try:
            result = nmap.scan_ports(target, ports=ports)
            open_ports = result.get("open_ports", {})
            if open_ports:
                evidence = "\n".join(
                    f"{port}/{info.get('service','?')}" for port, info in list(open_ports.items())[:30]
                )
                return [Finding(
                    agent=self.name, goal_type=GoalType.RECON,
                    target=target,
                    description=f"Port scan: {len(open_ports)} open ports",
                    severity="low",
                    evidence=evidence,
                )]
        except Exception:
            logger.debug("Non-critical error", exc_info=True)
        return []

    async def _run_directory_scan(self, target: str) -> list[Finding]:
        from orchestrator.scanners.gobuster_wrapper import GobusterWrapper
        gb = GobusterWrapper()
        try:
            result = await gb.dirs(target)
            if result.get("paths"):
                return [Finding(
                    agent=self.name, goal_type=GoalType.RECON,
                    target=target,
                    description=f"Directory scan: {result['count']} paths found",
                    severity="medium" if result["count"] > 10 else "low",
                    evidence=str(result["paths"][:30]),
                )]
        except Exception:
            logger.debug("Non-critical error", exc_info=True)
        return []

ReconAgent.max_iterations = 6
