import json, logging
from typing import Optional

from orchestrator.agents.base import (
    BaseAgent, GoalType, Task, AgentContext, Finding, ToolDef, Thought,
)
from orchestrator.events import EventBus, event_bus
from orchestrator.providers import call_model, resolve_persona_override

logger = logging.getLogger("scan_agent")

SCAN_PROMPT = (
    "You are a vulnerability analyst. Run the appropriate scanners based on recon results. "
    "Prioritize by likelihood of exploit.\n\n"
    "Available tools:\n"
    "  - service_scan: Nmap service version detection (-sV)\n"
    "  - vuln_scan: Nuclei vulnerability scanner (CVE templates)\n"
    "  - dir_scan: Gobuster directory enumeration\n"
    "  - ssl_scan: SSL/TLS certificate analysis\n\n"
    "Output ONLY valid JSON:\n"
    '{"actions": [{"tool": "tool_name", "args": {"target": "...", "ports": ["80","443"]}}]}\n\n'
    "Run service_scan first to identify versions, then vuln_scan on discovered services. "
    "Max 3 actions per cycle."
)

SCAN_TOOLS = {
    "service_scan": ToolDef(name="service_scan", description="Nmap service version detection (-sV)"),
    "vuln_scan": ToolDef(name="vuln_scan", description="Nuclei vulnerability scanner"),
    "dir_scan": ToolDef(name="dir_scan", description="Gobuster directory enumeration"),
    "ssl_scan": ToolDef(name="ssl_scan", description="SSL/TLS analysis"),
}


class ScanAgent(BaseAgent):
    name: str = "scan"
    system_prompt: str = SCAN_PROMPT
    tools: list[ToolDef] = list(SCAN_TOOLS.values())
    max_iterations: int = 10
    max_consecutive_failures: int = 2

    def __init__(self, bus: Optional[EventBus] = None, persona: str = ""):
        super().__init__(bus)
        self.persona = persona
        self._system_override = resolve_persona_override(persona) if persona else None

    async def think(self, task: Task, context: AgentContext,
                    system_override: Optional[str] = None) -> Thought:
        iteration = context.iteration
        scan_plan = [
            {"tool": "service_scan", "args": {"target": task.target}},
            {"tool": "vuln_scan", "args": {"target": task.target}},
            {"tool": "ssl_scan", "args": {"target": task.target}},
            {"tool": "dir_scan", "args": {"target": task.target}},
        ]

        if iteration <= len(scan_plan):
            return Thought(actions=[scan_plan[iteration - 1]], reasoning="Deterministic scan phase")
        else:
            return Thought(actions=[], reasoning="Scan complete")

    async def execute(self, action: dict) -> list[Finding]:
        tool = action.get("tool", "")
        args = action.get("args", {})
        target = args.get("target", "")
        findings = []

        try:
            if tool == "service_scan":
                findings = await self._run_service_scan(target, args.get("ports"))
            elif tool == "vuln_scan":
                findings = await self._run_vuln_scan(target, args.get("ports"))
            elif tool == "dir_scan":
                findings = await self._run_dir_scan(target)
            elif tool == "ssl_scan":
                findings = await self._run_ssl_scan(target)
            else:
                logger.warning(f"[scan] Unknown tool: {tool}")
        except Exception as e:
            logger.warning(f"[scan] Tool {tool} failed: {e}")

        return findings

    async def _run_service_scan(self, target: str, ports=None) -> list[Finding]:
        from orchestrator.scanners.nmap_scanner import NmapScanner
        nmap = NmapScanner()
        ports_str = ",".join(ports) if isinstance(ports, list) else (ports or "1-1000")
        try:
            result = nmap.scan_ports(target, ports=ports_str)
            open_ports = result.get("open_ports", {})
            if open_ports:
                lines = []
                for port, info in list(open_ports.items())[:50]:
                    svc = info.get("service", "?")
                    lines.append(f"  {port}/{svc}")
                return [Finding(
                    agent=self.name, goal_type=GoalType.SCAN,
                    target=target,
                    description=f"Service scan: {len(open_ports)} services on {target}",
                    severity="info",
                    evidence="\n".join(lines),
                )]
        except Exception:
            logger.debug("Non-critical error", exc_info=True)
        return []

    async def _run_vuln_scan(self, target: str, ports=None) -> list[Finding]:
        from orchestrator.scanners.nuclei_scanner import NucleiScanner
        ns = NucleiScanner()
        try:
            result = ns.scan(target, severity="medium,high,critical")
            findings_list = result.get("findings", [])
            if findings_list:
                return [Finding(
                    agent=self.name, goal_type=GoalType.SCAN,
                    target=target,
                    description=f"Nuclei: {len(findings_list)} vulnerabilities",
                    severity="high",
                    evidence=json.dumps(findings_list[:5], indent=2),
                )]
        except Exception:
            logger.debug("Non-critical error", exc_info=True)
        return []

    async def _run_dir_scan(self, target: str) -> list[Finding]:
        from orchestrator.scanners.gobuster_wrapper import GobusterWrapper
        gb = GobusterWrapper()
        try:
            result = await gb.dirs(target)
            if result.get("paths"):
                return [Finding(
                    agent=self.name, goal_type=GoalType.SCAN,
                    target=target,
                    description=f"Directory scan: {result['count']} paths",
                    severity="medium" if result["count"] > 5 else "low",
                    evidence=str(result["paths"][:30]),
                )]
        except Exception:
            logger.debug("Non-critical error", exc_info=True)
        return []

    async def _run_ssl_scan(self, target: str) -> list[Finding]:
        from orchestrator.kali_tools_client import kali
        try:
            result = await kali.run("sslscan", target, timeout=120)
            stdout = result.get("stdout", "")
            if "SSL" in stdout or "TLS" in stdout:
                lines = [l.strip() for l in stdout.split("\n") if "accepted" in l.lower() or "rejected" in l.lower()]
                return [Finding(
                    agent=self.name, goal_type=GoalType.SCAN,
                    target=target,
                    description="SSL/TLS cipher scan",
                    severity="low",
                    evidence=str(lines[:10]),
                )]
        except Exception:
            logger.debug("Non-critical error", exc_info=True)
        return []

ScanAgent.max_iterations = 4
