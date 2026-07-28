"""command_filter.py — Two-tier command filtering pipeline.

Tier 1: Static allowlist/regex matching (fast, deterministic, no LLM).
Tier 2: LLM intent classifier for ambiguous commands (ALLOW/ESCALATE/DENY).

ESCALATE decisions trigger FalsificationTask in the Planner before execution.
"""

import asyncio
import json
import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional, List, Dict

logger = logging.getLogger("interactive_shell.command_filter")


class FilterDecision(str, Enum):
    """Result of command filtering."""
    ALLOW = "allow"           # Command matches allowlist, execute immediately
    ESCALATE = "escalate"     # Ambiguous - requires LLM classification + falsification
    DENY = "deny"             # Explicitly denied, do not execute


@dataclass
class FilterResult:
    """Result of command filtering."""
    decision: FilterDecision
    matched_rule: str = ""           # Rule that matched (allowlist/denylist/classifier)
    confidence: float = 1.0          # Classifier confidence (0-1)
    reason: str = ""                 # Human-readable reason
    escalation_data: dict = field(default_factory=dict)  # For ESCALATE: {classifier_response, suggested_falsification}
    timestamp: float = field(default_factory=time.time)


class StaticAllowlist:
    """
    Tier 1: Fast static pattern matching.

    Uses compiled regex patterns for:
    - Allowlist: commands that are ALWAYS allowed (safe read-only)
    - Denylist: commands that are ALWAYS denied (destructive/dangerous)
    - Patterns: regex with capture groups for command + args validation
    """

    # Shell injection characters — commands containing these are escalated
    SHELL_INJECTION_RE = re.compile(r"[;&|`$()!]|\bexport\b|\bexec\b|\beval\b")

    # Core safe read-only commands (always allowed)
    DEFAULT_ALLOWLIST = [
        r"^ls\s+.*$",
        r"^cat\s+.*$",
        r"^head\s+.*$",
        r"^tail\s+.*$",
        r"^less\s+.*$",
        r"^more\s+.*$",
        r"^grep\s+.*$",
        r"^egrep\s+.*$",
        r"^fgrep\s+.*$",
        r"^awk\s+.*$",
        r"^sed\s+.*$",
        r"^cut\s+.*$",
        r"^sort\s+.*$",
        r"^uniq\s+.*$",
        r"^wc\s+.*$",
        r"^find\s+.*$",
        r"^locate\s+.*$",
        r"^which\s+.*$",
        r"^whereis\s+.*$",
        r"^file\s+.*$",
        r"^stat\s+.*$",
        r"^lsblk\s+.*$",
        r"^df\s+.*$",
        r"^du\s+.*$",
        r"^free\s+.*$",
        r"^free\s*$",
        r"^mount\s*$",
        r"^ps\s+.*$",
        r"^top\s*$",
        r"^htop\s*$",
        r"^netstat\s+.*$",
        r"^ss\s+.*$",
        r"^ip\s+.*$",
        r"^ifconfig\s*$",
        r"^route\s*$",
        r"^arp\s*$",
        r"^id\s*$",
        r"^whoami\s*$",
        r"^who\s*$",
        r"^w\s*$",
        r"^last\s+.*$",
        r"^uname\s+.*$",
        r"^hostname\s*$",
        r"^date\s*$",
        r"^uptime\s*$",
        r"^env\s*$",
        r"^printenv\s*$",
        r"^pwd\s*$",
        r"^echo\s+.*$",
        r"^printf\s+.*$",
        r"^history\s*$",
        r"^alias\s*$",
        r"^type\s+.*$",
        r"^command\s+.*$",
        r"^man\s+.*$",
        r"^info\s+.*$",
        r"^help\s*$",
        r"^exit\s*$",
        r"^logout\s*$",
        r"^clear\s*$",
        r"^reset\s*$",
    ]

    # Explicitly dangerous commands (always denied)
    DEFAULT_DENYLIST = [
        r"^rm\s+-rf\s+/",
        r"^rm\s+-rf\s+\*",
        r"^dd\s+.*of=/dev/",
        r"^mkfs",
        r"^fdisk\s+.*",
        r"^parted\s+.*",
        r"^shutdown\s+.*",
        r"^reboot\s*$",
        r"^halt\s*$",
        r"^poweroff\s*$",
        r"^kill\s+-9\s+1\s*$",
        r"^killall\s+-9\s+.*",
        r"^pkill\s+-9\s+.*",
        r">\s*/dev/sd",
        r">\s*/dev/mapper/",
        r"chmod\s+-R\s+777\s+/",
        r"chown\s+-R\s+.*\s+/",
        r"^:(){ :|:& };:",  # fork bomb
        r"^wget\s+.*\|\s*(sh|bash)",
        r"^curl\s+.*\|\s*(sh|bash)",
        r"^nc\s+-e\s+/bin/(sh|bash)",
        r"^python\s+-c\s+.*socket.*connect",
        r"^perl\s+-e\s+.*socket.*connect",
        r"^php\s+-r\s+.*fsockopen",
        r"^ruby\s+-rsocket\s+-e",
        r"^bash\s+-i\s+>&\s+/dev/tcp/",
        r"^0<&\d+;exec\s+\d+<>/dev/tcp/",
        r"^exec\s+\d+<>/dev/tcp/",
        r"^socat\s+.*EXEC:.*sh",
    ]

    def __init__(
        self,
        custom_allowlist: Optional[List[str]] = None,
        custom_denylist: Optional[List[str]] = None,
        allow_pattern: str = "",
    ):
        """
        Args:
            custom_allowlist: Additional regex patterns to allow
            custom_denylist: Additional regex patterns to deny
            allow_pattern: Single regex pattern from session config (takes priority)
        """
        self.allow_patterns = [re.compile(p, re.IGNORECASE) for p in self.DEFAULT_ALLOWLIST]
        self.deny_patterns = [re.compile(p, re.IGNORECASE) for p in self.DEFAULT_DENYLIST]

        if custom_allowlist:
            self.allow_patterns.extend([re.compile(p, re.IGNORECASE) for p in custom_allowlist])

        if custom_denylist:
            self.deny_patterns.extend([re.compile(p, re.IGNORECASE) for p in custom_denylist])

        self.session_allow_pattern = None
        if allow_pattern:
            try:
                self.session_allow_pattern = re.compile(allow_pattern, re.IGNORECASE)
            except re.error as e:
                logger.warning("Invalid session allow_pattern: %s", e)

    def check(self, command: str) -> FilterResult:
        """
        Check command against static patterns.

        Returns:
            FilterResult with ALLOW, DENY, or ESCALATE (if no match)
        """
        cmd = command.strip()

        # 1. Session-specific allow pattern (highest priority)
        if self.session_allow_pattern and self.session_allow_pattern.match(cmd):
            return FilterResult(
                decision=FilterDecision.ALLOW,
                matched_rule="session_allow_pattern",
                reason=f"Matches session allow pattern",
            )

        # 2. Explicit denylist (safety first)
        for pattern in self.deny_patterns:
            if pattern.search(cmd):
                return FilterResult(
                    decision=FilterDecision.DENY,
                    matched_rule=f"denylist:{pattern.pattern[:50]}",
                    reason=f"Command matches denylist pattern",
                )

        # 3. Shell injection character check
        # Commands with ; | & ` $() or other shell metacharacters are
        # escalated to prevent chained command injection.
        if self.SHELL_INJECTION_RE.search(cmd):
            return FilterResult(
                decision=FilterDecision.ESCALATE,
                matched_rule="shell_injection_chars",
                reason="Command contains shell metacharacters (; | & ` $) or control keywords",
            )

        # 4. Allowlist
        for pattern in self.allow_patterns:
            if pattern.match(cmd):
                return FilterResult(
                    decision=FilterDecision.ALLOW,
                    matched_rule=f"allowlist:{pattern.pattern[:50]}",
                    reason=f"Command matches safe allowlist pattern",
                )

        # 4. No match -> escalate to LLM
        return FilterResult(
            decision=FilterDecision.ESCALATE,
            matched_rule="no_static_match",
            reason="Command does not match allowlist or denylist",
        )


class LLMIntentClassifier:
    """
    Tier 2: LLM-based intent classification for ambiguous commands.

    Uses the same LLM provider as the D-series (bjoernb/gemma4-31b-think:latest)
    but with a specialized prompt for command safety classification.

    Output: ALLOW / ESCALATE / DENY with confidence and rationale.
    """

    CLASSIFIER_PROMPT = """You are a security classifier for interactive shell commands.
Your task: classify the command as ALLOW, ESCALATE, or DENY.

CONTEXT:
- This is an authorized penetration testing session
- Target: {target}
- Current directory: {cwd}
- User: {username}
- Recent commands: {recent_commands}

CLASSIFICATION RULES:
ALLOW - Read-only, informational, safe navigation, standard admin inspection:
  ls, cat, grep, find, ps, netstat, ss, ip, id, whoami, uname, df, du, mount
  file, stat, which, history, env, pwd, echo, man, less, head, tail, awk, sed
  (and their safe variations with args)

ESCALATE - Ambiguous, potentially dangerous, requires human/automated review:
  - Commands with redirection to sensitive paths (/etc/, /boot/, /dev/, /proc/sys/)
  - Commands modifying system config: systemctl, service, iptables, nft, ufw
  - Package managers: apt, yum, dnf, pip, npm, gem (install/remove)
  - User/group management: useradd, usermod, groupadd, passwd, chage
  - Permission changes: chmod, chown, chattr, setfacl on system dirs
  - Scheduled tasks: crontab, at, systemd timers
  - Network config changes: ip link, ip addr, route, dhclient
  - Kernel modules: modprobe, insmod, rmmod
  - Archive extraction to sensitive locations: tar -x, unzip to /etc, /var, /root
  - Script execution from untrusted sources: curl/wget | sh, python -c from URL

DENY - Clearly malicious, destructive, or out-of-scope:
  - Disk destruction: dd to /dev/sd*, mkfs, wipefs, shred on disks
  - Firmware/BIOS flashing
  - Kernel panic triggers: echo c > /proc/sysrq-trigger
  - Fork bombs, resource exhaustion
  - Credential dumping tools: mimikatz, gsecdump, secretsdump (unless explicitly scoped)
  - Lateral movement: psexec, wmiexec, smbexec, winrm (unless scoped)
  - Ransomware-like: mass encryption, file extension changes
  - Covering tracks: log deletion, timestamp manipulation, history clearing

OUTPUT FORMAT (JSON only):
{{
  "decision": "ALLOW|ESCALATE|DENY",
  "confidence": 0.0-1.0,
  "reason": "Brief explanation",
  "suggested_falsification": "If ESCALATE, what hypothesis should be tested before allowing?"
}}

Command to classify: {command}
"""

    def __init__(
        self,
        llm_provider=None,
        model: str = "bjoernb/gemma4-31b-think:latest",
        timeout: float = 10.0,
    ):
        self.llm_provider = llm_provider
        self.model = model
        self.timeout = timeout
        self._cache: Dict[str, FilterResult] = {}

    def set_provider(self, provider):
        """Set LLM provider (e.g., from orchestrator.llm)."""
        self.llm_provider = provider

    async def classify(
        self,
        command: str,
        context: dict = None,
    ) -> FilterResult:
        """Classify command using LLM."""
        cache_key = command.strip()
        if cache_key in self._cache:
            return self._cache[cache_key]

        if not self.llm_provider:
            # No LLM available - conservative default
            return FilterResult(
                decision=FilterDecision.ESCALATE,
                confidence=0.0,
                reason="No LLM provider configured",
                escalation_data={"error": "llm_unavailable"},
            )

        context = context or {}
        prompt = self.CLASSIFIER_PROMPT.format(
            target=context.get("target", "unknown"),
            cwd=context.get("cwd", "/"),
            username=context.get("username", "unknown"),
            recent_commands=context.get("recent_commands", "none"),
            command=command,
        )

        try:
            response = await asyncio.wait_for(
                self._call_llm(prompt),
                timeout=self.timeout,
            )
            result = self._parse_response(response, command)
            self._cache[cache_key] = result
            return result

        except asyncio.TimeoutError:
            logger.warning("LLM classifier timeout for command: %s", command[:50])
            return FilterResult(
                decision=FilterDecision.ESCALATE,
                confidence=0.0,
                reason="LLM classification timeout",
                escalation_data={"error": "timeout"},
            )
        except Exception as e:
            logger.error("LLM classifier error: %s", e)
            return FilterResult(
                decision=FilterDecision.ESCALATE,
                confidence=0.0,
                reason=f"LLM classifier error: {e}",
                escalation_data={"error": str(e)},
            )

    async def _call_llm(self, prompt: str) -> str:
        """Call LLM provider. Override or inject provider."""
        # Default: try to use a simple HTTP call or injected provider
        if hasattr(self.llm_provider, "generate"):
            return await self.llm_provider.generate(prompt, model=self.model)
        elif hasattr(self.llm_provider, "__call__"):
            return await self.llm_provider(prompt)
        else:
            raise RuntimeError("LLM provider not configured")

    def _parse_response(self, response: str, command: str) -> FilterResult:
        """Parse LLM JSON response."""
        try:
            # Extract JSON from response (may have markdown code fences)
            json_match = re.search(r"\{.*\}", response, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
            else:
                data = json.loads(response)

            decision_str = data.get("decision", "ESCALATE").upper()
            decision = FilterDecision(decision_str.lower()) if decision_str.lower() in ["allow", "escalate", "deny"] else FilterDecision.ESCALATE

            return FilterResult(
                decision=decision,
                confidence=float(data.get("confidence", 0.5)),
                reason=data.get("reason", "LLM classification"),
                escalation_data={
                    "suggested_falsification": data.get("suggested_falsification", ""),
                    "llm_response": response[:500],
                },
            )

        except (json.JSONDecodeError, ValueError) as e:
            logger.warning("Failed to parse LLM response: %s", e)
            return FilterResult(
                decision=FilterDecision.ESCALATE,
                confidence=0.0,
                reason=f"LLM response parse error: {e}",
                escalation_data={"error": "parse_error", "raw_response": response[:500]},
            )


class CommandFilterPipeline:
    """
    Two-tier command filtering pipeline.

    Flow:
        1. StaticAllowlist.check() -> ALLOW/DENY/ESCALATE
        2. If ESCALATE: LLMIntentClassifier.classify() -> ALLOW/ESCALATE/DENY
        3. If still ESCALATE: return ESCALATE (requires FalsificationTask)
    """

    def __init__(
        self,
        session_allow_pattern: str = "",
        custom_allowlist: List[str] = None,
        custom_denylist: List[str] = None,
        llm_provider=None,
        llm_model: str = "bjoernb/gemma4-31b-think:latest",
    ):
        self.static = StaticAllowlist(
            custom_allowlist=custom_allowlist,
            custom_denylist=custom_denylist,
            allow_pattern=session_allow_pattern,
        )
        self.llm = LLMIntentClassifier(
            llm_provider=llm_provider,
            model=llm_model,
        )
        self._stats = {
            "total": 0,
            "allow_static": 0,
            "deny_static": 0,
            "escalate_static": 0,
            "allow_llm": 0,
            "deny_llm": 0,
            "escalate_llm": 0,
        }

    async def filter(
        self,
        command: str,
        context: dict = None,
    ) -> FilterResult:
        """
        Run command through filtering pipeline.

        Returns:
            FilterResult with final decision
        """
        self._stats["total"] += 1

        # Tier 1: Static
        static_result = self.static.check(command)

        if static_result.decision == FilterDecision.ALLOW:
            self._stats["allow_static"] += 1
            return static_result

        if static_result.decision == FilterDecision.DENY:
            self._stats["deny_static"] += 1
            return static_result

        # Tier 2: LLM (only if static escalated)
        self._stats["escalate_static"] += 1
        llm_result = await self.llm.classify(command, context)

        if llm_result.decision == FilterDecision.ALLOW:
            self._stats["allow_llm"] += 1
        elif llm_result.decision == FilterDecision.DENY:
            self._stats["deny_llm"] += 1
        else:
            self._stats["escalate_llm"] += 1

        # Merge results: LLM decision is final unless it also escalates
        final_result = FilterResult(
            decision=llm_result.decision,
            matched_rule=f"llm:{llm_result.matched_rule}",
            confidence=llm_result.confidence,
            reason=llm_result.reason,
            escalation_data={
                **llm_result.escalation_data,
                "static_result": {
                    "decision": static_result.decision.value,
                    "matched_rule": static_result.matched_rule,
                },
            },
        )

        return final_result

    def get_stats(self) -> dict:
        return dict(self._stats)

    def reset_stats(self):
        self._stats = {k: 0 for k in self._stats}


# ── Pre-configured pipelines for common use cases ─────────────────

def create_standard_pipeline(
    session_allow_pattern: str = "",
    llm_provider=None,
) -> CommandFilterPipeline:
    """Standard pipeline for authorized pentest sessions."""
    return CommandFilterPipeline(
        session_allow_pattern=session_allow_pattern,
        llm_provider=llm_provider,
    )


def create_restricted_pipeline(
    session_allow_pattern: str = "",
    additional_denylist: List[str] = None,
    llm_provider=None,
) -> CommandFilterPipeline:
    """More restrictive pipeline with extra denylist entries."""
    return CommandFilterPipeline(
        session_allow_pattern=session_allow_pattern,
        custom_denylist=additional_denylist or [],
        llm_provider=llm_provider,
    )