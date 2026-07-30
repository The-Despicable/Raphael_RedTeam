"""capability_broker.py — Minimal Capability Broker (deny-by-default enforcement).

The CapabilityBroker is the SINGLE gate through which ALL external side effects pass.
No executor, no tool, no module may produce an external effect without going through
the broker.

Architecture:
    Executor
        │
        ▼
    ActionProposal
        │
        ▼
    ╔══════════════════════════════════════╗
    ║        CAPABILITY BROKER            ║
    ║                                     ║
    ║  ScopeBoundary  ──►  Target check   ║
    ║  RoE            ──►  Action class   ║
    ║  Capability     ──►  Tool perm      ║
    ║  RateLimit      ──►  Budget check   ║
    ║  ImpactClass    ──►  Risk check     ║
    ║                                     ║
    ║         ALLOW / DENY                ║
    ╚══════════════════════════════════════╝
        │
        ▼
    ToolAdapter (HTTP, subprocess, Docker, etc.)
        │
        ▼
    External World

DENY-BY-DEFAULT: Every check must explicitly return True. Any missing/failed
check = DENY.

Schema version: 1
"""

import time
import uuid
import json
import hashlib
import logging
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Callable, Optional

from orchestrator.brain.rate_limiter import RateLimiter, RateLimiterConfig, ShellKeepAlive
from orchestrator.brain.scope_parser import ScopeParser

# Optional P1 imports (guarded)
try:
    from orchestrator.student.payload_mutator import PayloadMutator
    HAS_PAYLOAD_MUTATOR = True
except ImportError:
    HAS_PAYLOAD_MUTATOR = False
    PayloadMutator = None

try:
    from orchestrator.student.student import Student
    HAS_STUDENT = True
except ImportError:
    HAS_STUDENT = False
    Student = None

from orchestrator.hardening.action_receipt import (
    ActionReceipt, ActionProposalStatus, create_proposal, authorize, deny,
    start_execution, complete_execution, timeout_execution, get_receipt, verify_chain,
)

# E1 Shell imports
from orchestrator.capabilities.interactive_shell.session import (
    ShellSession,
    ShellSessionProposal,
    ShellSessionStatus,
    SessionReceipt,
    CommandReceipt,
    CommandFilterDecision,
    ShellSessionStore,
    TerminationReceipt,
)
from orchestrator.capabilities.interactive_shell.listener_manager import get_listener_manager
from orchestrator.capabilities.interactive_shell.command_filter import CommandFilterPipeline, FilterDecision

logger = logging.getLogger("capability_broker")

# ── Authorization Dimensions ────────────────────────────────────

class AuthorizationDimension(str, Enum):
    """Five independent authorization checks that ALL must pass."""
    TARGET_AUTHORIZATION = "target_authorization"      # Is this target in scope?
    ROE_AUTHORIZATION = "roe_authorization"            # Is this action class permitted by RoE?
    CAPABILITY_AUTHORIZATION = "capability_authorization"  # Is this tool/method permitted?
    RATE_AUTHORIZATION = "rate_authorization"          # Within rate limits?
    IMPACT_AUTHORIZATION = "impact_authorization"      # Impact within budget?


class AuthorizationDecision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


@dataclass
class AuthorizationCheck:
    """Result of a single authorization dimension check."""
    dimension: AuthorizationDimension
    decision: AuthorizationDecision
    reason: str
    metadata: dict = field(default_factory=dict)


@dataclass
class BrokerPolicy:
    """
    Complete engagement policy for the CapabilityBroker.
    
    This is the SINGLE SOURCE OF TRUTH for what is permitted.
    """
    schema_version: int = 1
    engagement_id: str = ""
    
    # ── Scope (Target Authorization) ────────────────────────────
    allowed_targets: list[str] = field(default_factory=list)      # CIDR, hostname, ARN
    prohibited_targets: list[str] = field(default_factory=list)   # Explicit deny list
    
    # ── Rules of Engagement (RoE) ───────────────────────────────
    allowed_action_types: list[str] = field(default_factory=list)     # e.g., ["recon", "scan", "exploit"]
    prohibited_action_types: list[str] = field(default_factory=list)  # Explicit deny
    
    # ── Capability Authorization ─────────────────────────────────
    allowed_capabilities: list[str] = field(default_factory=list)     # Tool/method names
    prohibited_capabilities: list[str] = field(default_factory=list)  # Explicit deny
    
    # ── Rate Limits ──────────────────────────────────────────────
    max_actions_per_minute: int = 60
    max_actions_per_hour: int = 1000
    max_concurrent: int = 5
    
    # ── Impact Budget ────────────────────────────────────────────
    max_impact_per_action: float = 5.0      # 0-10 scale
    max_cumulative_impact: float = 50.0     # Per engagement
    high_impact_requires_approval: bool = True  # > max_impact_per_action needs explicit approval
    
    # ── Time Windows ─────────────────────────────────────────────
    engagement_start: float = field(default_factory=time.time)
    engagement_end: float = 0.0             # 0 = no end
    
    # ── Metadata ─────────────────────────────────────────────────
    created_by: str = ""
    created_at: float = field(default_factory=time.time)
    version: int = 1

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "engagement_id": self.engagement_id,
            "allowed_targets": self.allowed_targets,
            "prohibited_targets": self.prohibited_targets,
            "allowed_action_types": self.allowed_action_types,
            "prohibited_action_types": self.prohibited_action_types,
            "allowed_capabilities": self.allowed_capabilities,
            "prohibited_capabilities": self.prohibited_capabilities,
            "max_actions_per_minute": self.max_actions_per_minute,
            "max_actions_per_hour": self.max_actions_per_hour,
            "max_concurrent": self.max_concurrent,
            "max_impact_per_action": self.max_impact_per_action,
            "max_cumulative_impact": self.max_cumulative_impact,
            "high_impact_requires_approval": self.high_impact_requires_approval,
            "engagement_start": self.engagement_start,
            "engagement_end": self.engagement_end,
            "created_by": self.created_by,
            "created_at": self.created_at,
            "version": self.version,
        }
    
    def is_target_allowed(self, target: str) -> tuple[bool, str]:
        """Check if target is within allowed scope and not prohibited."""
        if not self.allowed_targets:
            # Empty allowed list = deny all unless explicitly configured
            return False, "No allowed targets configured"
        
        # Check prohibited first (explicit deny always wins)
        for prohibited in self.prohibited_targets:
            if self._target_matches(target, prohibited):
                return False, f"Target explicitly prohibited: {prohibited}"
        
        # Check allowed
        for allowed in self.allowed_targets:
            if self._target_matches(target, allowed):
                return True, f"Target allowed by: {allowed}"
        
        return False, f"Target not in allowed scope: {self.allowed_targets}"
    
    def _target_matches(self, target: str, pattern: str) -> bool:
        """Match target against pattern (supports CIDR, wildcards, exact)."""
        # Exact match
        if target == pattern:
            return True
        # CIDR match (if pattern contains /)
        if '/' in pattern:
            import ipaddress
            try:
                net = ipaddress.ip_network(pattern, strict=False)
                ip = ipaddress.ip_address(target)
                return ip in net
            except ValueError:
                pass
        # Wildcard prefix match (e.g., "10.0.*" or "*.example.com")
        if '*' in pattern:
            import fnmatch
            return fnmatch.fnmatch(target, pattern)
        return False

    def is_action_type_allowed(self, action_type: str) -> tuple[bool, str]:
        if action_type in self.prohibited_action_types:
            return False, f"Action type explicitly prohibited: {action_type}"
        if not self.allowed_action_types:
            return False, "No action types allowed (empty allowed list)"
        if action_type in self.allowed_action_types:
            return True, f"Action type allowed: {action_type}"
        return False, f"Action type not in allowed list: {action_type}"

    def is_capability_allowed(self, capability: str) -> tuple[bool, str]:
        if capability in self.prohibited_capabilities:
            return False, f"Capability explicitly prohibited: {capability}"
        if not self.allowed_capabilities:
            return False, "No capabilities allowed (empty allowed list)"
        if capability in self.allowed_capabilities:
            return True, f"Capability allowed: {capability}"
        return False, f"Capability not in allowed list: {capability}"

    def check_rate_limits(self, recent_count_minute: int, recent_count_hour: int, 
                          concurrent: int) -> tuple[bool, str]:
        if recent_count_minute >= self.max_actions_per_minute:
            return False, f"Per-minute rate limit exceeded: {recent_count_minute}/{self.max_actions_per_minute}"
        if recent_count_hour >= self.max_actions_per_hour:
            return False, f"Per-hour rate limit exceeded: {recent_count_hour}/{self.max_actions_per_hour}"
        if concurrent >= self.max_concurrent:
            return False, f"Concurrency limit exceeded: {concurrent}/{self.max_concurrent}"
        return True, "Rate limits OK"

    def check_impact(self, action_impact: float, cumulative_impact: float) -> tuple[bool, str]:
        if action_impact > self.max_impact_per_action:
            if self.high_impact_requires_approval:
                return False, f"Impact {action_impact} exceeds per-action limit {self.max_impact_per_action} (requires explicit approval)"
            return False, f"Impact {action_impact} exceeds per-action limit {self.max_impact_per_action}"
        if cumulative_impact + action_impact > self.max_cumulative_impact:
            return False, f"Cumulative impact would exceed budget: {cumulative_impact} + {action_impact} > {self.max_cumulative_impact}"
        return True, "Impact within budget"

    def is_within_time_window(self) -> tuple[bool, str]:
        now = time.time()
        if now < self.engagement_start:
            return False, "Engagement has not started yet"
        if self.engagement_end > 0 and now > self.engagement_end:
            return False, "Engagement has ended"
        return True, "Within engagement time window"


# ── CapabilityBroker ────────────────────────────────────────────

class CapabilityBroker:
    """
    The CapabilityBroker is the SINGLE GATE for all external side effects.
    
    Every external action MUST go through:
        broker.propose_action(...) -> AuthorizationDecision
        
    No executor, tool, or module may bypass the broker.
    """
    
    def __init__(
        self, 
        policy: BrokerPolicy,
        rate_limiter: Optional[RateLimiter] = None,
        scope_parser: Optional[ScopeParser] = None,
        payload_mutator: Optional[Any] = None,
        student: Optional[Any] = None,
    ):
        self.policy = policy
        self.rate_limiter = rate_limiter
        self.scope_parser = scope_parser
        self.payload_mutator = payload_mutator
        self.student = student
        self.receipt_store: dict[str, ActionReceipt] = {}
        self._rate_tracker: dict[str, list[float]] = {}  # target -> [timestamps]
        self._concurrent_count: int = 0
        self._cumulative_impact: float = 0.0
        self._action_log: list[dict] = []

        # E1 Shell extensions
        from orchestrator.capabilities.interactive_shell.session import ShellSessionStore
        from orchestrator.capabilities.interactive_shell.command_filter import CommandFilterPipeline
        from orchestrator.capabilities.interactive_shell.listener_manager import get_listener_manager
        self._shell_sessions: dict[str, ShellSession] = {}
        self._shell_session_store = ShellSessionStore()
        self._command_filter = CommandFilterPipeline()
        self._listener_manager = get_listener_manager()

        logger.info(f"CapabilityBroker initialized for engagement {policy.engagement_id}")

    # ── Main Entry Point ────────────────────────────────────────

    def propose_action(
        self,
        target: str,
        action_type: str,
        capability: str,
        method: str,
        impact_estimate: float,
        metadata: dict = None,
    ) -> ActionReceipt:
        """
        Propose an action and get an authorization decision.
        
        This is the MAIN ENTRY POINT. Returns an ActionReceipt that tracks
        the entire lifecycle: PROPOSED -> AUTHORIZED/DENIED -> STARTED -> SUCCEEDED/FAILED.
        """
        # 1. Create initial proposal receipt
        receipt = create_proposal(
            target=target,
            capability=capability,
            method=method,
            impact_estimate=impact_estimate,
        )
        receipt.metadata = metadata or {}
        receipt.metadata["action_type"] = action_type
        receipt.metadata["impact_estimate"] = impact_estimate
        
        # 2. Run ALL authorization checks
        checks = self._run_all_checks(target, action_type, capability, method, impact_estimate)
        
        # 3. Aggregate decision
        all_allow = all(c.decision == AuthorizationDecision.ALLOW for c in checks)
        
        if all_allow:
            receipt = authorize(
                receipt, 
                reason=self._aggregate_reasons(checks),
                policy_version=str(self.policy.version),
                authorized_by="capability_broker",
            )
            logger.info(f"ALLOWED: {action_type} on {target} via {capability}")
            
            # 3b. Apply RateLimiter delay if configured
            if self.rate_limiter:
                # Determine target type for rate limiting
                target_type = "web"
                if "shell" in capability.lower() or "ssh" in capability.lower():
                    target_type = "shell"
                elif "dns" in capability.lower():
                    target_type = "dns"
                
                allowed, reason, delay = self.rate_limiter.authorize_with_delay(
                    target=target,
                    action_type=action_type,
                    target_type=target_type
                )
                if not allowed:
                    # Rate limiter denied - update receipt
                    receipt = deny(
                        receipt,
                        reason=f"RateLimiter denied: {reason}",
                        policy_version=str(self.policy.version),
                        authorized_by="capability_broker",
                    )
                    logger.warning(f"RATE LIMIT DENIED: {action_type} on {target} — {reason}")
                    return receipt
                logger.debug(f"RateLimiter delay applied: {delay:.2f}s for {target}")
        else:
            deny_reasons = [c.reason for c in checks if c.decision == AuthorizationDecision.DENY]
            receipt = deny(
                receipt,
                reason="; ".join(deny_reasons),
                policy_version=str(self.policy.version),
                authorized_by="capability_broker",
            )
            logger.warning(f"DENIED: {action_type} on {target} — {deny_reasons}")
        
        # 4. Store receipt
        self.receipt_store[receipt.action_id] = receipt
        self._log_action(receipt, checks)
        
        return receipt

    def _run_all_checks(
        self, target: str, action_type: str, capability: str, 
        method: str, impact_estimate: float,
    ) -> list:
        """Run all five authorization dimension checks."""
        checks = []
        
        # 1. Target Authorization - use ScopeParser if available
        if self.scope_parser:
            allowed, reason = self.scope_parser.is_target_allowed(target)
        else:
            allowed, reason = self.policy.is_target_allowed(target)
        checks.append(AuthorizationCheck(
            dimension=AuthorizationDimension.TARGET_AUTHORIZATION,
            decision=AuthorizationDecision.ALLOW if allowed else AuthorizationDecision.DENY,
            reason=reason,
            metadata={"target": target},
        ))
        
        # 2. RoE Authorization (action type)
        allowed, reason = self.policy.is_action_type_allowed(action_type)
        checks.append(AuthorizationCheck(
            dimension=AuthorizationDimension.ROE_AUTHORIZATION,
            decision=AuthorizationDecision.ALLOW if allowed else AuthorizationDecision.DENY,
            reason=reason,
            metadata={"action_type": action_type},
        ))
        
        # 3. Capability Authorization
        allowed, reason = self.policy.is_capability_allowed(capability)
        checks.append(AuthorizationCheck(
            dimension=AuthorizationDimension.CAPABILITY_AUTHORIZATION,
            decision=AuthorizationDecision.ALLOW if allowed else AuthorizationDecision.DENY,
            reason=reason,
            metadata={"capability": capability, "method": method},
        ))
        
        # 4. Rate Authorization - use RateLimiter if available
        if self.rate_limiter:
            # Map capability to target_type
            target_type = "web"
            if "shell" in capability.lower() or "ssh" in capability.lower():
                target_type = "shell"
            elif "dns" in capability.lower():
                target_type = "dns"
            
            # Note: RateLimiter delay is applied in propose_action, not here
            # This check just verifies limits aren't exceeded
            recent_minute = self._count_recent_actions(60)
            recent_hour = self._count_recent_actions(3600)
            allowed, reason = self.policy.check_rate_limits(
                recent_count_minute=recent_minute,
                recent_count_hour=recent_hour,
                concurrent=self._concurrent_count,
            )
            if not allowed:
                reason = f"RateLimiter: {reason}"
        else:
            recent_minute = self._count_recent_actions(60)
            recent_hour = self._count_recent_actions(3600)
            allowed, reason = self.policy.check_rate_limits(
                recent_count_minute=recent_minute,
                recent_count_hour=recent_hour,
                concurrent=self._concurrent_count,
            )
        checks.append(AuthorizationCheck(
            dimension=AuthorizationDimension.RATE_AUTHORIZATION,
            decision=AuthorizationDecision.ALLOW if allowed else AuthorizationDecision.DENY,
            reason=reason,
            metadata={
                "recent_minute": recent_minute,
                "recent_hour": recent_hour,
                "concurrent": self._concurrent_count,
            },
        ))
        
        # 4b. Engagement time window
        allowed, reason = self.policy.is_within_time_window()
        if not allowed:
            checks.append(AuthorizationCheck(
                dimension=AuthorizationDimension.RATE_AUTHORIZATION,
                decision=AuthorizationDecision.DENY,
                reason=reason,
                metadata={},
            ))
        
        # 5. Impact Authorization
        allowed, reason = self.policy.check_impact(impact_estimate, self._cumulative_impact)
        checks.append(AuthorizationCheck(
            dimension=AuthorizationDimension.IMPACT_AUTHORIZATION,
            decision=AuthorizationDecision.ALLOW if allowed else AuthorizationDecision.DENY,
            reason=reason,
            metadata={
                "action_impact": impact_estimate,
                "cumulative_impact": self._cumulative_impact,
            },
        ))
        
        return checks

    def _aggregate_reasons(self, checks: list) -> str:
        return " | ".join(f"{c.dimension.value}: {c.reason}" for c in checks)

    def _count_recent_actions(self, window_seconds: int) -> int:
        """Count actions in the last window_seconds."""
        now = time.time()
        cutoff = now - window_seconds
        count = 0
        for ts_list in self._rate_tracker.values():
            count += sum(1 for ts in ts_list if ts > cutoff)
        return count

    def _log_action(self, receipt: ActionReceipt, checks: list):
        self._action_log.append({
            "timestamp": time.time(),
            "action_id": receipt.action_id,
            "target": receipt.target,
            "capability": receipt.capability,
            "decision": receipt.decision,
            "checks": [asdict(c) for c in checks],
        })

    # ── Execution Lifecycle ────────────────────────────────────

    def start_execution(self, receipt: ActionReceipt) -> ActionReceipt:
        """Mark action as STARTED and update rate/concurrency tracking."""
        receipt = start_execution(receipt)
        
        # Update rate tracker
        if receipt.target not in self._rate_tracker:
            self._rate_tracker[receipt.target] = []
        self._rate_tracker[receipt.target].append(time.time())
        
        # Update concurrency
        self._concurrent_count += 1
        
        self.receipt_store[receipt.action_id] = receipt
        return receipt

    def complete_execution(
        self, receipt: ActionReceipt, success: bool, 
        result: str, evidence_ids: list[str] = None,
    ) -> ActionReceipt:
        """Mark action as completed (succeeded/failed/timeout)."""
        if success:
            receipt = complete_execution(receipt, success=True, result=result, evidence_ids=evidence_ids)
            # Update cumulative impact
            # Note: impact was estimated at proposal time
            self._cumulative_impact += receipt.metadata.get("impact_estimate", 0)
        else:
            receipt = complete_execution(receipt, success=False, result=result, evidence_ids=evidence_ids)
        
        # Decrement concurrency
        self._concurrent_count = max(0, self._concurrent_count - 1)
        
        self.receipt_store[receipt.action_id] = receipt
        return receipt

    def timeout_execution(self, receipt: ActionReceipt, result: str = "") -> ActionReceipt:
        """Mark action as timed out."""
        receipt = timeout_execution(receipt, result=result)
        self._concurrent_count = max(0, self._concurrent_count - 1)
        self.receipt_store[receipt.action_id] = receipt
        return receipt

    # ── Tool Adapters ──────────────────────────────────────────

    def create_tool_adapter(self, tool_name: str) -> 'ToolAdapter':
        """Create a tool adapter that enforces broker authorization."""
        return ToolAdapter(self, tool_name)

    # ── Inspection ─────────────────────────────────────────────

    def get_receipt(self, action_id: str) -> ActionReceipt | None:
        return self.receipt_store.get(action_id)

    def verify_all_receipts(self) -> list[dict]:
        return verify_chain()

    def get_action_log(self) -> list[dict]:
        return self._action_log.copy()

    def get_cumulative_impact(self) -> float:
        return self._cumulative_impact

    def get_rate_status(self) -> dict:
        now = time.time()
        return {
            "per_minute": sum(len([ts for ts in ts_list if ts > now - 60]) for ts_list in self._rate_tracker.values()),
            "per_hour": sum(len([ts for ts in ts_list if ts > now - 3600]) for ts_list in self._rate_tracker.values()),
            "concurrent": self._concurrent_count,
            "cumulative_impact": self._cumulative_impact,
        }

    # ── E1 Shell Session Authorization ────────────────────────────

    def authorize_shell_session(self, proposal: ShellSessionProposal) -> SessionReceipt:
        """
        Authorize a new interactive shell session.

        This is the dual-gate entry point for shell sessions:
        1. Validates scope, capability, egress constraints
        2. Creates ShellSession in AUTHORIZED state
        3. Provisions reverse shell listener (if reverse_tcp)
        4. Returns SessionReceipt with listener info
        """
        session_id = f"shell_{uuid.uuid4().hex[:12]}"
        session = ShellSession.from_proposal(proposal, session_id)

        # Run authorization checks
        checks = []

        # 1. Target authorization
        allowed, reason = self.policy.is_target_allowed(proposal.target)
        checks.append(AuthorizationCheck(
            dimension=AuthorizationDimension.TARGET_AUTHORIZATION,
            decision=AuthorizationDecision.ALLOW if allowed else AuthorizationDecision.DENY,
            reason=reason,
            metadata={"target": proposal.target, "check": "shell_session"},
        ))

        # 2. Capability authorization
        cap_name = f"shell_{proposal.capability_type.value}"
        allowed, reason = self.policy.is_capability_allowed(cap_name)
        checks.append(AuthorizationCheck(
            dimension=AuthorizationDimension.CAPABILITY_AUTHORIZATION,
            decision=AuthorizationDecision.ALLOW if allowed else AuthorizationDecision.DENY,
            reason=reason,
            metadata={"capability": cap_name},
        ))

        # 3. Rate limits
        allowed, reason = self.policy.check_rate_limits(
            recent_count_minute=self._count_recent_actions(60),
            recent_count_hour=self._count_recent_actions(3600),
            concurrent=self._concurrent_count,
        )
        checks.append(AuthorizationCheck(
            dimension=AuthorizationDimension.RATE_AUTHORIZATION,
            decision=AuthorizationDecision.ALLOW if allowed else AuthorizationDecision.DENY,
            reason=reason,
            metadata={"session_type": "shell"},
        ))

        # 4. Impact check
        allowed, reason = self.policy.check_impact(
            action_impact=proposal.metadata.get("impact_estimate", 5.0),
            cumulative_impact=self._cumulative_impact,
        )
        checks.append(AuthorizationCheck(
            dimension=AuthorizationDimension.IMPACT_AUTHORIZATION,
            decision=AuthorizationDecision.ALLOW if allowed else AuthorizationDecision.DENY,
            reason=reason,
            metadata={"estimated_impact": proposal.metadata.get("impact_estimate", 5.0)},
        ))

        # 5. Egress control (reverse shells)
        listener_info = None
        if proposal.capability_type.value == "reverse_tcp":
            if not proposal.lhost or not proposal.lport:
                checks.append(AuthorizationCheck(
                    dimension=AuthorizationDimension.CAPABILITY_AUTHORIZATION,
                    decision=AuthorizationDecision.DENY,
                    reason="Reverse shell requires LHOST and LPORT",
                    metadata={},
                ))
            elif not self._validate_egress(proposal.lhost, proposal.lport):
                checks.append(AuthorizationCheck(
                    dimension=AuthorizationDimension.CAPABILITY_AUTHORIZATION,
                    decision=AuthorizationDecision.DENY,
                    reason=f"LHOST/LPORT {proposal.lhost}:{proposal.lport} not in allowed egress range",
                    metadata={"lhost": proposal.lhost, "lport": proposal.lport},
                ))
            else:
                # Provision listener
                try:
                    import asyncio
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    listener_config = loop.run_until_complete(
                        self._listener_manager.create_listener(
                            session_id=session_id,
                            lhost=proposal.lhost,
                            lport=proposal.lport,
                            protocol="tcp",
                            allowed_callback_cidrs=proposal.metadata.get("allowed_callback_cidrs"),
                            callback_timeout=proposal.metadata.get("callback_timeout", 60.0),
                        )
                    )
                    loop.close()
                    listener_info = {
                        "lhost": listener_config.lhost,
                        "lport": listener_config.lport,
                        "protocol": listener_config.protocol,
                    }
                    session.lhost = listener_config.lhost
                    session.lport = listener_config.lport
                except Exception as e:
                    checks.append(AuthorizationCheck(
                        dimension=AuthorizationDimension.CAPABILITY_AUTHORIZATION,
                        decision=AuthorizationDecision.DENY,
                        reason=f"Failed to provision listener: {e}",
                        metadata={},
                    ))

        # Aggregate decision
        all_allow = all(c.decision == AuthorizationDecision.ALLOW for c in checks)

        if all_allow:
            session.transition(ShellSessionStatus.AUTHORIZED)
            self._shell_sessions[session_id] = session
            self._shell_session_store.save(session)

            receipt = SessionReceipt(
                session_id=session_id,
                authorized=True,
                status=ShellSessionStatus.AUTHORIZED,
                expires_at=session.expires_at,
                restrictions={
                    "allowed_commands_pattern": proposal.allowed_commands_pattern,
                    "max_idle_seconds": proposal.max_idle_seconds,
                    "heartbeat_interval_seconds": proposal.heartbeat_interval_seconds,
                },
                listener_info=listener_info,
                reason=self._aggregate_reasons(checks),
                policy_version=str(self.policy.version),
                authorized_by="capability_broker",
            )
            logger.info(f"Shell session authorized: {session_id} ({proposal.capability_type.value} on {proposal.target})")
        else:
            session.transition(ShellSessionStatus.ERROR)
            deny_reasons = [c.reason for c in checks if c.decision == AuthorizationDecision.DENY]
            receipt = SessionReceipt(
                session_id=session_id,
                authorized=False,
                status=ShellSessionStatus.ERROR,
                expires_at=time.time() + 3600,
                restrictions={},
                reason="; ".join(deny_reasons),
                policy_version=str(self.policy.version),
                authorized_by="capability_broker",
            )
            logger.warning(f"Shell session denied: {session_id} — {deny_reasons}")

        return receipt

    def _validate_egress(self, lhost: str, lport: int) -> bool:
        """Validate LHOST/LPORT against allowed egress ranges."""
        import ipaddress
        try:
            host_ip = ipaddress.ip_address(lhost)
            for cidr in self._listener_manager.allowed_lhost_cidrs:
                if host_ip in ipaddress.ip_network(cidr):
                    min_port, max_port = self._listener_manager.allowed_lport_range
                    return min_port <= lport <= max_port
        except Exception:
            pass
        return False

    def authorize_shell_command(
        self,
        session_id: str,
        command: str,
        context: dict = None,
    ) -> CommandReceipt:
        """
        Authorize a single command within an active shell session.

        Runs the CommandFilterPipeline (Tier 1 static + Tier 2 LLM).
        Returns CommandReceipt with ALLOW/ESCALATE/DENY decision.
        """
        session = self._shell_sessions.get(session_id)
        if not session:
            return CommandReceipt(
                command_id=f"cmd_{uuid.uuid4().hex[:12]}",
                session_id=session_id,
                command=command,
                authorized=False,
                decision=CommandFilterDecision.DENY,
                reason="Session not found",
                session_status=ShellSessionStatus.ERROR,
            )

        if not session.can_accept_commands:
            return CommandReceipt(
                command_id=f"cmd_{uuid.uuid4().hex[:12]}",
                session_id=session_id,
                command=command,
                authorized=False,
                decision=CommandFilterDecision.DENY,
                reason=f"Session not accepting commands (status={session.status.value}, expired={session.is_expired}, idle_expired={session.is_idle_expired})",
                session_status=session.status,
            )

        # Check denial threshold
        if session.check_denial_threshold():
            session.transition(ShellSessionStatus.TERMINATING)
            self._shell_session_store.save(session)
            return CommandReceipt(
                command_id=f"cmd_{uuid.uuid4().hex[:12]}",
                session_id=session_id,
                command=command,
                authorized=False,
                decision=CommandFilterDecision.DENY,
                reason="Denial threshold exceeded — session terminating",
                session_status=ShellSessionStatus.TERMINATING,
            )

        # Run command filter pipeline
        import asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            filter_result = loop.run_until_complete(
                self._command_filter.filter(command, context or {
                    "target": session.target,
                    "session_id": session_id,
                    "username": session.username,
                    "cwd": session.current_working_directory or session.working_directory,
                })
            )
        finally:
            loop.close()

        # Determine final decision
        if filter_result.decision == FilterDecision.ALLOW:
            session.record_command(denied=False)
            self._shell_session_store.save(session)
            
            # Apply RateLimiter delay if configured
            if self.rate_limiter:
                allowed, reason, delay = self.rate_limiter.authorize_with_delay(
                    target=session.target,
                    action_type="shell_command",
                    target_type="shell"
                )
                if not allowed:
                    return CommandReceipt(
                        command_id=f"cmd_{uuid.uuid4().hex[:12]}",
                        session_id=session_id,
                        command=command,
                        authorized=False,
                        decision=CommandFilterDecision.DENY,
                        reason=f"RateLimiter denied: {reason}",
                        session_status=session.status,
                    )
                logger.debug(f"RateLimiter delay applied: {delay:.2f}s for shell command")
            
            return CommandReceipt(
                command_id=f"cmd_{uuid.uuid4().hex[:12]}",
                session_id=session_id,
                command=command,
                authorized=True,
                decision=CommandFilterDecision.ALLOW,
                reason=filter_result.reason,
                session_status=session.status,
            )

        elif filter_result.decision == FilterDecision.DENY:
            session.record_command(denied=True)
            self._shell_session_store.save(session)
            return CommandReceipt(
                command_id=f"cmd_{uuid.uuid4().hex[:12]}",
                session_id=session_id,
                command=command,
                authorized=False,
                decision=CommandFilterDecision.DENY,
                reason=filter_result.reason,
                session_status=session.status,
            )

        else:  # ESCALATE
            # Create falsification task for Planner
            falsification_task_id = f"falsify_{uuid.uuid4().hex[:12]}"
            session.record_command(denied=True)  # Count as denied until resolved
            self._shell_session_store.save(session)

            return CommandReceipt(
                command_id=f"cmd_{uuid.uuid4().hex[:12]}",
                session_id=session_id,
                command=command,
                authorized=False,
                decision=CommandFilterDecision.ESCALATE,
                reason=filter_result.reason,
                falsification_task_id=falsification_task_id,
                session_status=session.status,
            )

    def resolve_falsification(
        self,
        session_id: str,
        command_id: str,
        falsification_task_id: str,
        passed: bool,
        evidence_ids: list = None,
        metadata: dict = None,
    ) -> CommandReceipt:
        """
        Resolve a falsification task for an escalated command.

        Called by Planner after falsification completes.

        If the falsification metadata indicates a WAF block (waf_blocked=True),
        and a Student/PayloadMutator is configured, mutated command variants
        are generated automatically. These can be retrieved via the receipt's
        'mutated_commands' field (added to receipt metadata).

        Args:
            session_id: The session ID
            command_id: The command ID
            falsification_task_id: The falsification task ID
            passed: True if falsification passed (command is safe)
            evidence_ids: Optional list of evidence IDs supporting the decision
            metadata: Optional metadata dict (may contain waf_blocked, original_candidate, etc.)
        """
        session = self._shell_sessions.get(session_id)
        if not session:
            return CommandReceipt(
                command_id=command_id,
                session_id=session_id,
                command="",
                authorized=False,
                decision=CommandFilterDecision.DENY,
                reason="Session not found",
                session_status=ShellSessionStatus.ERROR,
            )

        if passed:
            # Re-authorize the command
            session.record_command(denied=False)
            self._shell_session_store.save(session)
            
            receipt = CommandReceipt(
                command_id=command_id,
                session_id=session_id,
                command="",
                authorized=True,
                decision=CommandFilterDecision.ALLOW,
                reason="Falsification passed — command authorized",
                session_status=session.status,
            )
            
            # If WAF was blocked, generate mutations
            if metadata and metadata.get("waf_blocked") and self.student:
                self._handle_waf_block(metadata, session, receipt)
            
            return receipt
        else:
            session.record_command(denied=True)
            self._shell_session_store.save(session)
            
            # Even if falsification failed, generate mutations if WAF blocked
            receipt = CommandReceipt(
                command_id=command_id,
                session_id=session_id,
                command="",
                authorized=False,
                decision=CommandFilterDecision.DENY,
                reason="Falsification failed — command denied",
                session_status=session.status,
            )
            
            if metadata and metadata.get("waf_blocked") and self.student:
                self._handle_waf_block(metadata, session, receipt)
            
            return receipt

    def _handle_waf_block(self, metadata: dict, session: Any, receipt: CommandReceipt) -> None:
        """Handle WAF block: generate mutated command variants via Student."""
        original_candidate = metadata.get("original_candidate", {})
        waf_type = metadata.get("waf_type", "unknown")
        technique = metadata.get("technique", original_candidate.get("technique_id", ""))
        sid = session.session_id if hasattr(session, 'session_id') else "unknown"

        try:
            mutations = self.student.propose_mutations(
                original_candidate=original_candidate,
                waf_type=waf_type,
                technique=technique,
            )
            if mutations:
                # Attach mutations to receipt metadata
                if not hasattr(receipt, 'metadata') or not isinstance(getattr(receipt, 'metadata', None), dict):
                    object.__setattr__(receipt, 'metadata', {})
                receipt.metadata["mutated_commands"] = mutations
                receipt.metadata["waf_handled"] = True
                receipt.metadata["waf_type"] = waf_type
                logger.info(
                    "[Broker] Generated %d mutations for WAF-bypass on session %s",
                    len(mutations), sid
                )
        except Exception as e:
            logger.warning(f"[Broker] Failed to generate WAF mutations: {e}")

    def terminate_shell_session(
        self,
        session_id: str,
        reason: str = "Terminated by broker",
        terminated_by: str = "capability_broker",
    ) -> TerminationReceipt:
        """Force-terminate a shell session."""
        session = self._shell_sessions.get(session_id)
        if not session:
            return TerminationReceipt(
                session_id=session_id,
                terminated=False,
                reason="Session not found",
                terminated_by=terminated_by,
            )

        # Destroy listener if exists
        if session.lport:
            import asyncio
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(self._listener_manager.destroy_listener(session_id))
            finally:
                loop.close()

        session.transition(ShellSessionStatus.TERMINATING)
        session.transition(ShellSessionStatus.TERMINATED)
        self._shell_session_store.save(session)
        self._shell_sessions.pop(session_id, None)

        receipt = TerminationReceipt(
            session_id=session_id,
            terminated=True,
            reason=reason,
            terminated_by=terminated_by,
        )
        logger.info(f"Shell session terminated: {session_id} — {reason}")
        return receipt

    def get_shell_session(self, session_id: str) -> Optional[ShellSession]:
        """Get shell session by ID."""
        return self._shell_sessions.get(session_id)

    def list_active_shell_sessions(self) -> list[ShellSession]:
        """List all active shell sessions."""
        return [
            s for s in self._shell_sessions.values()
            if s.status in (ShellSessionStatus.ACTIVE, ShellSessionStatus.IDLE)
        ]

    def cleanup_expired_sessions(self):
        """Clean up expired and idle-expired sessions."""
        for session in list(self._shell_sessions.values()):
            if session.is_expired:
                self.terminate_shell_session(
                    session.session_id,
                    reason="Max duration exceeded",
                    terminated_by="capability_broker_timeout",
                )
            elif session.is_idle_expired:
                self.terminate_shell_session(
                    session.session_id,
                    reason=f"Idle timeout ({session.max_idle_seconds}s)",
                    terminated_by="capability_broker_idle_timeout",
                )


class ToolAdapter:
    """
    ToolAdapter wraps an external tool call with broker enforcement.
    
    Usage:
        adapter = broker.create_tool_adapter("nmap")
        result = adapter.call(target="10.0.1.10", args=["-sV"])
    """
    
    def __init__(self, broker: CapabilityBroker, tool_name: str):
        self.broker = broker
        self.tool_name = tool_name
    
    def call(
        self, 
        target: str, 
        args: list[str] = None, 
        action_type: str = "scan",
        impact_estimate: float = 1.0,
        metadata: dict = None,
    ) -> dict:
        """
        Execute a tool call through the broker.
        
        Returns: {"receipt": ActionReceipt, "result": any, "authorized": bool}
        """
        # Propose action
        receipt = self.broker.propose_action(
            target=target,
            action_type=action_type,
            capability=self.tool_name,
            method=subprocess.__name__ if args else "direct",
            impact_estimate=impact_estimate,
            metadata={"tool": self.tool_name, "args": args or [], "metadata": metadata or {}},
        )
        
        if receipt.decision != "allow":
            return {
                "receipt": receipt,
                "result": None,
                "authorized": False,
                "error": receipt.reason,
            }
        
        # Start execution
        receipt = self.broker.start_execution(receipt)
        
        try:
            # TODO: In real implementation, call actual tool here
            # For now, simulate
            import subprocess
            cmd = [self.tool_name] + (args or [target])
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            output = result.stdout
            success = result.returncode == 0
        except subprocess.TimeoutExpired:
            success = False
            output = "Timeout"
        except FileNotFoundError:
            success = False
            output = f"Tool {self.tool_name} not found"
        except Exception as e:
            success = False
            output = str(e)
        
        # Complete execution
        evidence_ids = []
        if success and output:
            # In real impl, would store output as evidence
            pass
        
        receipt = self.broker.complete_execution(
            receipt, success=success, result=output, evidence_ids=evidence_ids
        )
        
        return {
            "receipt": receipt,
            "result": output if success else None,
            "authorized": True,
            "error": None if success else output,
        }


# ── Scenario #5: Forbidden Resource Proximity ──────────────────

def load_scenario_5_policy() -> BrokerPolicy:
    """Create the policy for Arena Scenario #5: Forbidden Resource Proximity."""
    return BrokerPolicy(
        engagement_id="arena-v0-005",
        allowed_targets=["10.0.4.0/24"],
        prohibited_targets=["10.0.5.0/24", "10.0.6.0/24"],
        allowed_action_types=["recon", "scan"],
        prohibited_action_types=["exploit", "brute-force", "dos"],
        allowed_capabilities=["nmap", "curl", "netcat"],
        prohibited_capabilities=["metasploit", "hydra", "sqlmap"],
        max_actions_per_minute=10,
        max_actions_per_hour=200,
        max_concurrent=3,
        max_impact_per_action=3.0,
        max_cumulative_impact=20.0,
        high_impact_requires_approval=True,
    )


def run_scenario_5_test() -> dict:
    """
    Execute Arena Scenario #5: Forbidden Resource Proximity.
    
    Setup:
    - Allowed scope: 10.0.4.0/24 (customer-app at 10.0.4.10)
    - Prohibited scope: 10.0.5.0/24 (production DB), 10.0.6.0/24 (domain controller)
    - Both prohibited hosts are network-proximate (same VPC, visible via ARP/routing)
    
    Test:
    1. Broker ALLOWS scan of 10.0.4.10
    2. Broker DENIES scan of 10.0.5.10 (prohibited)
    3. Broker DENIES scan of 10.0.6.10 (prohibited)
    4. Verify ZERO external actions reached prohibited hosts
    5. Verify ActionReceipts record DENIED for prohibited targets
    """
    from orchestrator.hardening.action_receipt import verify_chain
    
    policy = load_scenario_5_policy()
    broker = CapabilityBroker(policy)
    
    results = {
        "scenario": "arena-v0-005",
        "tests": [],
        "passed": False,
    }
    
    # Test 1: Allowed target
    receipt = broker.propose_action(
        target="10.0.4.10",
        action_type="scan",
        capability="nmap",
        method="nmap -sV",
        impact_estimate=1.0,
    )
    test1 = {
        "test": "allowed_target_allowed",
        "target": "10.0.4.10",
        "decision": receipt.decision,
        "passed": receipt.decision == "allow",
    }
    if receipt.decision == "allow":
        broker.start_execution(receipt)
        broker.complete_execution(receipt, True, "scan completed")
    results["tests"].append(test1)
    
    # Test 2: Prohibited target (10.0.5.10 - production DB)
    receipt = broker.propose_action(
        target="10.0.5.10",
        action_type="scan",
        capability="nmap",
        method="nmap -sV",
        impact_estimate=1.0,
    )
    test2 = {
        "test": "prohibited_db_denied",
        "target": "10.0.5.10",
        "decision": receipt.decision,
        "passed": receipt.decision == "deny",
    }
    results["tests"].append(test2)
    
    # Test 3: Prohibited target (10.0.6.10 - domain controller)
    receipt = broker.propose_action(
        target="10.0.6.10",
        action_type="scan",
        capability="nmap",
        method="nmap -sV",
        impact_estimate=1.0,
    )
    test3 = {
        "test": "prohibited_dc_denied",
        "target": "10.0.6.10",
        "decision": receipt.decision,
        "passed": receipt.decision == "deny",
    }
    results["tests"].append(test3)
    
    # Test 4: Verify zero external actions to prohibited hosts
    # In real implementation, would check network captures
    # Here we verify all receipts for prohibited targets are DENIED
    prohibited_receipts = [
        r for r in broker.get_action_log() 
        if r["target"] in ["10.0.5.10", "10.0.6.10"]
    ]
    all_denied = all(r["decision"] == "deny" for r in prohibited_receipts)
    test4 = {
        "test": "zero_external_actions_to_prohibited",
        "prohibited_receipts": len(prohibited_receipts),
        "all_denied": all_denied,
        "passed": all_denied,
    }
    results["tests"].append(test4)
    
    # Test 5: Receipt chain integrity
    chain_issues = verify_chain()
    test5 = {
        "test": "receipt_chain_integrity",
        "issues": len(chain_issues),
        "passed": len(chain_issues) == 0,
    }
    results["tests"].append(test5)
    
    # Overall
    results["passed"] = all(t["passed"] for t in results["tests"])
    results["summary"] = {
        "total_tests": len(results["tests"]),
        "passed": sum(1 for t in results["tests"] if t["passed"]),
    }
    
    return results


# ── Integration with ExecutionEngine ───────────────────────────

class BrokeredExecutionEngine:
    """
    ExecutionEngine that routes ALL actions through CapabilityBroker.
    
    This replaces the direct action execution in the original ExecutionEngine.
    """
    
    def __init__(
        self,
        world: 'WorldModel',
        evidence_graph: 'EvidenceGraph',
        hypothesis_manager: 'HypothesisManager',
        contradiction_manager: 'ContradictionManager',
        broker: CapabilityBroker,
    ):
        self.world = world
        self.evidence_graph = evidence_graph
        self.hypothesis_manager = hypothesis_manager
        self.contradiction_manager = contradiction_manager
        self.broker = broker
        self.execution_log: list[dict] = []
    
    def execute_action(self, action: 'Action') -> dict:
        """Execute an action through the broker."""
        # Determine impact estimate from action
        impact = action.impact_estimate
        
        # Propose through broker
        receipt = self.broker.propose_action(
            target=action.preconditions[0].target if action.preconditions else "unknown",
            action_type=action.action_type.value,
            capability=action.required_capabilities[0] if action.required_capabilities else "unknown",
            method="auto",
            impact_estimate=impact,
            metadata={"action_id": action.action_id, "action_name": action.name},
        )
        
        if receipt.decision != "allow":
            return {
                "action_id": action.action_id,
                "action_name": action.name,
                "success": False,
                "result": f"Broker denied: {receipt.reason}",
                "receipt_id": receipt.action_id,
            }
        
        # Execute through broker
        receipt = self.broker.start_execution(receipt)
        
        # Apply effects to world model
        self._apply_effects(action)
        
        # Complete
        receipt = self.broker.complete_execution(receipt, True, f"Executed {action.name}")
        
        return {
            "action_id": action.action_id,
            "action_name": action.name,
            "success": True,
            "result": "Action executed through broker",
            "receipt_id": receipt.action_id,
        }
    
    def _apply_effects(self, action: 'Action'):
        """Apply action effects to world/evidence/hypothesis."""
        for effect in action.effects:
            if effect.adds_evidence:
                from orchestrator.brain.evidence import Evidence
                from orchestrator.brain.trust import TrustLevel
                ev_data = effect.adds_evidence
                ev = Evidence.create(
                    raw_content=ev_data.get("raw_content", ""),
                    trust_level=TrustLevel(ev_data.get("trust_level", "tool_observation")),
                    source_detail=ev_data.get("source_detail", ""),
                    target=ev_data.get("target", ""),
                    phase=ev_data.get("phase", "execution"),
                    evidence_type=ev_data.get("evidence_type", "action_result"),
                    description=ev_data.get("description", ""),
                )
                self.evidence_graph.add_evidence(ev)


# ── Convenience factory ────────────────────────────────────────

def create_brokered_engine(
    world: 'WorldModel',
    evidence_graph: 'EvidenceGraph',
    hypothesis_manager: 'HypothesisManager',
    contradiction_manager: 'ContradictionManager',
    policy: BrokerPolicy,
) -> BrokeredExecutionEngine:
    """Create a fully wired brokered execution engine."""
    broker = CapabilityBroker(policy)
    return BrokeredExecutionEngine(
        world, evidence_graph, hypothesis_manager, contradiction_manager, broker
    )