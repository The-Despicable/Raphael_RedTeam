"""Tools broker service.

Wraps orchestrator.kali_tools_client.KaliToolsClient for HTTP tool execution,
and orchestrator.brain.capability_broker.CapabilityBroker for authorization
gates. Falls back to a local stub executor when the orchestrator is absent
or the Kali tools service is unreachable, so the brain keeps responding.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Dict, List, Optional

import httpx

from .config import Settings, get_settings
from .broadscan_tool import BroadscanError, BroadscanScopeError, BroadscanTool
from .cloak_tool import CloakError, CloakScopeError, CloakFetchTool

log = logging.getLogger("brain.tools")


# ---------------------------------------------------------------------------
# Stub executor (fallback)
# ---------------------------------------------------------------------------


class StubToolExecutor:
    """Returns a deterministic, safe, offline response when Kali tools is
    unavailable. Useful for tests and degraded-mode operation."""

    async def run(
        self, tool: str, args: List[str], target: Optional[str] = None, timeout: Optional[float] = None
    ) -> Dict[str, Any]:
        await asyncio.sleep(0.05)
        return {
            "tool": tool,
            "exit_code": 0,
            "stdout": (
                f"[stub] simulated run of {tool} {' '.join(args)}"
                + (f" against {target}" if target else "")
            ),
            "stderr": "",
            "duration_ms": 50.0,
            "timed_out": False,
            "fallback_used": True,
        }


# ---------------------------------------------------------------------------
# Kali Tools client wrapper
# ---------------------------------------------------------------------------


class KaliToolsClient:
    """Async wrapper around orchestrator.kali_tools_client if present;
    otherwise a direct httpx client against KALI_TOOLS_URL.

    A single shared AsyncClient is reused across calls (no per-request TCP/TLS
    handshake), and caller-supplied timeouts are capped at
    settings.max_tool_timeout so a hostile/buggy caller cannot pin a worker.
    """

    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or get_settings()
        self.url = self.settings.kali_tools_url.rstrip("/")
        self._impl: Optional[Any] = None
        self._stub = StubToolExecutor()
        self._http: Optional[httpx.AsyncClient] = None

        try:
            from orchestrator.kali_tools_client import (  # type: ignore
                KaliToolsClient as _OrchClient,
            )

            self._impl = _OrchClient(base_url=self.url)
            log.info("Using orchestrator.kali_tools_client.KaliToolsClient")
        except Exception:
            self._impl = None
            log.info(
                "orchestrator.kali_tools_client unavailable; using direct httpx client"
            )

    def _capped_timeout(self, timeout: Optional[float], default: float) -> float:
        effective = timeout if timeout and timeout > 0 else default
        return min(effective, self.settings.max_tool_timeout)

    async def _client(self) -> httpx.AsyncClient:
        if self._http is None or self._http.is_closed:
            self._http = httpx.AsyncClient(timeout=self.settings.max_tool_timeout)
        return self._http

    async def close(self) -> None:
        if self._http is not None and not self._http.is_closed:
            await self._http.aclose()
        self._http = None

    async def run(
        self,
        tool: str,
        args: List[str],
        target: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        t0 = time.perf_counter()
        # Try orchestrator impl first.
        if self._impl is not None:
            try:
                if hasattr(self._impl, "run"):
                    arg_str = " ".join(args) if isinstance(args, list) else str(args or "")
                    if target and arg_str and target not in arg_str:
                        arg_str = (arg_str + " " + str(target)).strip()
                    result = self._impl.run(tool=tool, args=arg_str, timeout=timeout or 300)
                    if asyncio.iscoroutine(result):
                        result = await result
                    return self._normalize(result, t0)
            except Exception as e:  # noqa: BLE001
                log.warning("orchestrator kali client failed: %s", str(e)[:160])
                # fall through to direct httpx

        # Direct httpx fallback (shared client, capped timeout).
        try:
            client = await self._client()
            payload = {"tool": tool, "args": list(args)}
            if target:
                payload["target"] = target
            r = await client.post(
                f"{self.url}/run",
                json=payload,
                timeout=self._capped_timeout(timeout, 60.0),
            )
            r.raise_for_status()
            return self._normalize(r.json(), t0)
        except (httpx.RequestError, httpx.HTTPError) as e:
            log.warning("kali tools HTTP unavailable, using stub: %s", str(e)[:120])
            return await self._stub.run(tool, args, target, timeout)

    async def tools_list(self) -> List[Dict[str, Any]]:
        if self._impl is not None and hasattr(self._impl, "tools_list"):
            try:
                result = self._impl.tools_list()
                if asyncio.iscoroutine(result):
                    result = await result
                if isinstance(result, list):
                    return result
                if isinstance(result, dict) and "tools" in result:
                    return result["tools"]
            except Exception as e:  # noqa: BLE001
                log.warning("tools_list via orchestrator failed: %s", str(e)[:120])

        try:
            client = await self._client()
            r = await client.get(f"{self.url}/tools", timeout=5.0)
            r.raise_for_status()
            data = r.json()
            if isinstance(data, list):
                return data
            return data.get("tools", [])
        except (httpx.RequestError, httpx.HTTPError):
            return []

    @staticmethod
    def _normalize(data: Any, t0: float) -> Dict[str, Any]:
        if isinstance(data, dict):
            return {
                "tool": data.get("tool") or data.get("name", ""),
                "exit_code": int(data.get("exit_code", data.get("returncode", 0)) or 0),
                "stdout": str(data.get("stdout", data.get("output", "")) or ""),
                "stderr": str(data.get("stderr", "") or ""),
                "duration_ms": float(
                    data.get("duration_ms", (time.perf_counter() - t0) * 1000)
                ),
                "timed_out": bool(data.get("timed_out", False)),
                "fallback_used": bool(data.get("fallback_used", False)),
            }
        return {
            "tool": "",
            "exit_code": 0,
            "stdout": str(data),
            "stderr": "",
            "duration_ms": (time.perf_counter() - t0) * 1000,
            "timed_out": False,
            "fallback_used": False,
        }


# ---------------------------------------------------------------------------
# Capability broker
# ---------------------------------------------------------------------------


class CapabilityBrokerService:
    """Wraps orchestrator.brain.capability_broker when present, otherwise a
    permissive local policy (scope-checked)."""

    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or get_settings()
        self._broker: Optional[Any] = None

        try:
            from orchestrator.brain.capability_broker import (  # type: ignore
                BrokerPolicy,
                CapabilityBroker,
                create_brokered_engine,
                load_scenario_5_policy,
            )

            policy = None
            try:
                policy = load_scenario_5_policy()
            except Exception:
                policy = None
            if policy is None:
                policy = BrokerPolicy()
            self._broker = CapabilityBroker(policy)
            log.info("Loaded orchestrator.brain.capability_broker.CapabilityBroker")
        except Exception:
            self._broker = None
            log.info("capability_broker unavailable; using permissive local policy")

    def check(
        self,
        agent: str,
        tool: str,
        action: str,
        scope: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if self._broker is not None:
            try:
                # The real orchestrator interface may differ; try a few shapes.
                if hasattr(self._broker, "authorize"):
                    decision = self._broker.authorize(agent, tool, action, scope or {})
                    if hasattr(decision, "decision"):
                        return {
                            "decision": str(decision.decision),
                            "reason": getattr(decision, "reason", None),
                            "dimensions": getattr(decision, "dimensions", {}) or {},
                        }
                    if isinstance(decision, dict):
                        return {
                            "decision": decision.get("decision", "allow"),
                            "reason": decision.get("reason"),
                            "dimensions": decision.get("dimensions", {}),
                        }
                    return {"decision": str(decision), "reason": None, "dimensions": {}}
            except Exception as e:  # noqa: BLE001
                log.warning("broker.authorize failed: %s", str(e)[:120])

        # Local permissive policy: deny only obviously destructive actions
        # unless explicitly approved via scope.
        destructive = action.lower() in {"delete", "destroy", "wipe", "exfil"}
        scope = scope or {}
        if destructive and not scope.get("approved"):
            return {
                "decision": "require_approval",
                "reason": f"destructive action '{action}' requires approval",
                "dimensions": {"destructive": True},
            }
        return {
            "decision": "allow",
            "reason": "permissive local policy",
            "dimensions": {"mode": "fallback"},
        }

    def known_tools(self) -> List[str]:
        if self._broker is not None and hasattr(self._broker, "known_tools"):
            try:
                return list(self._broker.known_tools())
            except Exception:
                pass
        # Conservative default set when no broker.
        return [
            "nmap", "masscan", "nikto", "nuclei", "httpx", "ffuf",
            "gobuster", "dirb", "sqlmap", "hydra", "whatweb", "wpscan",
            "smbclient", "enum4linux", "gobuster", "subfinder",
            "broadscan",
        ]

    def known_engines(self) -> List[str]:
        if self._broker is not None and hasattr(self._broker, "known_engines"):
            try:
                return list(self._broker.known_engines())
            except Exception:
                pass
        return ["kali-tools-http", "sliver", "local-fallback"]


# ---------------------------------------------------------------------------
# Tools service (facade)
# ---------------------------------------------------------------------------


class ToolsService:
    """Facade combining the client, the broker, and the stub fallback."""

    def __init__(
        self,
        settings: Optional[Settings] = None,
        client: Optional[KaliToolsClient] = None,
        broker: Optional[CapabilityBrokerService] = None,
    ):
        self.settings = settings or get_settings()
        self.client = client or KaliToolsClient(self.settings)
        self.broker = broker or CapabilityBrokerService(self.settings)
        self.broadscan = BroadscanTool(self.settings)
        self.cloak = CloakFetchTool(self.settings)

    # Tools the brain executes itself rather than routing to kali-tools.
    SELF_HOSTED = frozenset({"broadscan", "cloakfetch", "cloak_fetch"})

    async def execute(
        self,
        tool: str,
        args: List[str],
        target: Optional[str] = None,
        timeout: Optional[float] = None,
        agent: str = "autonomous-brain",
    ) -> Dict[str, Any]:
        # Broker gate first.
        decision = self.broker.check(agent, tool, "execute", {"target": target})
        if decision["decision"] == "deny":
            return {
                "tool": tool,
                "exit_code": 126,
                "stdout": "",
                "stderr": f"denied by capability broker: {decision.get('reason')}",
                "duration_ms": 0.0,
                "timed_out": False,
                "fallback_used": False,
                "broker_decision": decision,
            }
        if tool in self.SELF_HOSTED:
            result = await self._execute_self_hosted(tool, args, target, timeout)
            result["broker_decision"] = decision
            return result
        result = await self.client.run(tool, args, target, timeout)
        result["broker_decision"] = decision
        return result

    async def _execute_self_hosted(
        self,
        tool: str,
        args: List[str],
        target: Optional[str],
        timeout: Optional[float],
    ) -> Dict[str, Any]:
        """Run a locally-executed tool with its own scope gate."""
        t0 = time.perf_counter()
        capped = self._capped(timeout, self.settings.max_tool_timeout)
        try:
            if tool == "broadscan":
                result = await self.broadscan.from_args(args, target, capped)
            elif tool in ("cloakfetch", "cloak_fetch"):
                result = await self.cloak.from_args(args, target, capped)
            else:
                result = None
            if result is not None:
                result.setdefault("tool", tool)
                result.setdefault("exit_code", 0 if result.get("ok", True) else 1)
                result.setdefault("stdout", "")
                result["duration_ms"] = (time.perf_counter() - t0) * 1000
                result.setdefault("timed_out", False)
                result.setdefault("fallback_used", False)
                return result
        except (BroadscanScopeError, BroadscanError,
                CloakScopeError, CloakError) as e:
            return {
                "tool": tool,
                "exit_code": 126,
                "stdout": "",
                "stderr": f"{type(e).__name__}: {e}",
                "duration_ms": (time.perf_counter() - t0) * 1000,
                "timed_out": False,
                "fallback_used": False,
                "engine": "broadscan",
            }
        except Exception as e:  # noqa: BLE001
            log.warning("%s local execution failed: %s", tool, str(e)[:160])
            return {
                "tool": tool,
                "exit_code": 1,
                "stdout": "",
                "stderr": f"{type(e).__name__}: {e}",
                "duration_ms": (time.perf_counter() - t0) * 1000,
                "timed_out": False,
                "fallback_used": False,
                "engine": "broadscan",
            }

    def _capped(self, timeout: Optional[float], default: float) -> float:
        effective = timeout if timeout and timeout > 0 else default
        return float(min(effective, self.settings.max_tool_timeout))

    async def list_tools(self) -> List[Dict[str, Any]]:
        tools = await self.client.tools_list()
        names = {
            str(t.get("name") or t.get("tool") or "")
            for t in tools
            if isinstance(t, dict)
        }
        if "broadscan" not in names:
            tools.append(
                {
                    "name": "broadscan",
                    "engine": "local",
                    "description": "Scope-gated broad TCP scanner (connect/syn)",
                }
            )
        if "cloakfetch" not in names:
            tools.append(
                {
                    "name": "cloakfetch",
                    "engine": "local",
                    "description": "Scope-gated stealth-browser page fetch (cloakbrowser)",
                }
            )
        return tools

    async def close(self) -> None:
        """Release the shared HTTP client (called during shutdown)."""
        await self.client.close()

    def registry(self) -> List[str]:
        """Tool registry surfaced via orchestrator.chains when available."""
        try:
            from orchestrator import chains  # type: ignore

            if hasattr(chains, "TOOL_REGISTRY"):
                return list(chains.TOOL_REGISTRY)
            if hasattr(chains, "list_tools"):
                return list(chains.list_tools())
        except Exception:
            pass
        return self.broker.known_tools()

    def capabilities(self) -> List[str]:
        return self.broker.known_tools()

    def engines(self) -> List[str]:
        return self.broker.known_engines()


# Module-level singleton (managed by lifespan in main.py to avoid reload issues)
_tools: Optional[ToolsService] = None


def init_tools(settings: Optional[Settings] = None) -> ToolsService:
    global _tools
    _tools = ToolsService(settings)
    return _tools


def get_tools() -> ToolsService:
    global _tools
    if _tools is None:
        _tools = ToolsService()
    return _tools
