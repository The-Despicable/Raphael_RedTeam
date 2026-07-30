"""
adaptive_timeout.py — Module-aware, phase-tracked timeouts that report partial findings.

Replaces the flat 120s TimeoutGuard with dynamic timeouts based on:
- Module type (recon, exploit, privesc, etc.)
- Phase progress (sub-phase completion reports)
- Historical timing data per target
- Partial findings preservation on timeout
"""

import asyncio
import functools
import logging
import time
from typing import Any, Callable, Optional

logger = logging.getLogger("adaptive_timeout")

MODULE_TIMEOUTS = {
    "recon": 300.0,
    "scan": 180.0,
    "exploit": 300.0,
    "lpd_exploit": 240.0,
    "pjl_exploit": 240.0,
    "privesc": 300.0,
    "socket_scm": 180.0,
    "honeypot_analyzer": 120.0,
    "relay_chain": 300.0,
    "postex": 240.0,
    "credential": 180.0,
    "exfil": 180.0,
    "pivot": 240.0,
    "persistence": 180.0,
    "reversing": 300.0,
    "web_fuzz": 240.0,
    "craft_exploit": 240.0,
    "default": 120.0,
}

MIN_TIMEOUT = 30.0
MAX_TIMEOUT = 600.0


class PartialFindingsError(RuntimeError):
    """Raised when a phase times out but produced partial findings."""
    def __init__(self, message: str, partial_findings: list):
        self.partial_findings = partial_findings
        super().__init__(message)


class AdaptiveTimeout:
    def __init__(self, default_timeout: float = 120.0):
        self._default = default_timeout
        self._overrides: dict[str, float] = {}
        self._module_defaults: dict[str, float] = dict(MODULE_TIMEOUTS)
        self._history: dict[str, list[float]] = {}
        self._phase_progress: dict[str, dict] = {}

    def set_timeout(self, operation: str, timeout: float):
        self._overrides[operation] = timeout

    def set_module_timeout(self, module: str, timeout: float):
        self._module_defaults[module] = max(MIN_TIMEOUT, min(timeout, MAX_TIMEOUT))

    def get_timeout(self, operation: str) -> float:
        if operation in self._overrides:
            return self._overrides[operation]
        if operation in self._module_defaults:
            return self._module_defaults[operation]
        return self._default

    def record_timing(self, operation: str, elapsed: float):
        if operation not in self._history:
            self._history[operation] = []
        self._history[operation].append(elapsed)
        if len(self._history[operation]) > 10:
            self._history[operation] = self._history[operation][-10:]

    def adaptive_timeout_for(self, operation: str) -> float:
        base = self.get_timeout(operation)
        if operation not in self._history or not self._history[operation]:
            return base
        recent = self._history[operation][-3:]
        avg = sum(recent) / len(recent)
        p90 = sorted(recent)[int(len(recent) * 0.9)] if len(recent) >= 3 else max(recent)
        dynamic = max(avg * 2.5, p90 * 1.5, base * 0.8)
        return max(MIN_TIMEOUT, min(dynamic, MAX_TIMEOUT))

    def report_progress(self, phase_id: str, sub_phase: str, fraction: float,
                        findings: Optional[list] = None):
        if phase_id not in self._phase_progress:
            self._phase_progress[phase_id] = {
                "sub_phases": {},
                "findings": [],
                "started": time.time(),
            }
        self._phase_progress[phase_id]["sub_phases"][sub_phase] = {
            "fraction": fraction,
            "timestamp": time.time(),
        }
        if findings:
            self._phase_progress[phase_id]["findings"].extend(findings)

    def get_partial_findings(self, phase_id: str) -> list:
        data = self._phase_progress.get(phase_id, {})
        return data.get("findings", [])

    def clear_phase(self, phase_id: str):
        self._phase_progress.pop(phase_id, None)

    async def run(self, operation: str, coro, timeout: float = None,
                  phase_id: str = None, preserve_partial: bool = True):
        t = timeout or self.adaptive_timeout_for(operation)
        try:
            result = await asyncio.wait_for(coro, timeout=t)
            return result
        except asyncio.TimeoutError:
            msg = f"{operation} timed out after {t:.0f}s"
            if preserve_partial and phase_id:
                partial = self.get_partial_findings(phase_id)
                if partial:
                    raise PartialFindingsError(f"{msg} with {len(partial)} partial findings", partial)
            raise PartialFindingsError(msg, [])

    def stats(self) -> dict:
        return {
            "default_timeout": self._default,
            "module_defaults": dict(self._module_defaults),
            "overrides": dict(self._overrides),
            "history": {k: {"count": len(v), "recent_avg": sum(v[-3:])/len(v[-3:]) if len(v) >= 3 else 0}
                        for k, v in self._history.items()},
        }


_adaptive: AdaptiveTimeout = None


def get_adaptive_timeout() -> AdaptiveTimeout:
    global _adaptive
    if _adaptive is None:
        _adaptive = AdaptiveTimeout()
    return _adaptive
