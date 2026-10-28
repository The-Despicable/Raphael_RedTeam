"""patches/tools_service_patch.py — drop-in replacement for the docker-exec
broker inside brain/tools_service.py.

Import LocalToolsManager and route every tool call through it. The scoped
red-team layer from the earlier build (scope gate, profile allowlist,
RateLimiter) stays exactly as it was — only the execution backend changes:
docker exec -> native subprocess.

Paste-over pattern:

    # OLD (docker backend):
    # proc = await asyncio.create_subprocess_exec(
    #     "docker", "exec", "-i", "raphael-kali", binary, *args, target, ...)

    # NEW (native backend):
    result = await self._mgr.run(tool=req.tool, target=req.target, args=args)
    if result.errors or (result.returncode == -1 and not result.stdout):
        # per-call error list surfaced to the caller; no docker fallback
        return self._deny(req, "; ".join(result.errors) or "tool failed")
    # result.health always present: {"tool_resolved": ..., "kali_service": ...}
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# Make `scripts.` importable from anywhere (PYTHONPATH is also set in env.sh).
ROOT = Path(os.environ.get("RAPHAEL_ROOT", "/home/yaser/raphael-redteam"))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.local_tools_manager import LocalToolsManager, ToolResult  # noqa: E402


class NativeToolsBackend:
    """Async backend wrapper the tools_service delegates to.

    Every call:
      - health probe on the tool binary (PATH resolution) and on the kali
        service (KALI_TOOLS_URL shim, http://127.0.0.1:3800)
      - explicit error list (missing binary, permission, timeout, control chars)
      - no docker, no docker exec, no raphael-net
    """

    def __init__(self, require_kali: bool = False) -> None:
        self._mgr = LocalToolsManager(require_kali=require_kali)

    async def execute(self, *, tool: str, target: str, args: list[str] | None = None) -> ToolResult:
        return await self._mgr.run(tool=tool, target=target, args=args)

    async def health(self) -> dict:
        return await self._mgr.health()

    def which(self, tools: list[str]) -> dict[str, str | None]:
        return self._mgr.which(tools)


# Example of the patched tools_service.run_tool core (scope checks unchanged —
# see the raphael-scoped build; this shows ONLY the exec backend swap):
#
#     async def run_tool(self, req, *, task_id=None):
#         ... scope gate + profile allowlist + rate limiter exactly as before ...
#         result = await self._backend.execute(tool=req.tool, target=req.target, args=req.args)
#         if result.errors:
#             return self._deny(req, "; ".join(result.errors))
#         content = (f"$ {' '.join(result.argv)}\n"
#                    f"--- health: {result.health} ---\n"
#                    f"--- stdout ---\n{result.stdout}\n"
#                    f"--- stderr ---\n{result.stderr}\nrc={result.returncode}")
#         ev = self._evidence.record(...)
#         return ToolExecResult(..., evidence_ref=ev.evidence_id)
