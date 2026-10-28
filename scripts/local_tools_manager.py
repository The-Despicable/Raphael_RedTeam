#!/usr/bin/env python3
"""scripts/local_tools_manager.py — native subprocess tool broker.

Drop-in replacement for the `docker exec kali-tools ...` pattern. Resolves a
tool by name from $PATH, runs it as a direct subprocess on the host, captures
stdout/stderr/rc, records a per-call health probe on the requested tool and
the kali-tools HTTP service (legacy KALI_TOOLS_URL shim, default
http://127.0.0.1:3800), and returns a structured JSON result.

CLI:
    python3 scripts/local_tools_manager.py run --tool nmap --target 10.10.10.5 -- --sV -p 22,80
    python3 scripts/local_tools_manager.py health
    python3 scripts/local_tools_manager.py which --tool nmap
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import sys
import time
from dataclasses import dataclass, field
from typing import Optional

try:
    import httpx
except ImportError:  # pragma: no cover
    httpx = None  # type: ignore[assignment]


@dataclass
class ToolResult:
    tool: str
    target: str
    argv: list[str]
    returncode: int = -1
    stdout: str = ""
    stderr: str = ""
    health: dict = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    duration_ms: int = 0

    def to_dict(self) -> dict:
        return {
            "tool": self.tool, "target": self.target, "argv": self.argv,
            "returncode": self.returncode, "stdout": self.stdout, "stderr": self.stderr,
            "health": self.health, "errors": self.errors, "duration_ms": self.duration_ms,
        }


class LocalToolsManager:
    """Direct-subprocess tool broker. Replaces `docker exec kali-tools ...`."""

    def __init__(
        self,
        kali_service_url: Optional[str] = None,
        require_kali: bool = False,
        timeout: float = 300.0,
    ) -> None:
        env = os.environ
        # Legacy shim: KALI_TOOLS_URL keeps existing code working after the
        # compose stack is deleted. Default points at the native kali service.
        self.kali_service_url = kali_service_url or env.get(
            "KALI_TOOLS_URL", f"http://127.0.0.1:{env.get('KALI_TOOLS_PORT','3800')}"
        )
        self.require_kali = require_kali
        self.timeout = float(timeout)

    def resolve(self, tool: str) -> Optional[str]:
        return shutil.which(tool)

    async def health(self) -> dict:
        """Probe the kali-tools HTTP service on its exact port (default 3800)."""
        out = {"status": "skipped", "url": self.kali_service_url, "detail": ""}
        if not self.kali_service_url:
            out["detail"] = "no KALI_TOOLS_URL configured"
            return out
        if httpx is None:
            out["status"] = "down"
            out["detail"] = "httpx not installed"
            return out
        try:
            r = await httpx.AsyncClient(timeout=2.0).get(f"{self.kali_service_url}/health")
            out["status"] = "ok" if r.status_code == 200 else "down"
            out["detail"] = f"HTTP {r.status_code}"
        except Exception as e:
            out["status"] = "down"
            out["detail"] = repr(e)
        return out

    def which(self, tools: list[str]) -> dict[str, Optional[str]]:
        return {t: shutil.which(t) for t in tools}

    async def run(
        self,
        *,
        tool: str,
        target: str,
        args: Optional[list[str]] = None,
        cwd: Optional[str] = None,
        env: Optional[dict] = None,
    ) -> ToolResult:
        args = list(args or [])
        errors: list[str] = []
        # Arg hygiene: refuse control chars that could smuggle extra commands.
        for a in args:
            if any(c in a for c in ("\n", "\r", "\0")):
                errors.append(f"control character in arg: {a!r}")
                return ToolResult(tool=tool, target=target, argv=[], errors=errors)
        # Resolve binary on host PATH.
        binary = self.resolve(tool)
        if binary is None:
            errors.append(f"tool not on $PATH: {tool!r}")
            h = await self.health()
            if self.require_kali and h["status"] != "ok":
                errors.append(f"kali-tools service required but {h['status']}: {h['detail']}")
            return ToolResult(tool=tool, target=target, argv=[],
                              health={"tool_resolved": None, "kali_service": h["status"]},
                              errors=errors)
        # Build argv; never inject the target twice. Also skip injection when
        # the caller already embedded the target inside another arg (e.g. a
        # full URL like http://host/path) — appending a bare host would give
        # tools like curl a spurious second operand.
        argv = [binary, *args]
        target_embedded = any(target in a for a in args)
        if not target_embedded:
            argv.append(target)
        # Per-call health probe (tool resolution + kali service status).
        h = await self.health()
        if self.require_kali and h["status"] != "ok":
            errors.append(f"kali-tools service required but {h['status']}: {h['detail']}")
        # Exec.
        t0 = time.monotonic()
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
                env={**os.environ, **(env or {})},
            )
            try:
                stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                errors.append(f"timeout after {self.timeout}s")
                return ToolResult(tool=tool, target=target, argv=argv, returncode=-1,
                                  health={"tool_resolved": binary, "kali_service": h["status"]},
                                  errors=errors,
                                  duration_ms=int((time.monotonic() - t0) * 1000))
        except PermissionError as e:
            errors.append(f"permission denied: {e!r}")
            return ToolResult(tool=tool, target=target, argv=argv,
                              health={"tool_resolved": binary, "kali_service": h["status"]}, errors=errors)
        except OSError as e:
            errors.append(f"os error: {e!r}")
            return ToolResult(tool=tool, target=target, argv=argv,
                              health={"tool_resolved": binary, "kali_service": h["status"]}, errors=errors)
        stdout = stdout_b.decode("utf-8", errors="replace") if stdout_b else ""
        stderr = stderr_b.decode("utf-8", errors="replace") if stderr_b else ""
        rc = proc.returncode if proc.returncode is not None else -1
        return ToolResult(
            tool=tool, target=target, argv=argv, returncode=rc,
            stdout=stdout, stderr=stderr,
            health={"tool_resolved": binary, "kali_service": h["status"]},
            errors=errors,
            duration_ms=int((time.monotonic() - t0) * 1000),
        )


# ---- CLI -----------------------------------------------------------------


async def _cli_run(args: argparse.Namespace) -> int:
    mgr = LocalToolsManager(require_kali=args.require_kali, timeout=args.timeout)
    res = await mgr.run(tool=args.tool, target=args.target, args=args.extra)
    print(json.dumps(res.to_dict(), indent=2))
    return 0 if not res.errors else 1


async def _cli_health(_: argparse.Namespace) -> int:
    mgr = LocalToolsManager()
    h = await mgr.health()
    print(json.dumps(h, indent=2))
    return 0 if h["status"] == "ok" else 1


def _cli_which(args: argparse.Namespace) -> int:
    mgr = LocalToolsManager()
    default = ["nmap", "srm", "pupy", "bloodhound", "feroxbuster", "crackmapexec"]
    res = mgr.which([args.tool] if args.tool else default)
    print(json.dumps(res, indent=2))
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description="Native subprocess tool broker (replaces the container exec pattern)")
    sub = p.add_subparsers(dest="cmd", required=True)
    run_p = sub.add_parser("run", help="run a tool against a target")
    run_p.add_argument("--tool", required=True)
    run_p.add_argument("--target", required=True)
    run_p.add_argument("--require-kali", action="store_true", help="fail if kali-tools service is down")
    run_p.add_argument("--timeout", type=float, default=300.0)
    run_p.add_argument("extra", nargs=argparse.REMAINDER, help="extra argv for the tool")
    sub.add_parser("health", help="probe the kali-tools service")
    which_p = sub.add_parser("which", help="resolve tool(s) on $PATH")
    which_p.add_argument("--tool", default="")
    args = p.parse_args()
    if args.cmd == "run" and args.extra and args.extra[0] == "--":
        args.extra = args.extra[1:]
    if args.cmd == "run":
        return asyncio.run(_cli_run(args))
    if args.cmd == "health":
        return asyncio.run(_cli_health(args))
    if args.cmd == "which":
        return _cli_which(args)
    return 2


if __name__ == "__main__":
    sys.exit(main())
