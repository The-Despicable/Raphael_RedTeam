"""runtime.launcher — asyncio/subprocess process supervisor.

Replaces `docker compose up/down`:
  - dependency-ordered startup (compose depends_on equivalent)
  - health polling before dependents start
  - per-service log streaming to runtime/logs/<name>.log
  - PID files in runtime/pid/
  - graceful termination (SIGTERM -> SIGKILL)
  - restart backoff on crash
  - per-service startup guard (missing command / busy port = skip + report)
"""
from __future__ import annotations

import asyncio
import shutil
import signal
import sys
import time
from dataclasses import dataclass, field
from typing import Optional

from runtime import pidfiles
from runtime.env import as_export, ensure_dirs
from runtime.health import HealthResult, wait_for_service
from runtime.logs import drain_to_file, log_path
from runtime.service_registry import ServiceSpec, order_by_dependencies


@dataclass
class _ProcState:
    spec: ServiceSpec
    proc: Optional[asyncio.subprocess.Process] = None
    started_at: float = 0.0
    restarts: int = 0
    last_crash: float = 0.0
    backoff: float = 2.0
    watcher: Optional[asyncio.Task] = None


@dataclass
class LaunchReport:
    started: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    health: list[HealthResult] = field(default_factory=list)

    def summary(self) -> str:
        lines = []
        for h in self.health:
            lines.append(str(h))
        lines.append(f"started={len(self.started)} skipped={len(self.skipped)} failed={len(self.failed)}")
        return "\n".join(lines)


class NativeLauncher:
    """Single-command native stack supervisor."""

    def __init__(
        self,
        services: list[ServiceSpec],
        *,
        health_attempts: int = 30,
        health_delay: float = 1.0,
        max_restarts: int = 5,
    ) -> None:
        self.services = order_by_dependencies(services)
        self.health_attempts = health_attempts
        self.health_delay = health_delay
        self.max_restarts = max_restarts
        self._states: dict[str, _ProcState] = {}

    # ---------------------------------------------------------------- start

    async def start(self, *, only: Optional[list[str]] = None) -> LaunchReport:
        ensure_dirs()
        report = LaunchReport()
        base_env = as_export()

        for spec in self.services:
            if only and spec.name not in only:
                continue
            # startup guards
            exe = spec.command[0]
            resolved = shutil.which(exe) if "/" not in exe else exe
            if resolved is None and not (spec.optional and True):
                report.skipped.append(f"{spec.name}: command not found ({exe!r})")
                continue
            if resolved is None:
                report.skipped.append(f"{spec.name}: optional command not found ({exe!r})")
                continue
            if pidfiles.alive(spec.name):
                report.skipped.append(f"{spec.name}: already running (pid {pidfiles.read(spec.name)})")
                continue
            if spec.port and await self._port_busy(spec.port):
                report.skipped.append(f"{spec.name}: port {spec.port} busy")
                continue
            # dependency ordering: wait for deps to be healthy
            dep_ok = await self._wait_deps(spec, report)
            if not dep_ok:
                report.failed.append(f"{spec.name}: dependencies not healthy")
                continue

            try:
                proc = await self._spawn(spec, base_env)
            except Exception as e:
                report.failed.append(f"{spec.name}: spawn failed: {e!r}")
                continue

            state = _ProcState(spec=spec, proc=proc, started_at=time.monotonic())
            self._states[spec.name] = state
            pidfiles.write(spec.name, proc.pid)
            state.watcher = asyncio.create_task(self._watch(state, report))
            report.started.append(spec.name)
            # Block until this service is actually healthy before starting
            # dependents (deterministic report + ready upstream).
            if spec.health_kind != "none" and spec.port:
                hres = await wait_for_service(
                    spec, attempts=max(3, self.health_attempts // 2), delay=self.health_delay
                )
                if not hres.ok:
                    report.health.append(hres)

        # final health sweep for everything started
        from runtime.health import sweep
        started_specs = [s for s in self.services if s.name in report.started]
        report.health = await sweep(started_specs)
        return report

    async def _spawn(self, spec: ServiceSpec, base_env: dict) -> asyncio.subprocess.Process:
        log_path(spec.name).touch()
        logf = log_path(spec.name).open("ab")
        env = {**base_env, **spec.env}
        return await asyncio.create_subprocess_exec(
            *spec.command,
            stdout=logf,
            stderr=asyncio.subprocess.STDOUT,
            env={**env, "PATH": __import__("os").environ["PATH"]},
        )

    async def _wait_deps(self, spec: ServiceSpec, report: LaunchReport) -> bool:
        for dep in spec.depends_on:
            dep_state = self._states.get(dep)
            if dep_state is None:
                continue  # dep was skipped or optional; proceed
            res = await wait_for_service(dep_state.spec, attempts=self.health_attempts, delay=self.health_delay)
            if not res.ok:
                report.failed.append(f"{spec.name}: dep {dep} unhealthy: {res.detail}")
                return False
        return True

    # ---------------------------------------------------------------- watch

    async def _watch(self, state: _ProcState, report: LaunchReport) -> None:
        """Restart backoff loop. Dies permanently after max_restarts."""
        while True:
            assert state.proc is not None
            rc = await state.proc.wait()
            # process died
            state.last_crash = time.monotonic()
            pidfiles.clear(state.spec.name)
            if state.restarts >= self.max_restarts:
                report.failed.append(
                    f"{state.spec.name}: exhausted {self.max_restarts} restarts (last rc={rc})")
                return
            state.restarts += 1
            state.backoff = min(state.backoff * 2, 60.0)
            await asyncio.sleep(state.backoff)
            try:
                state.proc = await self._spawn(state.spec, as_export())
            except Exception:
                report.failed.append(f"{state.spec.name}: respawn failed")
                return
            pidfiles.write(state.spec.name, state.proc.pid)

    # ---------------------------------------------------------------- stop

    async def stop(self, *, only: Optional[list[str]] = None) -> list[str]:
        stopped: list[str] = []
        # reverse dependency order
        for spec in reversed(self.services):
            if only and spec.name not in only:
                continue
            state = self._states.get(spec.name)
            if state and state.proc and state.proc.returncode is None:
                state.proc.terminate()
                try:
                    await asyncio.wait_for(state.proc.wait(), timeout=8.0)
                except asyncio.TimeoutError:
                    state.proc.kill()
                    await state.proc.wait()
                if state.watcher:
                    state.watcher.cancel()
                    try:
                        await state.watcher
                    except asyncio.CancelledError:
                        pass
                stopped.append(spec.name)
            elif pidfiles.alive(spec.name):
                # started outside this launcher instance (PID file present)
                pidfiles.terminate(spec.name)
                stopped.append(spec.name + " (pidfile)")
        return stopped

    # ---------------------------------------------------------------- misc

    @staticmethod
    async def _port_busy(port: int) -> bool:
        try:
            fut = asyncio.open_connection("127.0.0.1", port)
            r, w = await asyncio.wait_for(fut, timeout=0.5)
            w.close()
            return True
        except Exception:
            return False

    def states(self) -> dict[str, dict]:
        return {
            name: {"pid": s.proc.pid if s.proc else None,
                   "restarts": s.restarts,
                   "alive": bool(s.proc and s.proc.returncode is None)}
            for name, s in self._states.items()
        }
