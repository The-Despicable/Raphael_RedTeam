"""orchestrator.runtime.backends.sandbox — SandboxBackend abstraction.

Docker becomes an *optional* backend selected by SANDBOX_BACKEND=docker.
Default is host execution with a timeout guard, rate limiter, and capped args.
This replaces orchestrator/runtime/docker_client.py as the execution surface;
docker_client remains importable only under the docker backend.
"""
from __future__ import annotations

import asyncio
import os
import shlex
import shutil
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class SandboxResult:
    command: list[str]
    returncode: int = -1
    stdout: str = ""
    stderr: str = ""
    errors: list[str] = field(default_factory=list)
    duration_ms: int = 0
    backend: str = "host"

    def to_dict(self) -> dict:
        return {
            "command": self.command, "returncode": self.returncode,
            "stdout": self.stdout, "stderr": self.stderr,
            "errors": self.errors, "duration_ms": self.duration_ms,
            "backend": self.backend,
        }


class RateLimiter:
    """Minimal spacing + concurrency limiter. Cannot be disabled by callers."""

    def __init__(self, max_concurrency: int = 4, min_spacing: float = 0.1) -> None:
        if max_concurrency < 1:
            raise ValueError("max_concurrency >= 1 required (limiter cannot be disabled)")
        self._sem = asyncio.Semaphore(max_concurrency)
        self._min_spacing = min_spacing
        self._lock = asyncio.Lock()
        self._last = 0.0

    async def __aenter__(self) -> "RateLimiter":
        await self._sem.acquire()
        async with self._lock:
            gap = time.monotonic() - self._last
            if gap < self._min_spacing:
                await asyncio.sleep(self._min_spacing - gap)
        return self

    async def __aexit__(self, *exc) -> None:
        self._last = time.monotonic()
        self._sem.release()


class SandboxBackend(ABC):
    """Interface every sandbox implements."""

    @abstractmethod
    async def run(self, command: list[str], *, timeout: float = 300.0,
                  cwd: Optional[str] = None, env: Optional[dict] = None) -> SandboxResult:
        ...

    @abstractmethod
    async def available(self) -> bool:
        ...


class HostSandboxBackend(SandboxBackend):
    """Direct subprocess execution with guards:
    - command must resolve on PATH (or be an absolute path)
    - args capped at MAX_ARGS, each arg capped at MAX_ARG_LEN
    - control characters refused
    - timeout enforced (kill on expiry)
    - rate limited
    """

    MAX_ARGS = 64
    MAX_ARG_LEN = 4096

    def __init__(self, rate_limiter: Optional[RateLimiter] = None) -> None:
        self._limiter = rate_limiter or RateLimiter()

    async def available(self) -> bool:
        return True  # host is always available

    async def run(self, command: list[str], *, timeout: float = 300.0,
                  cwd: Optional[str] = None, env: Optional[dict] = None) -> SandboxResult:
        errors: list[str] = []
        if not command:
            return SandboxResult(command=[], errors=["empty command"])
        if len(command) > self.MAX_ARGS:
            return SandboxResult(command=command[:self.MAX_ARGS], errors=[f"too many args (> {self.MAX_ARGS})"])
        for a in command:
            if len(a) > self.MAX_ARG_LEN:
                errors.append("arg exceeds max length")
                return SandboxResult(command=command, errors=errors)
            if any(c in a for c in ("\n", "\r", "\x00")):
                errors.append(f"control character in arg: {a!r}")
                return SandboxResult(command=command, errors=errors)

        exe = command[0]
        resolved = shutil.which(exe) if "/" not in exe else exe
        if resolved is None:
            return SandboxResult(command=command, errors=[f"command not found: {exe!r}"])

        argv = [resolved, *command[1:]]
        t0 = time.monotonic()
        async with self._limiter:
            try:
                proc = await asyncio.create_subprocess_exec(
                    *argv,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=cwd,
                    env={**os.environ, **(env or {})},
                )
                try:
                    out_b, err_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
                except asyncio.TimeoutError:
                    proc.kill()
                    await proc.wait()
                    errors.append(f"timeout after {timeout}s")
                    return SandboxResult(command=argv, returncode=-1, errors=errors,
                                         duration_ms=int((time.monotonic() - t0) * 1000))
            except OSError as e:
                errors.append(f"os error: {e!r}")
                return SandboxResult(command=argv, errors=errors,
                                     duration_ms=int((time.monotonic() - t0) * 1000))
        return SandboxResult(
            command=argv,
            returncode=proc.returncode if proc.returncode is not None else -1,
            stdout=out_b.decode("utf-8", errors="replace") if out_b else "",
            stderr=err_b.decode("utf-8", errors="replace") if err_b else "",
            errors=errors,
            duration_ms=int((time.monotonic() - t0) * 1000),
            backend="host",
        )


class DockerSandboxBackend(SandboxBackend):
    """Optional fallback. Conditionally imports docker; if the daemon is down
    or the SDK is missing, `available()` returns False and callers fall back
    to HostSandboxBackend."""

    def __init__(self, image: str = "kali-tools:latest") -> None:
        self.image = image
        self._client = None

    async def available(self) -> bool:
        try:
            import docker  # noqa: F401
        except ImportError:
            return False
        try:
            import docker
            self._client = docker.from_env()
            self._client.ping()
            return True
        except Exception:
            return False

    async def run(self, command: list[str], *, timeout: float = 300.0,
                  cwd: Optional[str] = None, env: Optional[dict] = None) -> SandboxResult:
        if not await self.available():
            return SandboxResult(command=command, errors=["docker backend unavailable"])
        t0 = time.monotonic()
        try:
            # run in a blocking thread; docker SDK is sync
            out = await asyncio.to_thread(
                self._client.containers.run,
                self.image,
                command=command,
                remove=True,
                detach=False,
                environment=env or {},
            )
            stdout = out.decode("utf-8", errors="replace") if isinstance(out, bytes) else str(out)
            return SandboxResult(command=command, returncode=0, stdout=stdout,
                                 duration_ms=int((time.monotonic() - t0) * 1000),
                                 backend="docker")
        except Exception as e:
            return SandboxResult(command=command, errors=[f"docker run failed: {e!r}"],
                                 duration_ms=int((time.monotonic() - t0) * 1000),
                                 backend="docker")


def get_backend(name: Optional[str] = None) -> SandboxBackend:
    """Factory honoring SANDBOX_BACKEND env. Docker requested but unavailable
    must be handled by the caller (we return host with a note in errors on use)."""
    name = name or os.environ.get("SANDBOX_BACKEND", "host")
    if name == "docker":
        d = DockerSandboxBackend()
        return d
    return HostSandboxBackend()
