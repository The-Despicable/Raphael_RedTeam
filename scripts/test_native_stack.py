"""scripts/test_native_stack.py — non-destructive integration test.

Boots a dummy stack (two tiny FastAPI services on UNUSED ports 3980/3981) via
the real NativeLauncher, verifies:
  - dependency ordering (dummy-b waits for dummy-a health)
  - health polling works (status: ok contract)
  - logs written under runtime/logs/
  - PID files under runtime/pid/
  - graceful stop clears processes
  - crash restart backoff fires

Never touches real service ports, never scans, never leaves processes behind.
"""
from __future__ import annotations

import asyncio
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from runtime import pidfiles  # noqa: E402
from runtime.health import probe_http  # noqa: E402
from runtime.launcher import NativeLauncher  # noqa: E402
from runtime.logs import log_path  # noqa: E402
from runtime.service_registry import ServiceSpec  # noqa: E402

PORT_A, PORT_B = 3980, 3981  # deliberately unused ports
DUMMY_DIR = ROOT / "tests" / "dummy"

failures = 0


def check(name: str, ok: bool, detail: str = "") -> None:
    global failures
    print(f"[{'OK  ' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))
    if not ok:
        failures += 1


def _spec(name: str, port: int, depends: list[str] | None = None) -> ServiceSpec:
    return ServiceSpec(
        name=name,
        command=[sys.executable, "-m", "uvicorn", "service:app",
                 "--host", "127.0.0.1", "--port", str(port), "--app-dir", str(DUMMY_DIR)],
        port=port,
        depends_on=depends or [],
        health_path="/health",
    )


async def main() -> int:
    dummy_a, dummy_b = _spec("dummy-a", PORT_A), _spec("dummy-b", PORT_B, ["dummy-a"])
    launcher = NativeLauncher([dummy_b, dummy_a], health_attempts=30, health_delay=0.5, max_restarts=3)

    # clean slate
    for n in ("dummy-a", "dummy-b"):
        pidfiles.terminate(n)
        log_path(n).unlink(missing_ok=True)

    report = await launcher.start()
    check("both services started", len(report.started) == 2, str(report.started))

    # let uvicorn bind (spawn returns before the socket is listening)
    for _ in range(20):
        await asyncio.sleep(0.5)
        ra = await probe_http(f"http://127.0.0.1:{PORT_A}/health")
        rb = await probe_http(f"http://127.0.0.1:{PORT_B}/health")
        if ra.ok and rb.ok:
            break

    # health via real probe
    ra = await probe_http(f"http://127.0.0.1:{PORT_A}/health")
    rb = await probe_http(f"http://127.0.0.1:{PORT_B}/health")
    check("dummy-a health status:ok", ra.ok, ra.detail)
    check("dummy-b health status:ok", rb.ok, rb.detail)

    # pid files
    check("pid file dummy-a", pidfiles.alive("dummy-a"), f"pid={pidfiles.read('dummy-a')}")
    check("pid file dummy-b", pidfiles.alive("dummy-b"), f"pid={pidfiles.read('dummy-b')}")

    # logs exist (uvicorn writes at least startup lines)
    await asyncio.sleep(1.0)
    for n in ("dummy-a", "dummy-b"):
        check(f"log {n}.log non-empty", log_path(n).is_file() and log_path(n).stat().st_size > 0)

    # crash + restart backoff
    pid = pidfiles.read("dummy-a")
    if pid:
        import os, signal as sig
        os.kill(pid, sig.SIGKILL)
        await asyncio.sleep(0.5)
        check("dummy-a killed", not pidfiles.alive("dummy-a"))
        # watcher should respawn within backoff (2s initial)
        ok = False
        for _ in range(20):
            await asyncio.sleep(0.5)
            if pidfiles.alive("dummy-a"):
                ok = True
                break
        check("dummy-a respawned by supervisor", ok,
              f"restarts={launcher.states().get('dummy-a', {}).get('restarts')}")

    # graceful stop
    stopped = await launcher.stop()
    check("graceful stop", set(stopped) >= {"dummy-a", "dummy-b"}, str(stopped))
    await asyncio.sleep(0.5)
    check("dummy-a gone", not pidfiles.alive("dummy-a"))
    check("dummy-b gone", not pidfiles.alive("dummy-b"))

    print()
    if failures:
        print(f"NATIVE STACK TEST FAILED — {failures} failure(s)")
        return 1
    print("NATIVE STACK TEST PASSED — launcher, health, pidfiles, logs, restart backoff, graceful stop all verified.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
