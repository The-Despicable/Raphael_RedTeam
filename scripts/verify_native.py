#!/usr/bin/env python3
"""scripts/verify_native.py — in-process proof that the stack boots natively.

Starts every core service on the deterministic shadow block (3980+), waits for
health, re-probes, kills one service to prove supervisor respawn, then stops.
Everything happens inside one process, so it works under WSL where background
jobs die with the parent shell.

    python3 scripts/verify_native.py
    python3 scripts/verify_native.py --json
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from dataclasses import replace
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from runtime import pidfiles                                    # noqa: E402
from runtime.health import probe_service                        # noqa: E402
from runtime.launcher import NativeLauncher                     # noqa: E402
from runtime.service_registry import load_registry, shadow_ports  # noqa: E402


def _shift(spec, ports: dict[str, int]):
    new = ports.get(spec.name)
    if not new:
        return spec
    cmd = list(spec.command)
    for i, tok in enumerate(cmd):
        if tok == "--port" and i + 1 < len(cmd):
            cmd[i + 1] = str(new)
    return replace(spec, port=new, command=cmd)


async def main_async(json_out: bool) -> int:
    services = [s for s in load_registry() if not s.optional]
    ports = shadow_ports(services)
    launcher = NativeLauncher(services, port_offset=min(ports.values()))
    report = await launcher.start()
    await asyncio.sleep(3)

    rows = []
    for raw in services:
        spec = _shift(raw, ports)
        res = await probe_service(spec)
        rows.append({"name": spec.name, "port": spec.port, "ok": res.ok, "detail": res.detail})

    # respawn proof: SIGKILL one healthily-started service, wait, re-probe
    respawn = {"name": None, "ok": False, "detail": "not attempted"}
    target = next((r["name"] for r in rows if r["ok"]), None)
    if target:
        raw = next(s for s in services if s.name == target)
        pid = pidfiles.read(target)
        try:
            import os
            os.kill(pid, 9)
        except Exception as e:  # noqa: BLE001
            respawn = {"name": target, "ok": False, "detail": f"kill failed: {e!r}"}
        else:
            spec = _shift(raw, ports)
            deadline = asyncio.get_event_loop().time() + 45
            while asyncio.get_event_loop().time() < deadline:
                await asyncio.sleep(2)
                res = await probe_service(spec)
                if res.ok and pidfiles.read(target) not in (None, pid):
                    respawn = {"name": target, "ok": True,
                               "detail": f"respawned pid {pidfiles.read(target)}"}
                    break
            else:
                respawn = {"name": target, "ok": False, "detail": "no respawn within 45s"}

    stopped = await launcher.stop()
    ok = all(r["ok"] for r in rows) and respawn["ok"] and not report.failed

    if json_out:
        print(json.dumps({"services": rows, "respawn": respawn,
                          "started": report.started, "skipped": report.skipped,
                          "failed": report.failed, "stopped": stopped, "ok": ok}, indent=2))
    else:
        for r in rows:
            print(f"{'OK  ' if r['ok'] else 'FAIL'} {r['name']:<16} :{r['port']:<6} {r['detail'][:90]}")
        print(f"{'OK  ' if respawn['ok'] else 'FAIL'} respawn {respawn['name']}: {respawn['detail']}")
        print(f"started={len(report.started)} skipped={len(report.skipped)} "
              f"failed={len(report.failed)} stopped={len(stopped)}")
        print("VERDICT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    return asyncio.run(main_async(args.json))


if __name__ == "__main__":
    sys.exit(main())
