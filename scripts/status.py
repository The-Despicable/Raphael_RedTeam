#!/usr/bin/env python3
"""scripts/status.py — deterministic health sweep for the native stack.

    python3 scripts/status.py            # human table, exit 1 if a core service is down
    python3 scripts/status.py --json
    python3 scripts/status.py --shadow   # probe the shadow ports (3980..)
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

from runtime import pidfiles                          # noqa: E402
from runtime.health import probe_service               # noqa: E402
from runtime.service_registry import load_registry, shadow_ports  # noqa: E402


def _shift(spec, ports: dict[str, int]):
    new_port = ports.get(spec.name)
    if not new_port:
        return spec
    cmd = list(spec.command)
    for i, token in enumerate(cmd):
        if token == "--port" and i + 1 < len(cmd):
            cmd[i + 1] = str(new_port)
    return replace(spec, port=new_port, command=cmd)


async def _collect(with_optional: bool, shadow: bool) -> list[dict]:
    services = load_registry()
    ports = shadow_ports(services) if shadow else {}
    rows = []
    for raw in services:
        if raw.optional and not with_optional:
            continue
        spec = _shift(raw, ports)
        res = await probe_service(spec)
        pid = pidfiles.read(raw.name) if pidfiles.alive(raw.name) else None
        rows.append({
            "name": spec.name,
            "port": spec.port,
            "pid": pid,
            "ok": res.ok,
            "detail": res.detail,
            "optional": raw.optional,
        })
    return rows


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--with-optional", action="store_true")
    ap.add_argument("--shadow", action="store_true")
    args = ap.parse_args()

    rows = asyncio.run(_collect(args.with_optional, args.shadow))

    if args.json:
        print(json.dumps(rows, indent=2))
    else:
        for r in rows:
            mark = "OK  " if r["ok"] else ("SKIP" if r["optional"] else "DOWN")
            print(f"{mark} {r['name']:<16} :{r['port']:<6} pid={r['pid'] or '-':<8} {r['detail']}")

    failed = [r for r in rows if not r["ok"] and not r["optional"]]
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
