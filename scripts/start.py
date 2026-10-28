#!/usr/bin/env python3
"""scripts/start.py — boot the native stack (replaces `docker compose up`).

    python3 scripts/start.py                 # core services, real ports
    python3 scripts/start.py --shadow        # +100 on every core port (3980..)
    python3 scripts/start.py --only brain,kali-tools
    python3 scripts/start.py --detach        # start and return; children keep running
    python3 scripts/start.py --hold 20       # keep supervising for N seconds
"""
from __future__ import annotations

import argparse
import asyncio
import signal
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from runtime.launcher import NativeLauncher          # noqa: E402
from runtime.service_registry import load_registry    # noqa: E402

SHADOW_OFFSET = 100


async def _run(args: argparse.Namespace) -> int:
    services = load_registry()
    if not args.with_optional:
        services = [s for s in services if not s.optional]
    only = [s.strip() for s in args.only.split(",") if s.strip()] if args.only else None
    offset = SHADOW_OFFSET if args.shadow else 0

    launcher = NativeLauncher(services, port_offset=offset)
    report = await launcher.start(only=only)
    print(report.summary())

    if args.detach:
        return 0 if not report.failed else 1

    stop = asyncio.Event()

    def _signal(*_: object) -> None:
        stop.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _signal)
        except NotImplementedError:      # pragma: no cover - non-POSIX
            pass

    if args.hold:
        try:
            await asyncio.wait_for(stop.wait(), timeout=args.hold)
        except asyncio.TimeoutError:
            pass
    else:
        await stop.wait()

    stopped = await launcher.stop()
    print(f"stopped: {', '.join(stopped) if stopped else 'none'}")
    return 0 if not report.failed else 1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--shadow", action="store_true", help=f"add {SHADOW_OFFSET} to core ports")
    ap.add_argument("--only", default="")
    ap.add_argument("--detach", action="store_true")
    ap.add_argument("--hold", type=float, default=0.0)
    ap.add_argument("--with-optional", action="store_true")
    args = ap.parse_args()
    return asyncio.run(_run(args))


if __name__ == "__main__":
    sys.exit(main())
