#!/usr/bin/env python3
"""scripts/stop.py — stop the native stack via PID files (SIGTERM -> SIGKILL).

    python3 scripts/stop.py
    python3 scripts/stop.py --only brain,kali-tools
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from runtime import pidfiles                        # noqa: E402
from runtime.service_registry import load_registry   # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="")
    args = ap.parse_args()
    only = {s.strip() for s in args.only.split(",") if s.strip()} or None

    stopped: list[str] = []
    for spec in reversed(load_registry()):
        if only and spec.name not in only:
            continue
        if pidfiles.alive(spec.name):
            pidfiles.terminate(spec.name)
            stopped.append(spec.name)
        else:
            pidfiles.clear(spec.name)
    print(f"stopped: {', '.join(stopped) if stopped else 'none'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
