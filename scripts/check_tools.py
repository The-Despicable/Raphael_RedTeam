#!/usr/bin/env python3
"""scripts/check_tools.py — verify the host toolchain against configs/tool-catalog.json.

Tools are resolved on PATH, or as repo-relative paths (sliver/, data/neo4j/).
Each entry may list several acceptable binaries (e.g. crackmapexec OR nxc).

    python3 scripts/check_tools.py            # human table
    python3 scripts/check_tools.py --json     # machine output
    python3 scripts/check_tools.py --strict   # exit 1 if a REQUIRED tool is missing

`required: false` tools are reported but never fail --strict (pupy is the known
GAP-006 deferral).
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CATALOG = REPO / "configs" / "tool-catalog.json"


def resolve(candidates: list[str]) -> str | None:
    for c in candidates:
        if "/" in c:
            p = REPO / c
            if p.is_file():
                return str(p)
        else:
            found = shutil.which(c)
            if found:
                return found
    return None


def probe(argv: list[str], path: str | None) -> bool:
    if not path:
        return False
    if not argv:
        return True
    # argv[0] is the nominal tool name; run the resolved binary instead.
    cmd = [path, *argv[1:]]
    try:
        subprocess.run(cmd, capture_output=True, timeout=10, check=False)
        return True
    except (OSError, subprocess.TimeoutExpired):
        return False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--no-probe", action="store_true")
    args = ap.parse_args()

    data = json.loads(CATALOG.read_text())
    results = []
    for entry in data["tools"]:
        path = resolve(entry["binaries"])
        ok = bool(path)
        if ok and not args.no_probe:
            ok = probe(entry.get("probe", []), path)
        results.append({
            "name": entry["name"],
            "binaries": entry["binaries"],
            "path": path,
            "found": bool(path),
            "probe_ok": ok,
            "required": entry.get("required", False),
            "warn_only": entry.get("warn", False),
            "category": entry.get("category", ""),
            "install": entry.get("install", ""),
            "deferred_reason": entry.get("deferred_reason"),
        })

    if args.json:
        json.dump(results, sys.stdout, indent=2)
        print()
    else:
        for r in results:
            if r["found"] and r["probe_ok"]:
                mark = "OK   "
            elif r["found"]:
                mark = "WARN "
            elif r["required"]:
                mark = "FAIL "
            else:
                mark = "SKIP "
            print(f"{mark} {r['name']:<16} {r['path'] or '-':<44} {r['install']}")
            if r["deferred_reason"]:
                print(f"      deferred: {r['deferred_reason']}")

    missing_required = [r for r in results if r["required"] and not r["probe_ok"]]
    if args.strict and missing_required:
        print(f"\n{len(missing_required)} required tool(s) missing:", file=sys.stderr)
        for r in missing_required:
            print(f"  - {r['name']}: install with `{r['install']}`", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
