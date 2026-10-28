#!/usr/bin/env python3
"""scripts/gen_env.py — derive shell/dotenv environment from configs/services.json.

configs/services.json is the single source of truth for service ports. Nothing
else may hardcode a port: env.sh sources this, and scripts/check_consistency.py
fails the build if a literal port reappears.

Usage:
    eval "$(python3 scripts/gen_env.py --shell)"
    python3 scripts/gen_env.py --json
    python3 scripts/gen_env.py --dotenv
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SERVICES = REPO / "configs" / "services.json"


def load(path: Path = SERVICES) -> list[dict]:
    data = json.loads(path.read_text())
    services = data.get("services", [])
    if not services:
        raise SystemExit(f"{path}: no services defined")
    ports = [s["port"] for s in services]
    if len(ports) != len(set(ports)):
        dupes = sorted({p for p in ports if ports.count(p) > 1})
        raise SystemExit(f"{path}: duplicate ports {dupes}")
    for s in services:
        if not 1024 <= int(s["port"]) <= 65535:
            raise SystemExit(f"{path}: port out of range for {s['name']}")
    return services


def env_name(service: str) -> str:
    """CLOAK_SERVICE -> CLOAK_PORT (short form used by the shell scripts)."""
    base = service[:-len("-service")] if service.endswith("-service") else service
    return base.upper().replace("-", "_") + "_PORT"


def env_name_full(service: str) -> str:
    return service.upper().replace("-", "_") + "_PORT"


def interpreter() -> str:
    venv = REPO / ".venv" / "bin" / "python"
    return str(venv) if venv.is_file() else "python3"


def shell(services: list[dict]) -> str:
    src = REPO / 'src'
    preexisting = '${PYTHONPATH:+:$PYTHONPATH}'
    out = [
        f'export RAPHAEL_PY="{interpreter()}"',
        f'export PYTHONPATH="{REPO}:{src}{preexisting}"',
    ]
    for s in services:
        out.append(f'export {env_name(s["name"])}="{s["port"]}"')
        full = env_name_full(s["name"])
        if full != env_name(s["name"]):
            out.append(f'export {full}="{s["port"]}"')
        if s.get("secondary_port"):
            out.append(f'export {env_name(s["name"]).replace("_PORT", "_ALT_PORT")}="{s["secondary_port"]}"')
    # Compatibility shim consumed by orchestrator/brain code.
    kali = next((s for s in services if s["name"] == "kali-tools"), None)
    if kali:
        out.append(f'export KALI_TOOLS_URL="http://127.0.0.1:{kali["port"]}"')
    out.append(f'export RAPHAEL_SERVICES_JSON="{SERVICES}"')
    return "\n".join(out)


def dotenv(services: list[dict]) -> str:
    lines = [f"KALI_TOOLS_URL=http://127.0.0.1:{next(s['port'] for s in services if s['name'] == 'kali-tools')}"]
    for s in services:
        lines.append(f"{env_name(s['name'])}={s['port']}")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--shell", action="store_true")
    g.add_argument("--dotenv", action="store_true")
    g.add_argument("--json", action="store_true")
    args = ap.parse_args()

    services = load()
    if args.shell:
        print(shell(services))
    elif args.dotenv:
        print(dotenv(services))
    else:
        resolved = []
        for s in services:
            entry = dict(s)
            entry["command"] = [
                interpreter() if a == "${RAPHAEL_PY}" else os.path.expandvars(a)
                for a in s["command"]
            ]
            resolved.append(entry)
        print(json.dumps({"services": resolved}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
