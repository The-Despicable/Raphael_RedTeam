#!/usr/bin/env python3
"""scripts/test_external_bridge.py — non-destructive smoke test.

Checks (all read-only, no hostile actions, no engagement needed):
  1. bridge spawns and answers system.health (JSON lines on stdout)
  2. Kali tools service reachable (when KALI_TOOLS_URL set)
  3. DNS resolves example.com (canary)
  4. Tor GET canary through SOCKS (curl --socks5-hostname) — when Tor configured
  5. VPN interface present (ip link show tun0) — optional / --with-vpn
  6. Sliver operator config exists (when SLIVER_OPERATOR_CONFIG set)
  7. Audit trail written under projects/<engagement>/bridge/

Exit code 0 when every applicable check passes, 1 otherwise; skipped
components (unconfigured) are reported but do not fail the run.

Usage:  python scripts/test_external_bridge.py [--skip-tor] [--with-vpn]
        python scripts/test_external_bridge.py --json     (machine output)
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

RESULTS: list = []
AUDIT_DIR = None  # shared across bridge calls so the audit check sees history


def record(name, status, detail=""):
    RESULTS.append({"check": name, "status": status, "detail": str(detail)[:300]})
    mark = {"PASS": "[PASS]", "FAIL": "[FAIL]", "SKIP": "[SKIP]"}.get(status, "[??]")
    print(f"{mark} {name:<38} {detail}")


def env(name, default=""):
    return os.environ.get(name, default)


async def bridge_call(payload, timeout=30):
    """One-shot JSON-RPC call to a fresh bridge subprocess."""
    proc = await asyncio.create_subprocess_exec(
        sys.executable, "-m", "bridge.raphael_bridge",
        "--audit-dir", AUDIT_DIR,
        cwd=str(REPO_ROOT),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        out, _ = await asyncio.wait_for(
            proc.communicate(json.dumps(payload).encode() + b"\n"),
            timeout=timeout,
        )
        lines = [ln for ln in out.decode().splitlines() if ln.strip()]
        if not lines:
            return None
        return json.loads(lines[0])
    finally:
        if proc.returncode is None:
            proc.kill()


def run(cmd, timeout=15):
    try:
        p = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            cwd=str(REPO_ROOT),
        )
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except (OSError, subprocess.TimeoutExpired) as e:
        return 127, str(e)


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-tor", action="store_true")
    ap.add_argument("--with-vpn", action="store_true",
                    help="also require a tun0 interface (fails when absent)")
    ap.add_argument("--json", action="store_true", help="JSON report to stdout")
    args = ap.parse_args()

    global AUDIT_DIR
    AUDIT_DIR = env("SMOKE_AUDIT_DIR") or tempfile.mkdtemp(prefix="smoke-bridge-")

    # 1. bridge health -------------------------------------------------------
    resp = await bridge_call({"jsonrpc": "2.0", "id": "smoke",
                              "method": "system.health", "params": {}})
    if resp and resp.get("result", {}).get("status") in ("ok", "degraded"):
        res = resp["result"]
        record("bridge.system.health", "PASS",
               f"status={res['status']} degraded={res['degraded']}")
    else:
        record("bridge.system.health", "FAIL", f"no valid response: {resp}")

    # 2. kali health ----------------------------------------------------------
    kali = env("KALI_TOOLS_URL")
    if kali:
        code, body = run(["curl", "-sS", "-m", "5", "-o", "/dev/null",
                          "-w", "%{http_code}", f"{kali.rstrip('/')}/"])
        (record("kali.tools.reachable", "PASS", f"{kali} -> {body.strip()[-3:]}")
         if code == 0 and body.strip().endswith(tuple("0123456789"))
         else record("kali.tools.reachable", "FAIL", f"{kali}: {body[:120]}"))
    else:
        record("kali.tools.reachable", "SKIP", "KALI_TOOLS_URL not set")

    # 3. DNS canary -------------------------------------------------------------
    resp = await bridge_call({"jsonrpc": "2.0", "id": "dns",
                              "method": "dns.resolve",
                              "params": {"host": "example.com"}})
    r = (resp or {}).get("result", {})
    if r.get("addresses"):
        record("dns.resolve.example.com", "PASS",
               ",".join(r["addresses"][:3]) + f" via {r.get('resolver')}")
    else:
        record("dns.resolve.example.com", "FAIL", f"{resp}")

    # 4. tor canary --------------------------------------------------------------
    tor_socks = env("TOR_SOCKS")
    if tor_socks and not args.skip_tor:
        code, body = run(["curl", "-sS", "-m", "20", "--socks5-hostname",
                          tor_socks, "https://api.ipify.org"])
        if code == 0 and body.strip():
            record("tor.canary.exit_ip", "PASS", f"exit={body.strip()}")
        else:
            record("tor.canary.exit_ip", "FAIL", f"{tor_socks}: {body.strip()[:120]}")
    elif args.skip_tor:
        record("tor.canary.exit_ip", "SKIP", "--skip-tor")
    else:
        record("tor.canary.exit_ip", "SKIP", "TOR_SOCKS not set")

    # 5. vpn interface (optional) -------------------------------------------------
    if shutil.which("ip"):
        code, body = run(["ip", "link", "show", "tun0"])
        tun = code == 0
        if args.with_vpn:
            record("vpn.tun0_interface", "PASS" if tun else "FAIL",
                   "tun0 present" if tun else "no tun0 (VPN not up)")
        else:
            record("vpn.tun0_interface",
                   "PASS" if tun else "SKIP",
                   "present" if tun else "not up (optional)")
    else:
        record("vpn.tun0_interface", "SKIP", "iproute2 missing")

    # 6. sliver operator config ----------------------------------------------------
    sliver_cfg = env("SLIVER_OPERATOR_CONFIG")
    if sliver_cfg:
        p = Path(sliver_cfg)
        record("sliver.operator_config",
               "PASS" if p.is_file() else "FAIL",
               f"{sliver_cfg} " + ("exists" if p.is_file() else "MISSING"))
    else:
        record("sliver.operator_config", "SKIP",
               "SLIVER_OPERATOR_CONFIG not set")

    # 7. audit trail ------------------------------------------------------------------
    resp = await bridge_call({"jsonrpc": "2.0", "id": "logs",
                              "method": "bridge.logs", "params": {"last_n": 5}})
    r = (resp or {}).get("result", {})
    if r.get("lines"):
        record("bridge.audit_trail", "PASS",
               f"{r.get('audit_file')} ({r['count']} records)")
    else:
        record("bridge.audit_trail", "FAIL", f"{resp}")

    fails = sum(1 for x in RESULTS if x["status"] == "FAIL")
    if args.json:
        print(json.dumps({"checks": RESULTS, "failures": fails}, indent=2))
    print(f"\n{len(RESULTS) - fails}/{len(RESULTS)} applicable checks passed"
          + (f", {fails} FAILED" if fails else ""))
    return 1 if fails else 0


if __name__ == "__main__":
    try:
        raise SystemExit(asyncio.run(main()))
    except KeyboardInterrupt:
        raise SystemExit(130)
