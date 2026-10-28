"""Engagement-scoped broadscan runner.

`tools/broadscan` is a fast IPv4 TCP scanner (connect or raw SYN) that takes a
``-scope`` JSON gate. This module is the only sanctioned way to run it inside
Raphael: every probe set is derived from the loaded ``EgressProfile`` and the
binary is handed an allow/deny file built from that profile, so broad internet
scans are bounded by the declared engagement scope.

Invariants
----------
* FAIL CLOSED: no profile -> ``NotConfiguredError``; targets or ports outside
  the profile -> ``PolicyViolationError`` before a single packet leaves.
* POLICY OWNS THE RATE: the probe rate is capped at
  ``profile.max_packet_rate`` (the engagement pps ceiling enforced elsewhere).
* AUDITED: every run records engagement, scope, rate, hit count and status
  through ``ExternalTargetManager.audit``.
* NO SHELL: the binary is exec'd directly with an argv list.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import re
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from .external_target_manager import (
    DEFAULT_TOOL_TIMEOUT,
    ExternalTargetManager,
    NotConfiguredError,
    PolicyViolationError,
    _clip,
)

BIN_ENV = "BROADSCAN_BIN"
DEFAULT_BIN_REL = Path("tools") / "broadscan" / "bin" / "broadscan"
PROGRESS_RE = re.compile(r"done: (\d+) probed, (\d+) open")
SUMMARY_RE = re.compile(r"^broadscan: (\d+) addrs, (\d+) ports", re.MULTILINE)
MAX_RATE = 100_000
HARD_MAX_TIMEOUT = 3600.0
DEFAULT_PROBE_TIMEOUT_MS = 900

PortSpec = Union[int, str, Sequence[Union[int, str]]]


class BroadscanRunner:
    """Scope-checked bridge between an ``EgressProfile`` and the binary."""

    def __init__(self, manager: ExternalTargetManager):
        self.manager = manager

    # ------------------------------------------------------------------
    # binary / scope resolution
    # ------------------------------------------------------------------

    def binary(self) -> str:
        """Resolve the broadscan binary. Explicit env wins, then the repo."""
        explicit = os.environ.get(BIN_ENV) or self.manager._env(BIN_ENV)
        if explicit:
            p = Path(explicit).expanduser()
            if p.is_file() and os.access(p, os.X_OK):
                return str(p)
            raise NotConfiguredError(
                f"{BIN_ENV}={explicit} is not an executable file"
            )
        root = getattr(self.manager, "repo_root", None) or Path.cwd()
        p = Path(root) / DEFAULT_BIN_REL
        if p.is_file() and os.access(p, os.X_OK):
            return str(p)
        found = shutil.which("broadscan")
        if found:
            return found
        raise NotConfiguredError(
            "broadscan binary not built; run `make -C tools/broadscan` or set "
            f"{BIN_ENV}"
        )

    def scope(self) -> Dict[str, List[str]]:
        """Allow/deny CIDRs derived from the engagement profile."""
        prof = self.manager._require_profile()  # fail closed
        deny = prof.meta.get("deny_cidrs") or prof.meta.get("exclude_cidrs") or []
        if isinstance(deny, str):
            deny = [d for d in deny.split(",") if d.strip()]
        deny = [str(d).strip() for d in deny if str(d).strip()]
        for d in deny:
            try:
                ipaddress.ip_network(d, strict=False)
            except ValueError:
                raise PolicyViolationError(
                    f"invalid deny CIDR in profile meta: {d!r}"
                ) from None
        return {"allow": list(prof.cidrs), "deny": deny}

    # ------------------------------------------------------------------
    # planning / validation
    # ------------------------------------------------------------------

    def check_targets(self, targets: Sequence[str]) -> List[str]:
        prof = self.manager._require_profile()
        out: List[str] = []
        for t in targets:
            spec = str(t or "").strip()
            if not spec:
                raise PolicyViolationError("empty target in targets[]")
            if "," in spec:
                raise PolicyViolationError(
                    f"pass targets as a list, not a comma string: {spec!r}"
                )
            ok, reason = self.manager._scope_check(spec)
            if not ok:
                raise PolicyViolationError(
                    f"target {spec!r} is outside engagement scope ({reason})",
                    data={"action": "scan.broad", "engagement": prof.engagement_id},
                )
            out.append(spec)
        if not out:
            raise PolicyViolationError("targets[] is empty (fail closed)")
        return out

    def check_ports(self, ports: Optional[PortSpec]) -> str:
        prof = self.manager._require_profile()
        if ports is None or ports == "":
            if prof.allowed_ports:
                return ",".join(str(p) for p in prof.allowed_ports)
            return "21,22,23,25,53,80,110,143,443,445,587,993,995,1433,1521," \
                   "3306,3389,5432,5900,6379,8080,8443,27017"

        items: List[str] = []
        if isinstance(ports, (int, str)):
            items = str(ports).split(",")
        else:
            for p in ports:
                items.extend(str(p).split(","))

        expanded: List[Tuple[int, int]] = []
        for raw in items:
            p = raw.strip()
            if not p:
                continue
            if "-" in p:
                lo_s, _, hi_s = p.partition("-")
                if not (lo_s.isdigit() and hi_s.isdigit()):
                    raise PolicyViolationError(f"bad port range {p!r}")
                lo, hi = int(lo_s), int(hi_s)
                if not (1 <= lo <= hi <= 65535):
                    raise PolicyViolationError(f"bad port range {p!r}")
                expanded.append((lo, hi))
            else:
                if not p.isdigit():
                    raise PolicyViolationError(f"bad port {p!r}")
                n = int(p)
                if not (1 <= n <= 65535):
                    raise PolicyViolationError(f"bad port {p!r}")
                expanded.append((n, n))

        if not expanded:
            raise PolicyViolationError("ports[] resolved to nothing")

        if prof.allowed_ports:
            allowed = set(prof.allowed_ports)
            for lo, hi in expanded:
                for n in range(lo, hi + 1):
                    if n not in allowed:
                        raise PolicyViolationError(
                            f"port {n} not in allowed_ports {sorted(allowed)}"
                        )
        return ",".join(
            f"{lo}-{hi}" if hi > lo else str(lo) for lo, hi in expanded
        )

    def check_rate(self, rate: Optional[int]) -> int:
        prof = self.manager._require_profile()
        ceiling = max(1, min(int(prof.max_packet_rate), MAX_RATE))
        if rate is None:
            return ceiling
        try:
            want = int(rate)
        except (TypeError, ValueError):
            raise PolicyViolationError(f"rate must be an integer, got {rate!r}")
        if want < 1:
            raise PolicyViolationError("rate must be >= 1")
        return min(want, ceiling)

    def plan(
        self,
        targets: Sequence[str],
        ports: Optional[PortSpec] = None,
        rate: Optional[int] = None,
        *,
        syn: bool = False,
        banners: bool = True,
        shuffle: bool = True,
        workers: Optional[int] = None,
        opsec: bool = False,
        decoys: Optional[Sequence[str]] = None,
        jitter_ms: Optional[int] = None,
        frag: int = 0,
        ttl: Optional[str] = None,
        tcp_ts: bool = False,
        sport: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Validate everything and return the exact argv-able plan."""
        prof = self.manager._require_profile()
        scoped = self.check_targets(targets)
        port_str = self.check_ports(ports)
        eff_rate = self.check_rate(rate)

        if opsec and not syn:
            raise PolicyViolationError(
                "opsec requires syn=True: TTL/window/decoys only exist on the "
                "raw path, and banner grabs open a logged connection"
            )
        if frag and (frag < 8 or frag % 8 != 0):
            raise PolicyViolationError("frag must be a multiple of 8 (>= 8)")
        if sport not in (None, "random", "fixed"):
            raise PolicyViolationError("sport must be 'random' or 'fixed'")
        if ttl is not None:
            _check_ttl(str(ttl))

        decoy_list = [str(d).strip() for d in (decoys or []) if str(d).strip()]
        for d in decoy_list:
            ok, reason = self.manager._scope_check(d)
            if not ok:
                raise PolicyViolationError(
                    f"decoy source {d!r} is outside engagement scope ({reason})"
                )

        if opsec:
            banners = False  # a banner grab is an application-layer log line

        return {
            "engagement_id": prof.engagement_id,
            "scope": self.scope(),
            "targets": scoped,
            "ports": port_str,
            "rate": eff_rate,
            "max_packet_rate": prof.max_packet_rate,
            "mode": "syn" if syn else "connect",
            "banners": bool(banners),
            "shuffle": bool(shuffle),
            "workers": max(1, int(workers or 256)),
            "opsec": bool(opsec),
            "decoys": decoy_list,
            "decoy_n": 2,
            "jitter_ms": int(jitter_ms or (25 if opsec else 0)),
            "frag": int(frag),
            "ttl": str(ttl) if ttl else ("48-64" if opsec else ""),
            "tcp_ts": bool(tcp_ts),
            "sport": sport or ("random" if opsec else None),
        }

    # ------------------------------------------------------------------
    # execution
    # ------------------------------------------------------------------

    async def run(
        self,
        targets: Sequence[str],
        ports: Optional[PortSpec] = None,
        rate: Optional[int] = None,
        timeout: Optional[float] = None,
        *,
        syn: bool = False,
        banners: bool = True,
        shuffle: bool = True,
        workers: Optional[int] = None,
        probe_timeout_ms: int = DEFAULT_PROBE_TIMEOUT_MS,
        opsec: bool = False,
        decoys: Optional[Sequence[str]] = None,
        jitter_ms: Optional[int] = None,
        frag: int = 0,
        ttl: Optional[str] = None,
        tcp_ts: bool = False,
        sport: Optional[str] = None,
    ) -> Dict[str, Any]:
        plan = self.plan(
            targets, ports, rate,
            syn=syn, banners=banners, shuffle=shuffle, workers=workers,
            opsec=opsec, decoys=decoys, jitter_ms=jitter_ms, frag=frag,
            ttl=ttl, tcp_ts=tcp_ts, sport=sport,
        )
        prof = self.manager._require_profile()
        bin_path = self.binary()

        t_total = min(float(timeout or DEFAULT_TOOL_TIMEOUT), HARD_MAX_TIMEOUT)
        started = time.monotonic()

        workdir = Path(tempfile.mkdtemp(prefix="broadscan-"))
        scope_path = workdir / "scope.json"
        out_path = workdir / "hits.jsonl"
        scope_path.write_text(json.dumps(plan["scope"]))
        os.chmod(scope_path, 0o600)

        argv = [
            bin_path,
            "-targets", ",".join(plan["targets"]),
            "-ports", plan["ports"],
            "-rate", str(plan["rate"]),
            "-scope", str(scope_path),
            "-out", str(out_path),
            "-json",
            "-workers", str(plan["workers"]),
            "-timeout", f"{max(1, int(probe_timeout_ms))}ms",
        ]
        if plan["banners"]:
            argv.append("-banners")
        else:
            argv.append("-banners=false")
        if plan["shuffle"]:
            argv.append("-shuffle")
        if plan["mode"] == "syn":
            argv.append("-syn")
        if plan["opsec"]:
            argv.append("-opsec")
        if plan["decoys"]:
            argv.append("-decoys")
            argv.append(",".join(plan["decoys"]))
            argv.append("-decoy-n")
            argv.append(str(plan["decoy_n"]))
        if plan["jitter_ms"]:
            argv.append("-jitter")
            argv.append(f"{plan['jitter_ms']}ms")
        if plan["frag"]:
            argv.append("-frag")
            argv.append(str(plan["frag"]))
        if plan["ttl"]:
            argv.append("-ttl")
            argv.append(plan["ttl"])
        if plan["tcp_ts"]:
            argv.append("-tcp-ts")
        if plan["sport"]:
            argv.append("-sport")
            argv.append(plan["sport"])
        # the scope file is a per-run temp copy: drop it once read
        argv.append("-wipe-scope")

        timed_out = False
        stderr = ""
        exit_code = -1
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(workdir),
        )
        try:
            _, err = await asyncio.wait_for(proc.communicate(), timeout=t_total)
            stderr = (err or b"").decode(errors="replace")
            exit_code = proc.returncode or 0
        except asyncio.TimeoutError:
            timed_out = True
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            _, err = await proc.communicate()
            stderr = (err or b"").decode(errors="replace")
            exit_code = -1

        hits = _read_hits(out_path)
        probed = scanned = 0
        m = PROGRESS_RE.search(stderr)
        if m:
            probed, scanned = int(m.group(1)), int(m.group(2))
        duration_ms = int((time.monotonic() - started) * 1000)

        result: Dict[str, Any] = {
            "tool": "broadscan",
            "engine": "broadscan",
            "exit_code": exit_code,
            "stdout": "",
            "stderr": _clip(stderr),
            "duration_ms": duration_ms,
            "timed_out": timed_out,
            "fallback_used": False,
            "probed": probed,
            "open": scanned,
            "hits": hits,
            "scope": plan["scope"],
            "rate": plan["rate"],
            "mode": plan["mode"],
            "targets": plan["targets"],
            "ports": plan["ports"],
            "opsec": plan["opsec"],
            "decoys": plan["decoys"],
            "engagement": prof.engagement_id,
            "routed": "local",
            "plan_file": str(scope_path),
        }
        self.manager.audit({
            "action": "scan.broad",
            "target": ",".join(plan["targets"])[:512],
            "status": "timeout" if timed_out else (
                "ok" if exit_code == 0 else "failed"
            ),
            "bytes": sum(len(h.get("banner", "")) for h in hits),
            "duration_ms": duration_ms,
            "detail": {
                "ports": plan["ports"],
                "rate": plan["rate"],
                "mode": plan["mode"],
                "probed": probed,
                "open": scanned,
                "scope": plan["scope"],
            },
        })
        try:
            out_path.unlink(missing_ok=True)
            scope_path.unlink(missing_ok=True)
            workdir.rmdir()
        except OSError:
            pass
        return result


def _check_ttl(spec: str) -> None:
    parts = [p.strip() for p in spec.split("-")]
    if not 1 <= len(parts) <= 2 or not all(p.isdigit() for p in parts):
        raise PolicyViolationError(f"bad ttl {spec!r} (use 64 or 48-64)")
    vals = [int(p) for p in parts]
    if any(not (1 <= v <= 255) for v in vals):
        raise PolicyViolationError(f"bad ttl {spec!r} (1..255)")
    if len(vals) == 2 and vals[0] > vals[1]:
        raise PolicyViolationError(f"bad ttl range {spec!r}")


def _read_hits(path: Path) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(obj, dict) and obj.get("ip") and obj.get("port"):
                    hits.append(obj)
    except FileNotFoundError:
        return []
    return hits
