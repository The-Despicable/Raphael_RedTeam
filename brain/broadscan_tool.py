"""Self-hosted broadscan tool for the Autonomous Brain.

The brain normally shells out to kali-tools over HTTP. ``broadscan`` is
in-process: it runs the local ``tools/broadscan`` binary directly, gated by a
scope document so a broad internet scan stays inside declared bounds.

Scope sources, in order:
  1. ``BROADSCAN_SCOPE``            — path to a JSON scope document
  2. ``BROADSCAN_SCOPE_INLINE``     — JSON string
  3. ``BROADSCAN_ALLOW_OPEN=1``     — explicit opt-out (no gate)

Accepted documents::

    {"allow": ["10.0.0.0/8"], "deny": ["10.1.0.0/16"], "max_rate": 5000}
    {"cidrs": ["10.0.0.0/8"], "exclude": ["10.1.0.0/16"]}
    {"scope": {"in_scope": [{"asset_identifier": "*.example.com"}]}}

Hostname entries are resolved to /32s at plan time. Without a scope document
the tool refuses to run (fail closed) — matching the bridge's engagement gate.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import re
import shlex
import shutil
import socket
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union

from .config import Settings, get_settings

DEFAULT_PORTS = (
    "21,22,23,25,53,80,110,143,443,445,587,993,995,1433,1521,"
    "3306,3389,5432,5900,6379,8080,8443,27017"
)
PROGRESS_RE = re.compile(r"done: (\d+) probed, (\d+) open")
HARD_MAX_TIMEOUT = 3600.0


class BroadscanError(RuntimeError):
    """Raised when the tool cannot run at all (not built / not configured)."""


class BroadscanScopeError(ValueError):
    """Raised when a request leaves the declared scope (fail closed)."""


def _ip_net(entry: str) -> ipaddress._BaseNetwork:
    """Parse a CIDR or single IP; hostnames are resolved by the caller."""
    e = entry.strip()
    if not e:
        raise BroadscanScopeError("empty scope entry")
    try:
        return ipaddress.ip_network(e, strict=False)
    except ValueError:
        raise BroadscanScopeError(f"invalid CIDR/IP {e!r}") from None


def _resolve_host(entry: str) -> List[ipaddress.IPv4Network]:
    """Resolve a URL/host scope entry to /32 networks."""
    host = entry.strip()
    if "://" in host:
        from urllib.parse import urlsplit

        host = urlsplit(host).hostname or ""
    host = host.split("/")[0].split(":")[0]
    if host.startswith("*."):
        host = host[2:]
    out: List[ipaddress.IPv4Network] = []
    try:
        for fam, _, _, _, sockaddr in socket.getaddrinfo(host, None):
            if fam == socket.AF_INET:
                out.append(ipaddress.ip_network(sockaddr[0] + "/32"))
    except socket.gaierror:
        return out
    if not out:
        try:
            for fam, _, _, _, sockaddr in socket.getaddrinfo(host, None):
                if fam == socket.AF_INET6:
                    out.append(ipaddress.ip_network(sockaddr[0] + "/128"))
        except socket.gaierror:
            pass
    return out


def _expand(items: Iterable[str]) -> List[ipaddress._BaseNetwork]:
    nets: List[ipaddress._BaseNetwork] = []
    for raw in items:
        s = str(raw).strip()
        if not s:
            continue
        try:
            nets.append(ipaddress.ip_network(s, strict=False))
        except ValueError:
            nets.extend(_resolve_host(s))
    return nets


class BroadscanTool:
    """Local, scope-gated broadscan runner."""

    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or get_settings()

    # ------------------------------------------------------------------
    # discovery
    # ------------------------------------------------------------------

    def binary(self) -> str:
        candidates: List[str] = []
        explicit = getattr(self.settings, "broadscan_bin", "") or os.environ.get(
            "BROADSCAN_BIN", ""
        )
        if explicit:
            candidates.append(explicit)
        env_bin = os.environ.get("BROADSCAN_BIN", "")
        if env_bin:
            candidates.append(env_bin)
        candidates.append("/opt/broadscan/broadscan")
        here = Path(__file__).resolve().parent.parent
        candidates.append(str(here / "tools" / "broadscan" / "bin" / "broadscan"))
        which = shutil.which("broadscan")
        if which:
            candidates.append(which)
        for c in candidates:
            p = Path(c).expanduser()
            if p.is_file() and os.access(p, os.X_OK):
                return str(p)
        raise BroadscanError(
            "broadscan binary not found; build it with "
            "`make -C tools/broadscan` or set BROADSCAN_BIN"
        )

    # ------------------------------------------------------------------
    # scope
    # ------------------------------------------------------------------

    def scope_document(self) -> Dict[str, Any]:
        """Load the scope document or raise unless explicitly opted out."""
        path = getattr(self.settings, "broadscan_scope_file", None) or \
            os.environ.get("BROADSCAN_SCOPE", "")
        inline = os.environ.get("BROADSCAN_SCOPE_INLINE", "")
        doc: Dict[str, Any] = {}
        if path:
            p = Path(path).expanduser()
            if not p.is_file():
                raise BroadscanScopeError(f"BROADSCAN_SCOPE file missing: {p}")
            try:
                doc = json.loads(p.read_text())
            except json.JSONDecodeError as e:
                raise BroadscanScopeError(f"scope file is not JSON: {e}") from e
        elif inline:
            try:
                doc = json.loads(inline)
            except json.JSONDecodeError as e:
                raise BroadscanScopeError(f"BROADSCAN_SCOPE_INLINE invalid: {e}") from e
        elif getattr(self.settings, "broadscan_allow_open", False) or \
                os.environ.get("BROADSCAN_ALLOW_OPEN") in ("1", "true", "yes"):
            return {"allow": ["0.0.0.0/0"], "deny": [], "enforced": False}
        else:
            raise BroadscanScopeError(
                "no scope configured — set BROADSCAN_SCOPE to a JSON scope "
                "document, or BROADSCAN_ALLOW_OPEN=1 for an explicit open scan"
            )
        if not isinstance(doc, dict):
            raise BroadscanScopeError("scope document must be an object")

        allow_raw = doc.get("allow") or doc.get("cidrs")
        if not allow_raw and isinstance(doc.get("scope"), dict):
            entries = doc["scope"].get("in_scope") or doc["scope"].get("allow") or []
            allow_raw = [
                e.get("asset_identifier") if isinstance(e, dict) else e
                for e in entries
            ]
        deny_raw = doc.get("deny") or doc.get("exclude") or doc.get("out_of_scope") or []

        allow = [str(a) for a in (allow_raw or []) if str(a).strip()]
        deny = [str(d) for d in (deny_raw or []) if str(d).strip()]
        if not allow:
            raise BroadscanScopeError("scope document declares no allow entries")
        rate_cap = doc.get("max_rate") or doc.get("max_packet_rate")
        return {
            "allow": allow,
            "deny": deny,
            "max_rate": int(rate_cap) if rate_cap else None,
            "enforced": True,
        }

    def plan(
        self,
        targets: Sequence[str],
        ports: Optional[Union[str, int, Sequence[Union[str, int]]]] = None,
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
        doc = self.scope_document()
        allow_nets = _expand(doc["allow"])
        deny_nets = _expand(doc["deny"])
        if not allow_nets:
            raise BroadscanScopeError("scope resolved to no networks")

        checked: List[str] = []
        for t in targets:
            spec = str(t or "").strip()
            if not spec:
                raise BroadscanScopeError("empty target")
            try:
                net = ipaddress.ip_network(spec, strict=False)
            except ValueError:
                resolved = _resolve_host(spec)
                if not resolved:
                    raise BroadscanScopeError(
                        f"target {spec!r} does not resolve"
                    ) from None
                for n in resolved:
                    self._assert_in_scope(n, allow_nets, deny_nets)
                checked.append(spec)
                continue
            self._assert_in_scope(net, allow_nets, deny_nets)
            checked.append(spec)
        if not checked:
            raise BroadscanScopeError("targets is empty (fail closed)")

        port_str = self._ports(ports)
        cap = getattr(self.settings, "broadscan_max_rate", 100_000)
        if doc.get("max_rate"):
            cap = min(cap, doc["max_rate"])
        eff_rate = min(int(rate or cap), int(cap))
        if eff_rate < 1:
            raise BroadscanScopeError("rate must be >= 1")

        if opsec and not syn:
            raise BroadscanScopeError(
                "opsec requires syn: ttl/window/decoys only exist on the raw "
                "path, and banner grabs open a logged connection"
            )
        if frag and (frag < 8 or frag % 8 != 0):
            raise BroadscanScopeError("frag must be a multiple of 8 (>= 8)")
        if sport not in (None, "random", "fixed"):
            raise BroadscanScopeError("sport must be 'random' or 'fixed'")
        decoy_list = [str(d).strip() for d in (decoys or []) if str(d).strip()]
        for d in decoy_list:
            dnets = _expand([d])
            if not dnets:
                raise BroadscanScopeError(f"decoy source {d!r} does not resolve")
            for dn in dnets:
                self._assert_in_scope(dn, allow_nets, deny_nets)

        if opsec:
            banners = False

        return {
            "scope": {"allow": doc["allow"], "deny": doc["deny"]},
            "enforced": doc["enforced"],
            "targets": checked,
            "ports": port_str,
            "rate": eff_rate,
            "mode": "syn" if syn else "connect",
            "banners": bool(banners),
            "shuffle": bool(shuffle),
            "workers": max(1, int(workers or 256)),
            "opsec": bool(opsec),
            "decoys": decoy_list,
            "jitter_ms": int(jitter_ms or (25 if opsec else 0)),
            "frag": int(frag),
            "ttl": str(ttl) if ttl else ("48-64" if opsec else ""),
            "tcp_ts": bool(tcp_ts),
            "sport": sport or ("random" if opsec else None),
        }

    @staticmethod
    def _assert_in_scope(
        net: ipaddress._BaseNetwork,
        allow: List[ipaddress._BaseNetwork],
        deny: List[ipaddress._BaseNetwork],
    ) -> None:
        ok = any(net.version == a.version and net.subnet_of(a) for a in allow)
        if not ok:
            raise BroadscanScopeError(f"target {net} is outside scope")
        for d in deny:
            if net.version == d.version and net.overlaps(d):
                raise BroadscanScopeError(f"target {net} overlaps denied {d}")

    def _ports(self, ports: Optional[Any]) -> str:
        if ports in (None, "", []):
            return getattr(self.settings, "broadscan_default_ports", DEFAULT_PORTS)
        items: List[str] = []
        if isinstance(ports, (str, int)):
            items = str(ports).split(",")
        else:
            for p in ports:
                items.extend(str(p).split(","))
        out: List[str] = []
        for raw in items:
            p = raw.strip()
            if not p:
                continue
            if "-" in p:
                lo_s, _, hi_s = p.partition("-")
                if not (lo_s.isdigit() and hi_s.isdigit()):
                    raise BroadscanScopeError(f"bad port range {p!r}")
                lo, hi = int(lo_s), int(hi_s)
                if not (1 <= lo <= hi <= 65535):
                    raise BroadscanScopeError(f"bad port range {p!r}")
                out.append(f"{lo}-{hi}")
            else:
                if not p.isdigit() or not (1 <= int(p) <= 65535):
                    raise BroadscanScopeError(f"bad port {p!r}")
                out.append(str(int(p)))
        if not out:
            raise BroadscanScopeError("ports resolved to nothing")
        return ",".join(out)

    # ------------------------------------------------------------------
    # execution
    # ------------------------------------------------------------------

    async def run(
        self,
        targets: Sequence[str],
        ports: Optional[Any] = None,
        rate: Optional[int] = None,
        timeout: Optional[float] = None,
        *,
        syn: bool = False,
        banners: bool = True,
        shuffle: bool = True,
        workers: Optional[int] = None,
        probe_timeout_ms: int = 900,
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
        bin_path = self.binary()
        cap = float(getattr(self.settings, "max_tool_timeout", 300.0) or 300.0)
        t_total = min(float(timeout or cap), cap, HARD_MAX_TIMEOUT)

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
            "-banners=" + ("true" if plan["banners"] else "false"),
            "-shuffle=" + ("true" if plan["shuffle"] else "false"),
            "-wipe-scope",
        ]
        if plan["mode"] == "syn":
            argv.append("-syn")
        if plan["opsec"]:
            argv.append("-opsec")
        if plan["decoys"]:
            argv.extend(["-decoys", ",".join(plan["decoys"])])
        if plan["jitter_ms"]:
            argv.extend(["-jitter", f"{plan['jitter_ms']}ms"])
        if plan["frag"]:
            argv.extend(["-frag", str(plan["frag"])])
        if plan["ttl"]:
            argv.extend(["-ttl", plan["ttl"]])
        if plan["tcp_ts"]:
            argv.append("-tcp-ts")
        if plan["sport"]:
            argv.extend(["-sport", plan["sport"]])

        started = time.monotonic()
        timed_out = False
        exit_code = -1
        stderr = ""
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

        hits: List[Dict[str, Any]] = []
        try:
            with out_path.open("r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(obj, dict) and obj.get("ip"):
                        hits.append(obj)
        except FileNotFoundError:
            pass

        probed = opened = 0
        m = PROGRESS_RE.search(stderr)
        if m:
            probed, opened = int(m.group(1)), int(m.group(2))

        for p in (out_path, scope_path):
            try:
                p.unlink(missing_ok=True)
            except OSError:
                pass
        try:
            workdir.rmdir()
        except OSError:
            pass

        return {
            "tool": "broadscan",
            "exit_code": exit_code,
            "stdout": "",
            "stderr": stderr[-4096:],
            "duration_ms": int((time.monotonic() - started) * 1000),
            "timed_out": timed_out,
            "fallback_used": False,
            "engine": "broadscan",
            "probed": probed,
            "open": opened,
            "hits": hits,
            "scope": plan["scope"],
            "rate": plan["rate"],
            "mode": plan["mode"],
            "targets": plan["targets"],
            "ports": plan["ports"],
            "routed": "local",
        }

    # ------------------------------------------------------------------
    # argv interface used by /tools/execute
    # ------------------------------------------------------------------

    def parse_args(
        self, args: Sequence[str], target: Optional[str] = None
    ) -> Dict[str, Any]:
        """Translate CLI-style args into run() kwargs."""
        opts: Dict[str, Any] = {"targets": [], "ports": None, "rate": None}
        toks: List[str] = []
        for a in args or []:
            toks.extend(shlex.split(str(a)))
        i = 0
        while i < len(toks):
            tok = toks[i]
            nxt = toks[i + 1] if i + 1 < len(toks) else ""
            if tok in ("-targets", "--targets") and nxt:
                opts["targets"].extend([t for t in nxt.split(",") if t])
                i += 2
            elif tok in ("-ports", "--ports") and nxt:
                opts["ports"] = nxt
                i += 2
            elif tok in ("-rate", "--rate") and nxt:
                opts["rate"] = int(nxt)
                i += 2
            elif tok in ("-workers", "--workers") and nxt:
                opts["workers"] = int(nxt)
                i += 2
            elif tok in ("-timeout", "--timeout") and nxt:
                opts["probe_timeout_ms"] = int(float(nxt.rstrip("ms")) or 900)
                i += 2
            elif tok in ("-syn", "--syn"):
                opts["syn"] = True
                i += 1
            elif tok in ("-no-banners", "--no-banners", "-banners=false"):
                opts["banners"] = False
                i += 1
            elif tok in ("-no-shuffle", "--no-shuffle", "-shuffle=false"):
                opts["shuffle"] = False
                i += 1
            elif tok in ("-banners", "--banners"):
                opts["banners"] = True
                i += 1
            elif tok in ("-shuffle", "--shuffle"):
                opts["shuffle"] = True
                i += 1
            elif tok in ("-opsec", "--opsec"):
                opts["opsec"] = True
                i += 1
            elif tok in ("-tcp-ts", "--tcp-ts"):
                opts["tcp_ts"] = True
                i += 1
            elif tok in ("-decoys", "--decoys") and nxt:
                opts["decoys"] = [d for d in nxt.split(",") if d]
                i += 2
            elif tok in ("-jitter", "--jitter") and nxt:
                opts["jitter_ms"] = int(float(nxt.rstrip("ms")) or 0)
                i += 2
            elif tok in ("-frag", "--frag") and nxt:
                opts["frag"] = int(nxt)
                i += 2
            elif tok in ("-ttl", "--ttl") and nxt:
                opts["ttl"] = nxt
                i += 2
            elif tok in ("-sport", "--sport") and nxt:
                opts["sport"] = nxt
                i += 2
            elif tok in ("-wipe-scope", "--wipe-scope"):
                i += 1
            elif tok.startswith("-"):
                raise BroadscanScopeError(f"unknown flag {tok!r}")
            else:
                opts["targets"].append(tok)
                i += 1
        if not opts["targets"] and target:
            opts["targets"] = [str(target)]
        if not opts["targets"]:
            raise BroadscanScopeError("no targets given")
        return opts

    async def from_args(
        self,
        args: Sequence[str],
        target: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        opts = self.parse_args(args, target)
        return await self.run(
            opts["targets"],
            ports=opts.get("ports"),
            rate=opts.get("rate"),
            timeout=timeout,
            syn=bool(opts.get("syn")),
            banners=bool(opts.get("banners", True)),
            shuffle=bool(opts.get("shuffle", True)),
            workers=opts.get("workers"),
            probe_timeout_ms=int(opts.get("probe_timeout_ms", 900)),
            opsec=bool(opts.get("opsec")),
            decoys=opts.get("decoys"),
            jitter_ms=opts.get("jitter_ms"),
            frag=int(opts.get("frag") or 0),
            ttl=opts.get("ttl"),
            tcp_ts=bool(opts.get("tcp_ts")),
            sport=opts.get("sport"),
        )


# ---------------------------------------------------------------------------
# direct CLI: python -m brain.broadscan_tool -targets 10.0.0.0/24 -ports 22,80
# ---------------------------------------------------------------------------


def _main(argv: Optional[Sequence[str]] = None) -> int:
    import sys

    tool = BroadscanTool()
    try:
        result = asyncio.run(tool.from_args(list(argv if argv is not None else sys.argv[1:])))
    except (BroadscanScopeError, BroadscanError) as e:
        print(f"broadscan: {e}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return 0 if result.get("exit_code") == 0 else 1


if __name__ == "__main__":
    raise SystemExit(_main())
