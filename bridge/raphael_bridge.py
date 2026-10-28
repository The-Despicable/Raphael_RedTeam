#!/usr/bin/env python3
"""Raphael external-target bridge — JSON-RPC 2.0 over line-delimited stdio.

FIX (was raphael-2.0): all import paths and defaults now target the repo
``raphael-redteam``; a legacy ``/home/yaser/raphael-2.0`` prefix found in env
vars is remapped at runtime to ``/home/yaser/raphael-redteam``.

Run from repo root::

    python -m bridge.raphael_bridge            # module form (OpenCode/MCP)
    python bridge/raphael_bridge.py            # direct script form

Protocol: line-delimited JSON-RPC 2.0 on stdin/stdout. All logs go to
stderr (stdout carries ONLY JSON-RPC responses). Non-fatal errors are
returned as JSON-RPC error objects — the bridge never crash-loops.

Security posture (non-negotiable):
  * FAIL CLOSED — every outward connect/tool run requires a loaded
    engagement profile (engagement_id + target_scope_cidr + egress policy).
  * AUDIT — every external session is appended (timestamp, source iface,
    target, bytes, duration, status) to projects/<engagement>/bridge/.
  * NO PARALLEL TOOL CATALOG — ``kali.run`` routes to the existing
    kali-tools service / raphael-api agents.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

# --- repo-root bootstrap (supports -m AND direct-script invocation) --------
_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

# FIX: legacy -> current repo root mapping --------------------------------
LEGACY_REPO_ROOT = Path("/home/yaser/raphael-2.0")
DEFAULT_REPO_ROOT = Path("/home/yaser/raphael-redteam")

from src.bridge.external_target_manager import (  # noqa: E402
    BridgeError,
    ComponentError,
    EgressPolicy,
    EgressProfile,
    ExternalTargetManager,
    NotConfiguredError,
    PolicyViolationError,
    RateLimitError,
    _clip,
    _is_canary,
    _split_hostport,
    parse_ovpn_profile,
)

log = logging.getLogger("raphael.bridge")

VERSION = "2.0.0"
BRIDGE_NAME = "raphael-external-bridge"


def resolve_repo_root(env: Optional[Dict[str, str]] = None) -> Path:
    """RAPHAEL_REPO_ROOT > default host path > this file's repo root."""
    e = env if env is not None else dict(os.environ)
    override = e.get("RAPHAEL_REPO_ROOT")
    if override:
        return Path(override).resolve()
    if DEFAULT_REPO_ROOT.is_dir():
        return DEFAULT_REPO_ROOT
    return _REPO_ROOT


def remap_legacy(path: Optional[str]) -> Optional[str]:
    """Rewrite /home/yaser/raphael-2.0/** -> <repo_root>/** (obsoleted path)."""
    if not path:
        return path
    root = resolve_repo_root()
    legacy = str(LEGACY_REPO_ROOT)
    if path.startswith(legacy):
        replaced = str(root) + path[len(legacy):]
        log.debug("remapped legacy path %s -> %s", path, replaced)
        return replaced
    return path


def load_env_file(repo_root: Path) -> None:
    """Tiny .env loader (KEY=VALUE, no interpolation, no comments)."""
    env_path = repo_root / ".env"
    if not env_path.is_file():
        return
    try:
        for raw in env_path.read_text(errors="replace").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            k = k.strip()
            v = v.strip().strip('"').strip("'")
            if k and k not in os.environ:
                os.environ[k] = v
    except OSError as e:  # never fatal
        log.warning("could not read .env: %s", e)


# ---------------------------------------------------------------------------
# JSON-RPC error codes (std + bridge domain)
# ---------------------------------------------------------------------------

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603


class RpcError(Exception):
    def __init__(self, code: int, message: str,
                 data: Optional[Dict[str, Any]] = None,
                 *, id: Any = None):  # noqa: A002
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data
        self.id = id


# ---------------------------------------------------------------------------
# Bridge
# ---------------------------------------------------------------------------


class RaphaelBridge:
    """Dispatches JSON-RPC methods onto the ExternalTargetManager."""

    def __init__(
        self,
        manager: Optional[ExternalTargetManager] = None,
        *,
        repo_root: Optional[Path] = None,
        engagement: Optional[str] = None,
    ):
        self.repo_root = Path(repo_root or resolve_repo_root())
        self.manager = manager or ExternalTargetManager(
            env=None, repo_root=self.repo_root
        )
        self.started_at = time.time()
        self.default_engagement = (
            engagement
            or self.manager._env("BRIDGE_ENGAGEMENT", "_global")
        )
        self.pid_path: Optional[Path] = None
        self.methods = {
            # --- read-only / health (safe without engagement scope) -------
            "system.health": (self._m_system_health, False),
            "bridge.version": (self._m_bridge_version, False),
            "vpn.status": (self._m_vpn_status, False),
            "proxy.status": (self._m_proxy_status, False),
            "proxy.test": (self._m_proxy_test, False),
            "dns.resolve": (self._m_dns_resolve, False),
            "bridge.logs": (self._m_bridge_logs, False),
            "web.cloak": (self._m_web_cloak, True),
            # --- scoped mutations / outward actions (fail closed) ---------
            "vpn.connect": (self._m_vpn_connect, True),
            "vpn.disconnect": (self._m_vpn_disconnect, True),
            "targets.set": (self._m_targets_set, False),
            "targets.get_policy": (self._m_targets_get_policy, False),
            "network.check_reachability": (self._m_check_reachability, True),
            "egress_policy.set": (self._m_egress_policy_set, False),
            "tls.query": (self._m_tls_query, True),
            "vpn/profile/load": (self._m_vpn_profile_load, False),
            "kali.run": (self._m_kali_run, True),
            "scan.broad": (self._m_scan_broad, True),
            # --- MCP shim (stdio MCP server mount for OpenCode) ----------
            "initialize": (self._m_mcp_initialize, False),
            "tools/list": (self._m_mcp_tools_list, False),
            "tools/call": (self._m_mcp_tools_call, False),
            "ping": (self._m_ping, False),
        }

    # ------------------------------------------------------------------
    # plumbing
    # ------------------------------------------------------------------

    @property
    def engagement(self) -> str:
        if self.manager.profile is not None:
            return self.manager.profile.engagement_id
        return self.default_engagement

    def write_pid(self) -> None:
        try:
            d = self.manager._engagement_dir(self.engagement)
            d.mkdir(parents=True, exist_ok=True)
            self.pid_path = d / "raphael_bridge.pid"
            self.pid_path.write_text(str(os.getpid()))
        except OSError as e:
            log.warning("pid write failed: %s", e)

    def remove_pid(self) -> None:
        if self.pid_path is not None:
            try:
                self.pid_path.unlink()
            except OSError:
                pass

    # ------------------------------------------------------------------
    # health (component probes; never crash, explicit degraded states)
    # ------------------------------------------------------------------

    async def _health_components(self) -> Dict[str, Any]:
        mgr = self.manager
        env = mgr._env
        comps: Dict[str, Any] = {}

        # tor ---------------------------------------------------------
        tor_socks = env("TOR_SOCKS", "")
        tor_ctrl = env("TOR_CONTROL", "")
        if tor_socks:
            sh, sp = _split_hostport(tor_socks, 9050)
            ch, cp = _split_hostport(tor_ctrl, 9051)
            comps["tor"] = {
                "configured": True,
                "socks": tor_socks,
                "control": tor_ctrl,
                "reachable": await mgr._tcp_probe(sh, sp, timeout=2.0),
                "control_reachable": await mgr._tcp_probe(ch, cp, timeout=1.5),
            }
        else:
            comps["tor"] = {"configured": False, "reachable": False}

        # sliver --------------------------------------------------------
        sliver_cfg = remap_legacy(env("SLIVER_OPERATOR_CONFIG", ""))
        cfg_exists = bool(sliver_cfg) and Path(sliver_cfg).is_file()
        comps["sliver"] = {
            "configured": bool(sliver_cfg),
            "operator_config": sliver_cfg or None,
            "operator_config_exists": bool(cfg_exists),
        }

        # neo4j -----------------------------------------------------------
        neo4j_uri = env("NEO4J_URI", "")
        nh, np_ = _split_hostport(
            urlsplit(neo4j_uri).netloc if "://" in neo4j_uri else neo4j_uri,
            7687,
        )
        comps["neo4j"] = {
            "configured": bool(neo4j_uri),
            "uri": neo4j_uri or None,
            "reachable": (
                await mgr._tcp_probe(nh, np_, timeout=2.0) if neo4j_uri else False
            ),
        }

        # kali ------------------------------------------------------------
        kali_url = env("KALI_TOOLS_URL")
        if kali_url:
            comps["kali"] = {"configured": True, "url": kali_url, "reachable": False}
            try:
                import httpx
                async with httpx.AsyncClient(trust_env=False, timeout=2.0) as c:
                    r = await c.get(f"{kali_url.rstrip('/')}/")
                    comps["kali"]["reachable"] = r.status_code < 500
                    comps["kali"]["http_status"] = r.status_code
            except Exception as e:  # noqa: BLE001
                comps["kali"]["error"] = type(e).__name__
        else:
            comps["kali"] = {"configured": False, "reachable": False}

        # vpn provider ------------------------------------------------------
        import shutil
        comps["vpn_provider"] = {
            "installed": bool(shutil.which("openvpn")),
            "tun_device": Path("/dev/net/tun").exists(),
            "profile_path": remap_legacy(env("VPN_PROFILE_PATH")) or None,
            "credentials_configured": bool(
                env("VPN_USERNAME") or env("VPN_PASSWORD")
            ),
            "active_session": bool(mgr._vpn.get("connected")),
        }

        # ovpn profile -----------------------------------------------------
        comps["ovpn_profile_loaded"] = mgr.ovpn_meta is not None or bool(
            mgr.profile and mgr.profile.vpn_profile_path
        )

        # dns ----------------------------------------------------------------
        dns_configured = bool(
            env("DNS_PRIMARY") or env("DNS_SECONDARY") or env("DNS_CORPORATE")
        )
        dns_probe = {"configured": dns_configured, "resolver": "canary"}
        try:
            res = await mgr.resolve("example.com")
            ok = bool(res.get("addresses"))
            dns_probe.update({
                "reachable": ok,
                "resolver": res.get("resolver"),
                "addresses": res.get("addresses", [])[:4],
            })
        except Exception as e:  # noqa: BLE001
            dns_probe.update({"reachable": False, "error": str(e)[:120]})
        comps["dns"] = dns_probe

        return comps

    async def _m_system_health(self, params: Dict[str, Any]) -> Dict[str, Any]:
        comps = await self._health_components()
        degraded: List[str] = []
        for name, c in comps.items():
            if isinstance(c, dict):
                configured = c.get("configured", True)
                reachable = c.get("reachable", c.get("ok", True))
                if configured and not reachable:
                    degraded.append(name)
        status = "ok" if not degraded else "degraded"
        out = {
            "status": status,
            "components": comps,
            "degraded": degraded,
            "engagement": self.engagement,
            "uptime_s": round(time.time() - self.started_at, 1),
            "pid": os.getpid(),
        }
        self.manager.audit({"action": "system.health", "status": "ok",
                            "detail": {"status": status, "degraded": degraded}})
        return out

    # ------------------------------------------------------------------
    # simple read-only methods
    # ------------------------------------------------------------------

    async def _m_bridge_version(self, params: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "bridge": BRIDGE_NAME,
            "version": VERSION,
            "repo_root": str(self.repo_root),
            "engagement": self.engagement,
            "python": sys.version.split()[0],
            "methods": sorted(k for k in self.methods if "/" not in k),
        }

    async def _m_ping(self, params: Dict[str, Any]) -> Dict[str, Any]:
        return {"pong": True, "ts": time.time()}

    async def _m_vpn_status(self, params: Dict[str, Any]) -> Dict[str, Any]:
        out = await self.manager.vpn_status()
        out["egress_policy"] = (
            self.manager.profile.egress.value
            if self.manager.profile
            else self.manager._env("EGRESS_STRATEGY", "unset")
        )
        return out

    async def _m_vpn_connect(self, p: Dict[str, Any]) -> Dict[str, Any]:
        # fail closed: must already have an engagement scope
        if self.manager.profile is None:
            raise NotConfiguredError(
                "vpn.connect refused (fail closed): load an engagement scope "
                "first via targets.set {engagement_id, cidrs[], egress}"
            )
        out = await self.manager.connect_vpn(
            profile=p.get("profile"),
            username=p.get("username"),
            password=p.get("password"),
        )
        return out

    async def _m_vpn_disconnect(self, p: Dict[str, Any]) -> Dict[str, Any]:
        if self.manager.profile is None:
            raise NotConfiguredError(
                "vpn.disconnect refused (fail closed): no engagement scope"
            )
        return await self.manager.disconnect_vpn(p.get("session_id"))

    async def _m_vpn_profile_load(self, p: Dict[str, Any]) -> Dict[str, Any]:
        path = remap_legacy(str(p.get("path") or "")) or ""
        if not path:
            raise RpcError(INVALID_PARAMS, "vpn/profile/load requires {path}")
        meta = self.manager.link_profile(path)
        return meta

    # ------------------------------------------------------------------
    # targets / engagement policy
    # ------------------------------------------------------------------

    async def _m_targets_set(self, p: Dict[str, Any]) -> Dict[str, Any]:
        engagement = str(p.get("engagement_id") or "").strip()
        if not engagement:
            raise RpcError(
                INVALID_PARAMS,
                "targets.set requires engagement_id (fail closed)",
            )
        cidrs = list(p.get("cidrs") or [])
        if not cidrs:
            raise RpcError(
                INVALID_PARAMS,
                "targets.set requires a non-empty cidrs[] scope "
                "(fail closed: target_scope_cidr)",
            )
        egress = p.get("egress") or p.get("egress_policy") or \
            self.manager._env("EGRESS_STRATEGY")
        if not egress:
            raise RpcError(
                INVALID_PARAMS,
                "no egress policy: pass egress=proxy|tor|vpn|direct or set "
                "EGRESS_STRATEGY in .env (fail closed)",
            )
        creds = p.get("credentials") or {}
        if not isinstance(creds, dict):
            raise RpcError(INVALID_PARAMS, "credentials must be an object")
        # accept top-level vpn fields too (spec: vpn_username etc.)
        obj = {
            "engagement_id": engagement,
            "cidrs": cidrs,
            "urls": list(p.get("urls") or []),
            "egress": egress,
            "allowed_ports": list(p.get("allowed_ports") or []),
            "max_packet_rate": p.get("max_packet_rate") or 30,
            "credentials": {
                **creds,
                "tor_socks": creds.get("tor_socks")
                or self.manager._env("TOR_SOCKS", "127.0.0.1:9050"),
                "vpn_profile_path": remap_legacy(
                    creds.get("vpn_profile_path")
                    or self.manager._env("VPN_PROFILE_PATH") or ""
                ) or None,
                "vpn_username": creds.get("vpn_username")
                or self.manager._env("VPN_USERNAME") or None,
                "vpn_password": creds.get("vpn_password")
                or self.manager._env("VPN_PASSWORD") or None,
                "proxy_auth": creds.get("proxy_auth")
                or self.manager._env("OUTBOUND_PROXY_AUTH") or None,
                "sliver_config_path": remap_legacy(
                    creds.get("sliver_config_path") or ""
                ) or None,
            },
        }
        prof = EgressProfile.from_obj(obj)  # raises PolicyViolation on bad scope
        self.manager.profile = prof
        self.manager._rate = None  # rebuilt by load_profile below
        await self.manager.load_profile(obj)
        path = self.manager.persist_profile()
        summary = prof.summary()
        summary["policy_file"] = str(path)
        summary["credentials_persisted"] = any(
            [prof.vpn_username, prof.vpn_password, prof.proxy_auth]
        )
        self.manager.audit({
            "action": "targets.set", "status": "ok",
            "detail": summary,
        })
        return summary

    async def _m_targets_get_policy(self, p: Dict[str, Any]) -> Dict[str, Any]:
        engagement = str(p.get("engagement_id") or "").strip()
        if self.manager.profile is not None and (
            not engagement or engagement == self.manager.profile.engagement_id
        ):
            prof = self.manager.profile
        elif engagement:
            try:
                return self._policy_view(
                    self.manager.load_engagement_policy(engagement)
                )
            except NotConfiguredError:
                if self.manager.profile is None:
                    raise
                prof = self.manager.profile
        else:
            raise NotConfiguredError(
                "no engagement policy loaded; call targets.set first"
            )
        return self._policy_view(prof.summary())

    def _policy_view(self, summary: Dict[str, Any]) -> Dict[str, Any]:
        """Shape mandated by the bridge contract (no secrets)."""
        return {
            "engagement_id": summary["engagement_id"],
            "scope_cidrs": summary["cidrs"],
            "allowed_ports": summary.get("allowed_ports", []),
            "egress_policy": summary["egress"],
            "max_rate": summary.get("max_packet_rate", 30),
            "urls": summary.get("urls", []),
            "dns_servers": summary.get("dns_servers", []),
        }

    async def _m_egress_policy_set(self, p: Dict[str, Any]) -> Dict[str, Any]:
        engagement = str(p.get("engagement_id") or "").strip()
        mode = p.get("mode")
        if not engagement or not mode:
            raise RpcError(
                INVALID_PARAMS,
                "egress_policy.set requires engagement_id and mode "
                "(proxy|tor|vpn|direct)",
            )
        policy = EgressPolicy.coerce(mode)  # raises PolicyViolation if unknown
        if self.manager.profile is not None and (
            engagement == self.manager.profile.engagement_id
        ):
            self.manager.profile.egress = policy
        else:
            # load persisted policy for that engagement (fail closed if absent)
            self.manager.load_engagement_policy(engagement)
            self.manager.profile.egress = policy
        self.manager.persist_profile()
        self.manager.audit({
            "action": "egress_policy.set", "status": "ok",
            "detail": {"engagement": engagement, "mode": policy.value},
        })
        return self._policy_view(self.manager.profile.summary())

    # ------------------------------------------------------------------
    # network operations
    # ------------------------------------------------------------------

    async def _m_check_reachability(self, p: Dict[str, Any]) -> Dict[str, Any]:
        target = p.get("target")
        if not target:
            raise RpcError(INVALID_PARAMS, "network.check_reachability requires target")
        ports = p.get("ports") or []
        if not isinstance(ports, list):
            raise RpcError(INVALID_PARAMS, "ports must be a list of ints")
        timeout = min(max(float(p.get("timeout") or 3.0), 0.5), 30.0)
        return await self.manager.check_reachability(
            str(target), [int(x) for x in ports], timeout=timeout
        )

    async def _m_tls_query(self, p: Dict[str, Any]) -> Dict[str, Any]:
        target = p.get("target")
        if not target:
            raise RpcError(INVALID_PARAMS, "tls.query requires target")
        return await self.manager.tls_query(
            str(target),
            min_version=p.get("min_version"),
            cipher=p.get("cipher"),
            timeout=min(max(float(p.get("timeout") or 8.0), 1.0), 60.0),
        )

    async def _m_dns_resolve(self, p: Dict[str, Any]) -> Dict[str, Any]:
        host = str(p.get("host") or "").strip()
        if not host:
            raise RpcError(INVALID_PARAMS, "dns.resolve requires host")
        return await self.manager.resolve(host)

    async def _m_kali_run(self, p: Dict[str, Any]) -> Dict[str, Any]:
        tool = str(p.get("tool") or "").strip()
        target = p.get("target")
        if not tool:
            raise RpcError(INVALID_PARAMS, "kali.run requires tool")
        if not target:
            raise RpcError(INVALID_PARAMS, "kali.run requires target")
        args = p.get("args") or []
        if not isinstance(args, list):
            raise RpcError(INVALID_PARAMS, "kali.run args must be a list")
        return await self.manager.run_tool(
            tool, args, str(target), timeout=p.get("timeout")
        )

    async def _m_scan_broad(self, p: Dict[str, Any]) -> Dict[str, Any]:
        """Engagement-scoped broad IP scan via tools/broadscan."""
        raw = p.get("targets")
        targets: List[str] = []
        if isinstance(raw, list):
            targets = [str(t) for t in raw]
        elif isinstance(raw, str) and raw.strip():
            targets = [raw]
        if not targets and p.get("target"):
            targets = [str(p["target"])]
        if not targets:
            raise RpcError(
                INVALID_PARAMS,
                "scan.broad requires targets[] (or target) — fail closed",
            )
        ports = p.get("ports")
        if ports is not None and not isinstance(ports, (str, int, list)):
            raise RpcError(INVALID_PARAMS, "ports must be a string, int or list")
        try:
            return await self.manager.broadscan(
                targets,
                ports=ports,
                rate=p.get("rate"),
                timeout=min(max(float(p.get("timeout") or 120.0), 1.0), 3600.0),
                syn=bool(p.get("syn", False)),
                banners=bool(p.get("banners", True)),
                shuffle=bool(p.get("shuffle", True)),
                workers=p.get("workers"),
                probe_timeout_ms=int(p.get("probe_timeout_ms") or 900),
                opsec=bool(p.get("opsec", False)),
                decoys=p.get("decoys"),
                jitter_ms=p.get("jitter_ms"),
                frag=int(p.get("frag") or 0),
                ttl=p.get("ttl"),
                tcp_ts=bool(p.get("tcp_ts", False)),
                sport=p.get("sport"),
            )
        except PolicyViolationError as e:
            raise RpcError(-32001, str(e), data=e.data) from e
        except NotConfiguredError as e:
            raise RpcError(-32002, str(e), data=e.data) from e

    async def _m_web_cloak(self, p: Dict[str, Any]) -> Dict[str, Any]:
        url = str(p.get("url") or "").strip()
        if not url:
            raise RpcError(INVALID_PARAMS, "web.cloak requires url (fail closed)")
        screenshot = bool(p.get("screenshot", False))
        timeout = min(max(float(p.get("timeout") or 30.0), 1.0), 240.0)
        try:
            return await self.manager.cloak_fetch(
                url, timeout=timeout, screenshot=screenshot,
                full_html=bool(p.get("full_html", True)),
                wait_ms=int(p.get("wait_ms", 2000)),
                humanize=bool(p.get("humanize", False)),
            )
        except PolicyViolationError as e:
            raise RpcError(-32001, str(e), data=e.data) from e
        except Exception as e:  # noqa: BLE001
            raise RpcError(-32003, f"web.cloak failed: {e}")

    # ------------------------------------------------------------------
    # proxy / egress verification
    # ------------------------------------------------------------------

    async def _m_proxy_status(self, p: Dict[str, Any]) -> Dict[str, Any]:
        mgr = self.manager
        socks = mgr._tor_socks_endpoint()
        sh, sp = _split_hostport(socks, 9050)
        reachable = await mgr._tcp_probe(sh, sp, timeout=2.0)
        ip_check: Dict[str, Any] = {"exit_ip": None}
        if reachable:
            ip_check["exit_ip"] = await mgr._canary_ip(socks)
        out = {
            "tor": {
                "socks": socks,
                "reachable": reachable,
            },
            "socks5": reachable,
            "ip_check": ip_check,
            "engagement": self.engagement,
        }
        self.manager.audit({"action": "proxy.status", "status": "ok",
                            "target": socks,
                            "detail": {"reachable": reachable}})
        return out

    async def _m_proxy_test(self, p: Dict[str, Any]) -> Dict[str, Any]:
        """Execute curl through SOCKS to a canary; assert no identity leak."""
        mgr = self.manager
        socks = mgr._tor_socks_endpoint()
        tor_ip = await mgr._canary_ip(socks)
        if tor_ip is None:
            raise ComponentError(
                f"tor SOCKS unreachable at {socks}; start the tor-proxy service "
                "(docker compose --profile tor up -d tor-proxy)",
                data={"socks": socks},
            )
        direct_ip = await mgr._canary_ip(None)
        tor_info = await mgr._tor_check()
        distinct = direct_ip is None or direct_ip != tor_ip
        out = {
            "ok": bool(distinct and (tor_info or {}).get("IsTor", distinct)),
            "socks": socks,
            "exit_ip": tor_ip,
            "direct_ip": direct_ip,
            "tor_confirmed": (tor_info or {}).get("IsTor"),
            "identity_leak": not distinct,
        }
        self.manager.audit({
            "action": "proxy.test", "target": "canary", "status": "ok",
            "detail": {"exit_ip": tor_ip, "direct_ip": direct_ip,
                       "leak": out["identity_leak"]},
        })
        return out

    async def _m_bridge_logs(self, p: Dict[str, Any]) -> Dict[str, Any]:
        last_n = int(p.get("last_n") or 50)
        lines = self.manager.recent_logs(last_n)
        return {
            "count": len(lines),
            "audit_file": self.manager.audit_path(),
            "lines": lines,
        }

    # ------------------------------------------------------------------
    # MCP shim (stdio MCP server mount for OpenCode)
    # ------------------------------------------------------------------

    async def _m_mcp_initialize(self, p: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "protocolVersion": p.get("protocolVersion") or "2024-11-05",
            "capabilities": {
                "tools": {"listChanged": False},
            },
            "serverInfo": {"name": BRIDGE_NAME, "version": VERSION},
        }

    async def _m_mcp_tools_list(self, p: Dict[str, Any]) -> Dict[str, Any]:
        descs = {
            "system.health": "Probe tor/sliver/neo4j/kali/vpn/dns components",
            "bridge.version": "Bridge + repo + engagement info",
            "vpn.status": "OpenVPN session state (explicit, never crashes)",
            "vpn.connect": "Bring up engagement VPN (fail closed on scope)",
            "vpn.disconnect": "Tear down VPN session",
            "targets.set": "Declare engagement scope (cidrs/urls/egress/creds)",
            "targets.get_policy": "Read engagement egress policy (no secrets)",
            "network.check_reachability": "Scoped async TCP port probes",
            "web.cloak": "Scoped stealth-browser page fetch (cloakbrowser) via engagement scope",
            "egress_policy.set": "Set mode proxy|tor|vpn|direct for engagement",
            "proxy.status": "Tor SOCKS reachability + exit IP check",
            "proxy.test": "Canary request through Tor; leak detection",
            "dns.resolve": "Scoped DNS (deferred to SOCKS under tor)",
            "tls.query": "Scoped TLS version/cipher/cert inspection",
            "vpn/profile/load": "Validate + attach an OpenVPN profile",
            "bridge.logs": "Tail the audit trail",
            "kali.run": "Scoped tool run routed to kali-tools (single catalog)",
            "scan.broad": "Engagement-scoped broad TCP scan (tools/broadscan)",
        }
        schemas = {
            "targets.set": {
                "type": "object",
                "required": ["engagement_id", "cidrs"],
                "properties": {
                    "engagement_id": {"type": "string"},
                    "cidrs": {"type": "array", "items": {"type": "string"}},
                    "urls": {"type": "array", "items": {"type": "string"}},
                    "egress": {"type": "string",
                               "enum": ["proxy", "tor", "vpn", "direct"]},
                    "credentials": {"type": "object"},
                },
            },
            "kali.run": {
                "type": "object",
                "required": ["tool", "target"],
                "properties": {
                    "tool": {"type": "string"},
                    "args": {"type": "array", "items": {"type": "string"}},
                    "target": {"type": "string"},
                    "timeout": {"type": "number"},
                },
            },
            "dns.resolve": {
                "type": "object", "required": ["host"],
                "properties": {"host": {"type": "string"}},
            },
            "web.cloak": {
                "type": "object",
                "required": ["url"],
                "properties": {
                    "url": {"type": "string"},
                    "timeout": {"type": "number"},
                    "screenshot": {"type": "boolean"},
                    "full_html": {"type": "boolean"},
                    "wait_ms": {"type": "integer"},
                    "humanize": {"type": "boolean"},
                },
            },
            "scan.broad": {
                "type": "object",
                "required": ["targets"],
                "properties": {
                    "targets": {"type": "array", "items": {"type": "string"}},
                    "ports": {"type": ["string", "array"]},
                    "rate": {"type": "integer"},
                    "timeout": {"type": "number"},
                    "syn": {"type": "boolean"},
                    "banners": {"type": "boolean"},
                    "shuffle": {"type": "boolean"},
                    "workers": {"type": "integer"},
                    "probe_timeout_ms": {"type": "integer"},
                    "opsec": {"type": "boolean"},
                    "decoys": {"type": "array", "items": {"type": "string"}},
                    "jitter_ms": {"type": "integer"},
                    "frag": {"type": "integer"},
                    "ttl": {"type": "string"},
                    "tcp_ts": {"type": "boolean"},
                    "sport": {"type": "string", "enum": ["random", "fixed"]},
                },
            },
        }
        tools = []
        for name, desc in descs.items():
            tools.append({
                "name": name,
                "description": desc,
                "inputSchema": schemas.get(
                    name,
                    {"type": "object", "properties": {}, "required": []},
                ),
            })
        return {"tools": tools}

    async def _m_mcp_tools_call(self, p: Dict[str, Any]) -> Dict[str, Any]:
        name = str(p.get("name") or "")
        arguments = p.get("arguments") or {}
        if name not in self.methods:
            raise RpcError(METHOD_NOT_FOUND, f"unknown tool {name!r}")
        handler, _scope_required = self.methods[name]
        result = await handler(arguments if isinstance(arguments, dict) else {})
        return {
            "content": [{"type": "text", "text": json.dumps(result, default=str)}],
            "isError": False,
        }

    # ------------------------------------------------------------------
    # JSON-RPC dispatch
    # ------------------------------------------------------------------

    async def handle_line(self, raw: str) -> Optional[Dict[str, Any]]:
        """Process one stdin line; returns the response object or None
        (notifications / unknown-id-less junk emit no response)."""
        request_id: Any = None
        try:
            req = json.loads(raw)
            if not isinstance(req, dict):
                raise ValueError("request must be an object")
            request_id = req.get("id")
            method = req.get("method")
            if not isinstance(method, str) or not method:
                raise ValueError("missing method")
        except (ValueError, json.JSONDecodeError) as e:
            resp = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": PARSE_ERROR,
                          "message": f"parse error: {e}"},
            }
            return resp

        if method not in self.methods:
            if request_id is None:
                return None  # notification: silently drop unknown methods
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": METHOD_NOT_FOUND,
                    "message": f"method {method!r} not found",
                    "data": {"known": sorted(self.methods)},
                },
            }

        params = req.get("params")
        if params is not None and not isinstance(params, dict):
            if request_id is None:
                return None
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": INVALID_PARAMS,
                          "message": "params must be an object"},
            }

        handler, scope_required = self.methods[method]
        if scope_required and self.manager.profile is None:
            # HARD RULE: fail closed before touching anything outward
            if request_id is None:
                return None
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": NotConfiguredError(
                    "fail closed: no engagement scope loaded; call "
                    "targets.set {engagement_id, cidrs[], egress} first"
                ).to_dict(),
            }

        try:
            result = await handler(params or {})
            # notifications emit no response (e.g. MCP notifications/initialized)
            if request_id is None:
                return None
            return {"jsonrpc": "2.0", "id": request_id, "result": result}
        except RpcError as e:
            if request_id is None:
                return None
            err: Dict[str, Any] = {"code": e.code, "message": e.message}
            if e.data:
                err["data"] = e.data
            return {"jsonrpc": "2.0", "id": request_id, "error": err}
        except BridgeError as e:
            if request_id is None:
                return None
            return {"jsonrpc": "2.0", "id": request_id, "error": e.to_dict()}
        except asyncio.TimeoutError:
            if request_id is None:
                return None
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32005,
                          "message": "operation timed out (non-fatal)"},
            }
        except Exception as e:  # noqa: BLE001 — never crash the bridge
            log.exception("handler %s crashed", method)
            self.manager.audit({
                "action": method, "status": "crashed",
                "error": _clip(f"{type(e).__name__}: {e}"),
            })
            if request_id is None:
                return None
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": INTERNAL_ERROR,
                    "message": f"internal error: {type(e).__name__}: "
                               f"{_clip(str(e), 256)}",
                },
            }


# ---------------------------------------------------------------------------
# stdio server loop
# ---------------------------------------------------------------------------


async def serve(bridge: "RaphaelBridge") -> None:
    """Read line-delimited JSON-RPC from stdin until EOF; write to stdout.

    Blocking readline runs in a worker thread (robust on pipes); all method
    handlers are async; stdout carries ONLY JSON-RPC responses.
    """
    loop = asyncio.get_running_loop()
    bridge.write_pid()
    bridge.manager.audit({
        "action": "bridge.start",
        "status": "ok",
        "session_id": os.getpid(),
        "detail": {"version": VERSION, "repo_root": str(bridge.repo_root),
                   "engagement": bridge.engagement},
    })
    log.info(
        "%s v%s serving on stdio (repo=%s engagement=%s)",
        BRIDGE_NAME, VERSION, bridge.repo_root, bridge.engagement,
    )
    try:
        while True:
            line = await loop.run_in_executor(None, sys.stdin.readline)
            if not line:  # EOF — OpenCode closed the pipe
                break
            if not line.strip():
                continue
            resp = await bridge.handle_line(line.strip())
            if resp is not None:
                print(json.dumps(resp, default=str), flush=True)
    finally:
        bridge.manager.audit({"action": "bridge.stop", "status": "ok",
                              "duration_ms": int(
                                  (time.time() - bridge.started_at) * 1000)})
        bridge.remove_pid()
        await bridge.manager.close()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="raphael-bridge",
        description="Raphael external-target bridge (JSON-RPC over stdio)",
    )
    ap.add_argument("--engagement", default=None,
                    help="default engagement id (else BRIDGE_ENGAGEMENT / _global)")
    ap.add_argument("--policy", default=None,
                    help="engagement policy file to load at startup")
    ap.add_argument("--audit-dir", default=None,
                    help="override audit root (default <repo>/projects)")
    ap.add_argument("--repo-root", default=None,
                    help="override repo root detection")
    ap.add_argument("--version", action="store_true", help="print version and exit")
    ap.add_argument("--check", action="store_true",
                    help="emit one system.health response and exit (smoke)")
    return ap


async def _run(args: argparse.Namespace) -> int:
    repo_root = Path(args.repo_root) if args.repo_root else resolve_repo_root()
    load_env_file(repo_root)  # .env (gitignored) supplies EGRESS_STRATEGY etc.

    manager = ExternalTargetManager(
        env=None,
        repo_root=repo_root,
        audit_root=Path(args.audit_dir) if args.audit_dir else None,
    )
    bridge = RaphaelBridge(
        manager, repo_root=repo_root, engagement=args.engagement
    )

    if args.policy:
        await manager.load_profile(remap_legacy(args.policy))
    elif args.engagement and args.engagement != "_global":
        try:
            manager.load_engagement_policy(args.engagement)
        except NotConfiguredError:
            log.info("no persisted policy for %s; waiting for targets.set",
                     args.engagement)

    if args.check:
        resp = await bridge.handle_line(
            json.dumps({"jsonrpc": "2.0", "id": "check",
                       "method": "system.health", "params": {}})
        )
        print(json.dumps(resp, default=str))
        await manager.close()
        return 0

    await serve(bridge)
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    logging.basicConfig(
        level=os.environ.get("BRIDGE_LOG_LEVEL", "INFO"),
        stream=sys.stderr,  # stdout is reserved for JSON-RPC
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    args = build_parser().parse_args(argv)
    if args.version:
        print(json.dumps({"bridge": BRIDGE_NAME, "version": VERSION}))
        return 0
    try:
        return asyncio.run(_run(args))
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
