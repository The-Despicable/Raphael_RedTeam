"""External Target Manager for Raphael 2.0.

Single policy-enforcement point for every external (internet / Tor / VPN /
tunnel) operation Raphael performs. Used by ``bridge/raphael_bridge.py``
(JSON-RPC stdio) and callable directly from ``raphael-api``.

Design invariants
-----------------
* FAIL CLOSED: without an engagement profile (engagement_id + scope CIDRs +
  egress policy) every outward-looking operation refuses with
  ``PolicyViolationError``/``NotConfiguredError`` — never silently proceeds.
* SECRETS ARE NEVER ECHOED: credentials are held in memory / persisted with
  0600 perms, and every response/audit/exception redacts them to ``***``.
* AUDIT EVERYTHING: every external session logs timestamp, source iface,
  target, bytes, duration and status under ``projects/<engagement>/bridge/``.
* GRACEFUL DEGRADATION: missing openvpn / TUN / Tor / Kali produce explicit
  non-fatal errors (never crash-loops).
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import re
import shutil
import socket
import ssl
import stat
import subprocess
import tempfile
import time
import uuid
from collections import deque
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Deque, Dict, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlsplit

import httpx

log = logging.getLogger("raphael.bridge.manager")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_CLIP = 4096                       # max chars of captured stdout/stderr kept
DEFAULT_MAX_PACKET_RATE = 30          # pps ceiling per engagement (NAT default)
DEFAULT_VPN_CONNECT_TIMEOUT = 45.0
DEFAULT_REACH_TIMEOUT = 3.0
DEFAULT_DNS_LIFETIME = 3.0
DEFAULT_TOOL_TIMEOUT = 120.0
ENGAGEMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
TOOL_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")
DEFAULT_IP_CHECK = "https://api.ipify.org"
TOR_IP_CHECK = "https://check.torproject.org/api/ip"

#: Read-only, non-destructive hosts the bridge may touch without an
#: engagement scope (exit-IP canaries and documentation domains only).
CANARY_HOSTS = frozenset(
    {
        "api.ipify.org",
        "check.torproject.org",
        "example.com",
        "www.example.com",
        "ifconfig.me",
        "icanhazip.com",
        "dns.google",
        "one.one.one.one",
        "cloudflare.com",
    }
)
CANARY_SUFFIXES = (".torproject.org", ".ipify.org")

DEFAULT_LOCAL_TOOL_ALLOWLIST = (
    "nmap", "nuclei", "curl", "dig", "whois", "ping", "traceroute", "masscan",
)


def _clip(text: str, limit: int = MAX_CLIP) -> str:
    """Clip captured subprocess/HTTP output so logs and errors stay small."""
    if text is None:
        return ""
    if len(text) <= limit:
        return text
    return text[:limit] + f" ...[clipped {len(text) - limit} chars]"


def _is_canary(host: str) -> bool:
    h = (host or "").strip().lower().rstrip(".")
    return h in CANARY_HOSTS or any(h.endswith(s) for s in CANARY_SUFFIXES)


def _split_hostport(s: str, default_port: int) -> Tuple[str, int]:
    if not s:
        return "", default_port
    if s.count(":") == 1 and not s.startswith("["):
        host, _, port = s.partition(":")
        return host, int(port) if port.isdigit() else default_port
    return s, default_port


def _detect_repo_root() -> Path:
    """Repo root = parent of src/ (this file is src/bridge/...)."""
    return Path(__file__).resolve().parents[2]


# ---------------------------------------------------------------------------
# Errors (JSON-RPC friendly codes)
# ---------------------------------------------------------------------------


class BridgeError(Exception):
    """Base class — carries a JSON-RPC-ish error code."""

    code = -32000

    def __init__(self, message: str, *, data: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.data = data or {}

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"code": self.code, "message": self.message[:512]}
        if self.data:
            d["data"] = self.data
        return d


class PolicyViolationError(BridgeError):
    """Engagement scope / policy refused the operation (fail closed)."""

    code = -32001


class NotConfiguredError(BridgeError):
    """Required component/credential/config missing — explicit + non-fatal."""

    code = -32002


class ComponentError(BridgeError):
    """Component present but failed (openvpn handshake, unreachable...)."""

    code = -32003


class RateLimitError(BridgeError):
    """Engagement packet-rate ceiling hit."""

    code = -32004

    def __init__(self, message: str = "engagement rate limit exceeded",
                 *, data: Optional[Dict[str, Any]] = None):
        super().__init__(message, data=data or {"retry_after": 1.0})


# ---------------------------------------------------------------------------
# Egress policy
# ---------------------------------------------------------------------------


class EgressPolicy(str, Enum):
    DIRECT = "direct"
    PROXY_TOR = "proxy_tor"
    VPN = "vpn"
    SSH_TUNNEL = "ssh_tunnel"
    HTTP_CONNECT = "http_connect"

    @classmethod
    def coerce(cls, value: Any) -> "EgressPolicy":
        """Accepts JSON-RPC spellings: proxy|tor|socks5 -> proxy_tor, etc."""
        if isinstance(value, cls):
            return value
        v = str(value or "").strip().lower().replace("-", "_")
        aliases = {
            "": cls.DIRECT,
            "tor": cls.PROXY_TOR,
            "proxy": cls.PROXY_TOR,
            "socks": cls.PROXY_TOR,
            "socks5": cls.PROXY_TOR,
            "proxy_tor": cls.PROXY_TOR,
            "vpn": cls.VPN,
            "openvpn": cls.VPN,
            "direct": cls.DIRECT,
            "nat": cls.DIRECT,
            "ssh": cls.SSH_TUNNEL,
            "ssh_tunnel": cls.SSH_TUNNEL,
            "http": cls.HTTP_CONNECT,
            "http_connect": cls.HTTP_CONNECT,
            "connect": cls.HTTP_CONNECT,
        }
        if v in aliases:
            return aliases[v]
        try:
            return cls(v)
        except ValueError:
            raise PolicyViolationError(
                f"unknown egress mode {value!r}; expected one of "
                "direct|tor|proxy|vpn|ssh_tunnel|http_connect"
            ) from None


# ---------------------------------------------------------------------------
# Engagement profile
# ---------------------------------------------------------------------------


@dataclass
class OvpnProfileMeta:
    """Parsed .ovpn metadata (never the secrets)."""

    path: str
    remote_host: str
    remote_port: int
    proto: str
    requires_auth: bool
    auth_file: Optional[str] = None
    remote_count: int = 1
    warnings: Tuple[str, ...] = ()
    size_bytes: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "remote_host": self.remote_host,
            "remote_port": self.remote_port,
            "proto": self.proto,
            "requires_auth": self.requires_auth,
            "auth_from_file": self.auth_file is not None,
            "remote_count": self.remote_count,
            "warnings": list(self.warnings),
            "size_bytes": self.size_bytes,
        }


def parse_ovpn_profile(path: "os.PathLike[str] | str") -> OvpnProfileMeta:
    """Validate an OpenVPN profile and extract its remote line.

    Raises ``NotConfiguredError`` with an explicit, non-secret message on any
    structural problem (missing file, empty file, no ``remote`` line).
    """
    p = Path(path)
    if not p.is_file():
        raise NotConfiguredError(f"OpenVPN profile not found: {p}")
    try:
        text = p.read_text(errors="replace")
    except OSError as e:
        raise NotConfiguredError(f"OpenVPN profile unreadable: {e}") from e
    if not text.strip():
        raise NotConfiguredError(f"OpenVPN profile is empty: {p}")

    remotes: List[Tuple[str, str, Optional[str]]] = []
    proto = "udp"
    requires_auth = False
    auth_file: Optional[str] = None
    warnings: List[str] = []

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        parts = line.split()
        d = parts[0].lower()
        if d == "remote" and len(parts) >= 2:
            port = parts[2] if len(parts) > 2 and parts[2].isdigit() else "1194"
            l4 = parts[3].lower() if len(parts) > 3 else None
            remotes.append((parts[1], port, l4))
        elif d == "proto" and len(parts) > 1:
            proto = parts[1].lower()
        elif d == "auth-user-pass":
            requires_auth = True
            auth_file = parts[1] if len(parts) > 1 else None
        elif d in ("up", "down", "route-up", "iproute", "tls-verify") and len(parts) > 1:
            warnings.append(
                f"directive '{d}' executes a user script with root privileges"
            )
        elif d == "script-security" and len(parts) > 1 and parts[1] not in ("0", "1"):
            warnings.append(
                f"script-security {parts[1]} allows arbitrary script execution"
            )

    if not remotes:
        raise NotConfiguredError(
            f"OpenVPN profile has no 'remote <host> <port>' line: {p}"
        )
    host, port, l4 = remotes[0]
    return OvpnProfileMeta(
        path=str(p),
        remote_host=host,
        remote_port=int(port),
        proto=(l4 or proto),
        requires_auth=requires_auth,
        auth_file=auth_file,
        remote_count=len(remotes),
        warnings=tuple(warnings),
        size_bytes=len(text),
    )


@dataclass
class EgressProfile:
    """Declared engagement scope — everything the fail-closed gate needs."""

    engagement_id: str
    cidrs: Tuple[str, ...] = ()
    urls: Tuple[str, ...] = ()
    egress: EgressPolicy = EgressPolicy.DIRECT
    tor_socks: str = "tor-proxy:9050"
    proxy_auth: Optional[str] = None
    vpn_profile_path: Optional[str] = None
    vpn_username: Optional[str] = None
    vpn_password: Optional[str] = None
    sliver_config_path: Optional[str] = None
    dns_servers: Tuple[str, ...] = ()
    allowed_ports: Tuple[int, ...] = ()
    max_packet_rate: int = DEFAULT_MAX_PACKET_RATE
    meta: Dict[str, Any] = field(default_factory=dict)

    # -- validation --------------------------------------------------------

    @classmethod
    def from_obj(cls, obj: Mapping[str, Any]) -> "EgressProfile":
        if not isinstance(obj, Mapping):
            raise PolicyViolationError("policy object must be a mapping")
        engagement = str(obj.get("engagement_id") or "").strip()
        if not ENGAGEMENT_RE.match(engagement):
            raise PolicyViolationError(
                "engagement_id is required and must match "
                f"{ENGAGEMENT_RE.pattern} (fail closed)"
            )

        cidrs = tuple(str(c).strip() for c in (obj.get("cidrs") or []) if str(c).strip())
        urls = tuple(str(u).strip() for u in (obj.get("urls") or []) if str(u).strip())
        if not cidrs:
            raise PolicyViolationError(
                "targets.set requires at least one target_scope_cidr (fail closed)"
            )
        for c in cidrs:
            try:
                ipaddress.ip_network(c, strict=False)
            except ValueError:
                raise PolicyViolationError(f"invalid CIDR in scope: {c!r}") from None
        for u in urls:
            if "/" in u or " " in u:
                raise PolicyViolationError(
                    f"invalid URL/host scope entry: {u!r} (use scheme-less host or host:port)"
                )

        ports = tuple(
            int(p) for p in (obj.get("allowed_ports") or [])
        )
        for p in ports:
            if not (1 <= p <= 65535):
                raise PolicyViolationError(f"invalid allowed port: {p}")

        rate = int(obj.get("max_packet_rate") or DEFAULT_MAX_PACKET_RATE)
        if not (1 <= rate <= 10_000):
            raise PolicyViolationError(
                f"max_packet_rate must be within 1..10000 (got {rate})"
            )

        creds = obj.get("credentials") or {}
        if not isinstance(creds, Mapping):
            raise PolicyViolationError("credentials must be a mapping")

        return cls(
            engagement_id=engagement,
            cidrs=cidrs,
            urls=urls,
            egress=EgressPolicy.coerce(obj.get("egress")),
            tor_socks=str(creds.get("tor_socks") or obj.get("tor_socks")
                         or "tor-proxy:9050"),
            proxy_auth=str(creds["proxy_auth"]) if creds.get("proxy_auth") else None,
            vpn_profile_path=str(creds["vpn_profile_path"]) if creds.get("vpn_profile_path") else None,
            vpn_username=str(creds["vpn_username"]) if creds.get("vpn_username") else None,
            vpn_password=str(creds["vpn_password"]) if creds.get("vpn_password") else None,
            sliver_config_path=str(creds["sliver_config_path"]) if creds.get("sliver_config_path") else None,
            dns_servers=tuple(
                str(s) for s in (obj.get("dns_servers") or []) if str(s).strip()
            ),
            allowed_ports=ports,
            max_packet_rate=rate,
            meta=dict(obj.get("meta") or {}),
        )

    def to_obj(self, *, redact: bool = False) -> Dict[str, Any]:
        d = asdict(self)
        d["egress"] = self.egress.value
        if redact:
            for k in ("vpn_password", "proxy_auth"):
                if d.get(k):
                    d[k] = "***"
        return d

    def summary(self) -> Dict[str, Any]:
        """Secret-free view used in responses, logs and audit records."""
        return {
            "engagement_id": self.engagement_id,
            "cidrs": list(self.cidrs),
            "urls": list(self.urls),
            "egress": self.egress.value,
            "allowed_ports": list(self.allowed_ports),
            "max_packet_rate": self.max_packet_rate,
            "has_vpn_profile": bool(self.vpn_profile_path),
            "has_vpn_credentials": bool(self.vpn_username and self.vpn_password),
            "has_proxy_auth": bool(self.proxy_auth),
            "dns_servers": list(self.dns_servers),
        }


# ---------------------------------------------------------------------------
# Small system helpers
# ---------------------------------------------------------------------------


def _tun_up() -> bool:
    """True when a tun/tap interface exists (VPN active). Linux-only, safe."""
    try:
        for name in os.listdir("/sys/class/net"):
            if name.startswith(("tun", "tap")):
                return True
    except OSError:
        pass
    try:  # fallback for non-Linux / containers hiding /sys
        import socket as _s
        _s.if_nametoindex("tun0")
        return True
    except Exception:  # noqa: BLE001
        return False


def default_iface() -> str:
    """Default-route interface from /proc/net/route (no subprocess)."""
    if _tun_up():
        return "tun0"
    try:
        with open("/proc/net/route") as f:
            next(f)  # header
            for line in f:
                cols = line.split()
                if len(cols) > 3 and cols[1] == "00000000":
                    return cols[0]
    except OSError:
        pass
    return "unknown"


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return False
    except OSError:
        return False


class _RateLimiter:
    """Minimal token bucket enforcing the engagement pps ceiling."""

    def __init__(self, rate: float, burst: Optional[float] = None):
        self.rate = max(1.0, float(rate))
        self.burst = float(burst or self.rate)
        self.tokens = self.burst
        self.last = time.monotonic()

    def try_consume(self, n: float = 1.0) -> Optional[float]:
        """Consume n tokens; returns None on success or retry-after seconds."""
        now = time.monotonic()
        self.tokens = min(self.burst, self.tokens + (now - self.last) * self.rate)
        self.last = now
        if self.tokens >= n:
            self.tokens -= n
            return None
        return (n - self.tokens) / self.rate


# ---------------------------------------------------------------------------
# ExternalTargetManager
# ---------------------------------------------------------------------------


class ExternalTargetManager:
    """Policy-gated access to external targets (direct / tor / vpn / tunnels).

    Called by ``bridge/raphael_bridge.py`` and reusable from ``raphael-api``.
    Every outward operation is guarded by the engagement profile, rate
    limited, and audited under ``projects/<engagement>/bridge/``.
    """

    def __init__(
        self,
        policy_file_or_obj: Optional[Any] = None,
        *,
        env: Optional[Mapping[str, str]] = None,
        repo_root: Optional[os.PathLike | str] = None,
        audit_root: Optional[os.PathLike | str] = None,
    ):
        self.env: Dict[str, str] = dict(os.environ)
        if env:
            self.env.update({k: v for k, v in env.items() if v is not None})
        self.repo_root = Path(repo_root or _detect_repo_root()).resolve()
        self.audit_root = Path(
            audit_root or self.repo_root / "projects"
        ).resolve()
        self._source = policy_file_or_obj

        self.profile: Optional[EgressProfile] = None
        self.ovpn_meta: Optional[OvpnProfileMeta] = None
        self._recent: Deque[Dict[str, Any]] = deque(maxlen=1000)
        self._vpn: Dict[str, Any] = {}
        self._rate: Optional[_RateLimiter] = None
        self._http: Optional[httpx.AsyncClient] = None
        self._ssh_proc: Optional[asyncio.subprocess.Process] = None
        self._ssh_socks_port: Optional[int] = None
        self._kali_probe: Tuple[bool, float] = (False, 0.0)

    # ------------------------------------------------------------------
    # env helpers
    # ------------------------------------------------------------------

    def _env(self, name: str, default: str = "") -> str:
        v = self.env.get(name, default)
        return v if v is not None else default

    def _engagement(self) -> str:
        return self.profile.engagement_id if self.profile else "_global"

    # ------------------------------------------------------------------
    # Profile lifecycle
    # ------------------------------------------------------------------

    async def load_profile(self, source: Optional[Any] = None) -> Dict[str, Any]:
        """Load engagement policy from file (path) or object (mapping).

        Without any source the constructor-provided policy is used. Raises
        PolicyViolationError when the profile is structurally invalid — the
        manager never operates with a partial scope (fail closed).
        """
        src = source if source is not None else self._source
        if src is None:
            raise NotConfiguredError(
                "no engagement policy loaded; call targets.set first "
                "(engagement_id + target_scope_cidr + egress policy required)"
            )
        if isinstance(src, (str, os.PathLike)):
            p = Path(src)
            if not p.is_file():
                raise NotConfiguredError(f"policy file not found: {p}")
            obj = json.loads(p.read_text(errors="strict"))
        elif isinstance(src, Mapping):
            obj = dict(src)
        else:
            raise PolicyViolationError(
                "policy must be a file path or a mapping, got "
                f"{type(src).__name__}"
            )
        self.profile = EgressProfile.from_obj(obj)
        self._rate = _RateLimiter(self.profile.max_packet_rate)
        summary = self.profile.summary()
        self.audit({
            "action": "profile.load",
            "status": "ok",
            "target": None,
            "detail": summary,
        })
        return summary

    def persist_profile(self, profile: Optional[EgressProfile] = None) -> Path:
        """Persist engagement policy (incl. secrets) with 0600 perms."""
        prof = profile or self.profile
        if prof is None:
            raise NotConfiguredError("no profile to persist")
        path = self._engagement_dir(prof.engagement_id) / "policy.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(prof.to_obj(), indent=2))
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0600
        return path

    def load_engagement_policy(self, engagement_id: str) -> Dict[str, Any]:
        """Sync load of a persisted engagement policy (bridge helpers)."""
        if not ENGAGEMENT_RE.match(str(engagement_id or "")):
            raise PolicyViolationError("invalid engagement_id (path unsafe)")
        path = self.audit_root / engagement_id / "bridge" / "policy.json"
        if not path.is_file():
            raise NotConfiguredError(
                f"no persisted policy for engagement '{engagement_id}'; "
                "call targets.set first"
            )
        obj = json.loads(path.read_text())
        self.profile = EgressProfile.from_obj(obj)
        self._rate = _RateLimiter(self.profile.max_packet_rate)
        return self.profile.summary()

    def _require_profile(self) -> EgressProfile:
        if self.profile is None:
            raise NotConfiguredError(
                "fail closed: no engagement scope loaded; "
                "targets.set {engagement_id, cidrs[], egress} required"
            )
        return self.profile

    def _consume_rate(self, tokens: float = 1.0) -> None:
        if self._rate is not None:
            retry = self._rate.try_consume(tokens)
            if retry is not None:
                raise RateLimitError(data={"retry_after": round(retry, 2)})

    # ------------------------------------------------------------------
    # Audit
    # ------------------------------------------------------------------

    def _engagement_dir(self, engagement_id: Optional[str] = None) -> Path:
        eng = engagement_id or self._engagement()
        if not ENGAGEMENT_RE.match(str(eng)):
            eng = "_global"
        return self.audit_root / eng / "bridge"

    def audit(self, record: Mapping[str, Any]) -> None:
        """Append one JSONL audit record under projects/<eng>/bridge/."""
        rec: Dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "engagement": self._engagement(),
            "source_iface": default_iface(),
        }
        rec.update(dict(record))
        for k in ("vpn_password", "password", "proxy_auth"):
            if rec.get(k):
                rec[k] = "***"
        rec.setdefault("action", "unknown")
        rec.setdefault("status", "ok")
        rec["detail"] = _clip(json.dumps(rec.get("detail", ""), default=str)[:MAX_CLIP])
        try:
            d = self._engagement_dir()
            d.mkdir(parents=True, exist_ok=True)
            os.chmod(d, 0o700)
            with open(d / "audit.jsonl", "a") as f:
                f.write(json.dumps(rec, default=str) + "\n")
        except OSError as e:  # auditing must never kill the operation
            log.warning("audit write failed: %s", e)
        self._recent.append(rec)

    def recent_logs(self, last_n: int = 50) -> List[Dict[str, Any]]:
        n = max(1, min(int(last_n), 1000))
        return list(self._recent)[-n:]

    def audit_path(self) -> str:
        return str(self._engagement_dir() / "audit.jsonl")

    # ------------------------------------------------------------------
    # Scope validation (fail closed)
    # ------------------------------------------------------------------

    async def validate_target_scope(self, target: str) -> bool:
        """True only when target lies inside the declared engagement scope.

        Never raises for out-of-scope targets (returns False); callers that
        intend to act on the target must translate False into
        PolicyViolationError.
        """
        try:
            ok, _reason = self._scope_check(target)
        except (PolicyViolationError, NotConfiguredError):
            return False
        return ok

    def _scope_check(self, target: str) -> Tuple[bool, str]:
        """Scope engine. target: IP | CIDR | host | host:port | URL."""
        prof = self._require_profile()  # fail closed: no profile -> raise
        if not target or not isinstance(target, str):
            return False, "empty target"
        if len(target) > 2048:
            return False, "target too long"

        host: Optional[str] = None
        port: Optional[int] = None

        if "://" in target:  # URL form
            parts = urlsplit(target)
            host = parts.hostname
            if parts.port:
                port = parts.port
        else:
            s = target.strip()
            if s.count(":") == 1 and not s.startswith("["):
                h, _, p = s.partition(":")
                if p.isdigit():
                    host, port = h, int(p)
                else:
                    host = s
            else:
                host = s

        # Port policy
        if prof.allowed_ports and port is not None and port not in prof.allowed_ports:
            return False, f"port {port} not in allowed_ports"

        nets = [ipaddress.ip_network(c, strict=False) for c in prof.cidrs]

        # CIDR target: must be a subnet of some allowed CIDR
        if host and "/" in host:
            try:
                tnet = ipaddress.ip_network(host, strict=False)
            except ValueError:
                return False, "invalid CIDR target"
            for n in nets:
                if tnet.version == n.version and tnet.subnet_of(n):
                    return True, "cidr within scope"
            return False, "cidr outside scope"

        # IP literal target
        try:
            tip = ipaddress.ip_address(host)
        except ValueError:
            tip = None
        if tip is not None:
            for n in nets:
                if tip.version == n.version and tip in n:
                    return True, "ip within scope"
            return False, "ip outside scope"

        # Hostname target: matched only against declared url scopes
        h = (host or "").strip().lower().rstrip(".")
        for entry in prof.urls:
            e = entry.strip().lower().rstrip(".")
            if e.startswith("*."):
                if h.endswith(e[1:]) and len(h) > len(e[1:]):
                    return True, "host matches wildcard scope"
            elif h == e or h.startswith(e + ":"):
                return True, "host matches url scope"
        return False, "host not in url scope"

    def _require_in_scope(self, target: str, *, action: str = "operation") -> None:
        ok, reason = self._scope_check(target)
        if not ok:
            raise PolicyViolationError(
                f"target {target!r} is outside engagement scope ({reason})",
                data={"action": action, "engagement": self._engagement()},
            )

    # ------------------------------------------------------------------
    # Tor / proxy helpers
    # ------------------------------------------------------------------

    def _tor_socks_endpoint(self) -> str:
        prof = self.profile
        if prof is not None and prof.tor_socks:
            socks = prof.tor_socks
        else:
            socks = self._env("TOR_SOCKS", "tor-proxy:9050")
        return socks

    async def _tcp_probe(self, host: str, port: int, timeout: float = 2.0) -> bool:
        if not host or not port:
            return False
        fut = asyncio.ensure_future(asyncio.open_connection(host, port))
        try:
            reader, writer = await asyncio.wait_for(fut, timeout=timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass
            return True
        except (OSError, asyncio.TimeoutError):
            fut.cancel()
            try:
                await fut
            except (asyncio.CancelledError, OSError):
                pass
            return False

    async def proxy(self, mode: str = "socks5") -> Dict[str, Any]:
        """Resolve an egress proxy descriptor for the requested mode.

        socks5/tor  -> Tor SOCKS (or OUTBOUND_PROXY when no Tor)
        http_connect-> httpx-style HTTP CONNECT proxy via OUTBOUND_PROXY
        ssh_tunnel  -> managed ``ssh -N -D <port>`` dynamic forward
        """
        m = EgressPolicy.coerce(mode)
        out: Dict[str, Any] = {"mode": m.value, "reachable": False}

        if m is EgressPolicy.PROXY_TOR:
            socks = self._tor_socks_endpoint()
            out["endpoint"] = socks
            out["proxy_url"] = f"socks5://{socks}"
            out["reachable"] = await self._tcp_probe(
                *_split_hostport(socks, 9050), timeout=2.0
            )
        elif m is EgressPolicy.HTTP_CONNECT:
            upstream = self._env("OUTBOUND_PROXY")
            if not upstream:
                raise NotConfiguredError(
                    "HTTP CONNECT mode requires OUTBOUND_PROXY "
                    "(http://host:port) in environment"
                )
            out["endpoint"] = upstream
            out["proxy_url"] = upstream
            out["reachable"] = await self._tcp_probe(
                *_split_hostport(
                    urlsplit(upstream).netloc if "://" in upstream else upstream,
                    8080,
                ),
                timeout=2.0,
            )
        elif m is EgressPolicy.SSH_TUNNEL:
            out.update(await self.open_ssh_tunnel())
        else:
            raise PolicyViolationError(
                f"proxy() mode {mode!r} not supported here "
                "(use socks5|http_connect|ssh_tunnel)"
            )

        # Proxy env chain for kali-tools / brain subprocesses
        proxy_url = out.get("proxy_url") or ""
        out["env"] = {
            "HTTP_PROXY": proxy_url,
            "HTTPS_PROXY": proxy_url,
            "SOCKS_PROXY": proxy_url,
            "ALL_PROXY": proxy_url,
            "EGRESS_STRATEGY": m.value,
        }
        if self.profile and self.profile.proxy_auth:
            out["auth"] = True  # never echo proxy_auth
        self.audit({
            "action": "proxy",
            "target": out.get("endpoint"),
            "status": "ok" if out.get("reachable") else "unreachable",
            "detail": {"mode": m.value},
        })
        return out

    async def open_ssh_tunnel(self) -> Dict[str, Any]:
        """Non-interactive SSH dynamic SOCKS forward (``ssh -N -D``)."""
        host = self._env("SSH_TUNNEL_HOST")
        if not host:
            raise NotConfiguredError(
                "ssh_tunnel mode requires SSH_TUNNEL_HOST (optionally "
                "SSH_TUNNEL_PORT, SSH_TUNNEL_USER, SSH_TUNNEL_KEY, "
                "SSH_TUNNEL_SOCKS_PORT)"
            )
        port = self._env("SSH_TUNNEL_SOCKS_PORT", "1080")
        user = self._env("SSH_TUNNEL_USER")
        key = self._env("SSH_TUNNEL_KEY", str(Path.home() / ".ssh/id_rsa"))
        if not Path(key).expanduser().is_file():
            raise NotConfiguredError(f"SSH key not found: {key}")
        if self._ssh_proc is not None and self._ssh_proc.returncode is None:
            return {
                "mode": "ssh_tunnel",
                "endpoint": f"127.0.0.1:{self._ssh_socks_port}",
                "proxy_url": f"socks5://127.0.0.1:{self._ssh_socks_port}",
                "reachable": True,
                "pid": self._ssh_proc.pid,
            }
        tgt = f"{user}@{host}" if user else host
        cmd = [
            "ssh", "-N", "-D", port, "-o", "ExitOnForwardFailure=yes",
            "-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes",
            "-i", key, tgt,
        ]
        try:
            self._ssh_proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
        except FileNotFoundError:
            raise NotConfiguredError(
                "ssh binary not found; install openssh-client"
            ) from None
        await asyncio.sleep(0.5)
        if self._ssh_proc.returncode not in (None, 0):
            err = _clip((await self._ssh_proc.stderr.read()).decode(errors="replace"))
            self._ssh_proc = None
            raise ComponentError(f"ssh tunnel failed: {err or 'exited'}")
        self._ssh_socks_port = int(port)
        ok = await self._tcp_probe("127.0.0.1", self._ssh_socks_port, timeout=3.0)
        self.audit({
            "action": "proxy.ssh_tunnel",
            "target": tgt,
            "status": "ok" if ok else "unreachable",
            "session_id": self._ssh_proc.pid,
        })
        return {
            "mode": "ssh_tunnel",
            "endpoint": f"127.0.0.1:{self._ssh_socks_port}",
            "proxy_url": f"socks5://127.0.0.1:{self._ssh_socks_port}",
            "reachable": ok,
            "pid": self._ssh_proc.pid,
        }

    # ------------------------------------------------------------------
    # Egress canaries / leak tests
    # ------------------------------------------------------------------

    async def _canary_ip(
        self, socks: Optional[str] = None, url: Optional[str] = None
    ) -> Optional[str]:
        """Exit IP as seen by a canary service (None on failure — never raises)."""
        check_url = url or self._env("EGRESS_IP_CHECK", DEFAULT_IP_CHECK)
        if socks:
            try:
                import socksio  # noqa: F401  (httpx socks support)
                async with httpx.AsyncClient(
                    proxy=f"socks5://{socks}", timeout=8.0
                ) as client:
                    r = await client.get(check_url)
                    text = r.text.strip()
            except ImportError:
                text = await self._curl_canary(check_url, socks)
            except (httpx.HTTPError, OSError):
                text = await self._curl_canary(check_url, socks)
        else:
            try:
                async with httpx.AsyncClient(
                    timeout=8.0, trust_env=False
                ) as client:
                    r = await client.get(check_url)
                    text = r.text.strip()
            except (httpx.HTTPError, OSError):
                text = ""
        try:
            ipaddress.ip_address(text)
            return text
        except ValueError:
            return None

    async def _curl_canary(self, url: str, socks: str) -> str:
        """curl --socks5-hostname canary (DNS stays inside the Tor circuit)."""
        cmd = ["curl", "-sS", "-m", "10", "--socks5-hostname", socks, url]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            out, err = await asyncio.wait_for(proc.communicate(), timeout=12.0)
        except (OSError, asyncio.TimeoutError):
            return ""
        if err:
            log.debug("curl canary stderr: %s", _clip(err.decode(errors="replace")))
        return out.decode(errors="replace").strip()

    async def _tor_check(self) -> Optional[Dict[str, Any]]:
        """Query check.torproject.org/api/ip through Tor SOCKS."""
        raw = await self._curl_canary(
            TOR_IP_CHECK, self._tor_socks_endpoint()
        )
        if not raw:
            return None
        try:
            info = json.loads(raw)
            return {"IsTor": bool(info.get("IsTor")), "IP": info.get("IP")}
        except ValueError:
            return None

    async def test_egress(self) -> Dict[str, Any]:
        """Verify what the outside world sees: exit IP, tor circuit, VPN iface.

        Touches only canary hosts — safe to run without an engagement scope.
        """
        if self.profile is not None:
            policy = self.profile.egress
        else:
            policy = EgressPolicy.coerce(self._env("EGRESS_STRATEGY", "direct"))

        direct_ip = await self._canary_ip(None)
        out: Dict[str, Any] = {
            "egress_policy": policy.value,
            "direct_ip": direct_ip,
            "exit_ip": None,
            "tor_circuit": None,
            "vpn_exposed": _tun_up(),
            "leak_suspected": False,
        }

        if policy is EgressPolicy.PROXY_TOR:
            out["exit_ip"] = await self._canary_ip(self._tor_socks_endpoint())
            info = await self._tor_check()
            if info is not None:
                out["tor_circuit"] = info.get("IsTor")
            out["leak_suspected"] = bool(
                direct_ip is not None
                and out["exit_ip"] is not None
                and direct_ip == out["exit_ip"]
            )
        elif policy is EgressPolicy.VPN:
            out["exit_ip"] = direct_ip if out["vpn_exposed"] else None
        else:
            out["exit_ip"] = direct_ip

        self.audit({
            "action": "test_egress",
            "target": self._env("EGRESS_IP_CHECK", DEFAULT_IP_CHECK),
            "status": "ok" if out["exit_ip"] else "unreachable",
            "bytes": 0,
            "detail": {k: out[k] for k in ("egress_policy", "exit_ip", "direct_ip")},
        })
        return out

    # ------------------------------------------------------------------
    # DNS
    # ------------------------------------------------------------------

    def _dns_servers(self) -> List[str]:
        prof = self.profile
        servers: List[str] = []
        if prof is not None and prof.dns_servers:
            servers = list(prof.dns_servers)
        else:
            primary = self._env("DNS_PRIMARY", "8.8.8.8")
            secondary = self._env("DNS_SECONDARY", "1.1.1.1")
            corporate = self._env("DNS_CORPORATE")
            # Under VPN, corporate DNS takes priority (internal resolvable names)
            if corporate and (prof is None or prof.egress is EgressPolicy.VPN):
                servers = [corporate]
            if primary:
                servers.append(primary)
            if secondary:
                servers.append(secondary)
        return servers

    async def resolve(self, host: str) -> Dict[str, Any]:
        """Scoped DNS resolution. Canary hosts resolve freely (read-only).

        Under proxy_tor policy, in-scope hostnames are NOT resolved locally:
        resolution is deferred to the SOCKS circuit (socks5h) so DNS never
        leaks outside Tor. All other policies resolve via configured servers
        (dnspython first, socket fallback), gracefully degrading.
        """
        raw = (host or "").strip()
        if "://" in raw:  # tolerate URLs
            raw = urlsplit(raw).hostname or ""
        h = raw.lower().rstrip(".")
        if not h:
            raise PolicyViolationError("dns.resolve requires a host")
        if h.count(".") == 0 and not _is_canary(h):
            raise PolicyViolationError(f"invalid host {host!r}")

        if _is_canary(h):
            policy = (
                self.profile.egress if self.profile
                else EgressPolicy.coerce(self._env("EGRESS_STRATEGY", "direct"))
            )
        else:
            prof = self._require_profile()
            self._require_in_scope(h, action="dns.resolve")
            policy = prof.egress

        started = time.monotonic()
        if policy is EgressPolicy.PROXY_TOR and not _is_canary(h):
            # Fail closed on DNS: defer to the Tor circuit, never query locally.
            res = {
                "host": h,
                "addresses": [],
                "resolver": "deferred",
                "deferred_to_proxy": True,
                "via": f"socks5h://{self._tor_socks_endpoint()}",
                "nameservers": [],
                "note": (
                    "DNS deferred to Tor SOCKS circuit to avoid leaking "
                    "queries; pass the hostname to kali.run/tls via the proxy"
                ),
            }
            self.audit({"action": "dns.resolve", "target": h, "status": "deferred",
                        "detail": {"resolver": "socks5h"}})
            return res

        servers = self._dns_servers()
        addresses: List[str] = []
        used = "socket"
        try:
            import dns.asyncresolver  # dnspython
            r = dns.asyncresolver.Resolver(configure=False)
            r.nameservers = servers
            r.lifetime = DEFAULT_DNS_LIFETIME
            try:
                ans = await r.resolve(h, "A")
                addresses = sorted({a.address for a in ans})
                used = "dnspython"
            except Exception:  # noqa: BLE001 — graceful fallback
                addresses = await self._socket_resolve(h)
        except ImportError:
            addresses = await self._socket_resolve(h)
        except Exception as e:  # noqa: BLE001 — never crash on DNS
            addresses = await self._socket_resolve(h)
            log.debug("dns fallback (%s): %s", h, e)

        if not addresses:
            self.audit({"action": "dns.resolve", "target": h, "status": "nxdomain"})
            return {
                "host": h,
                "addresses": [],
                "resolver": used,
                "nameservers": servers,
                "error": "resolution failed (graceful)",
            }
        self.audit({
            "action": "dns.resolve", "target": h, "status": "ok",
            "duration_ms": int((time.monotonic() - started) * 1000),
            "detail": {"resolver": used, "count": len(addresses)},
        })
        return {
            "host": h,
            "addresses": addresses,
            "resolver": used,
            "nameservers": servers,
        }

    async def _socket_resolve(self, h: str) -> List[str]:
        def _do() -> List[str]:
            try:
                infos = socket.getaddrinfo(h, None, proto=socket.IPPROTO_TCP)
                return sorted({i[4][0] for i in infos})
            except OSError:
                return []
        return await asyncio.to_thread(_do)

    # ------------------------------------------------------------------
    # Reachability / TLS
    # ------------------------------------------------------------------

    def _tor_hostname_guard(self, host: str, action: str) -> None:
        """Under proxy_tor, refuse hostname targets (raw TCP/resolve would
        leak DNS outside the circuit). IP literals carry no DNS, allowed."""
        policy = self.profile.egress if self.profile else EgressPolicy.DIRECT
        if policy is EgressPolicy.PROXY_TOR and not _is_canary(host):
            try:
                ipaddress.ip_address(host)
            except ValueError:
                raise PolicyViolationError(
                    f"{action} on hostname {host!r} would leak DNS under tor "
                    "policy; use an in-scope IP literal or route the tool "
                    "through the SOCKS proxy (kali.run)",
                    data={"action": action},
                )

    async def check_reachability(
        self,
        target: str,
        ports: Sequence[int],
        timeout: float = DEFAULT_REACH_TIMEOUT,
    ) -> Dict[str, Any]:
        """Scoped async TCP reachability across ports (no data sent)."""
        self._require_profile()
        self._require_in_scope(target, action="check_reachability")
        host, default_port = self._parse_target(target, default_port=443)
        self._tor_hostname_guard(host, "check_reachability")
        if not ports:
            ports = [default_port]
        ports = sorted({int(p) for p in ports if 1 <= int(p) <= 65535})
        self._consume_rate(max(1.0, len(ports) / 8.0))

        started = time.monotonic()

        async def _one(port: int) -> Dict[str, Any]:
            t0 = time.monotonic()
            fut = asyncio.ensure_future(asyncio.open_connection(host, port))
            try:
                _, writer = await asyncio.wait_for(fut, timeout=timeout)
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:  # noqa: BLE001
                    pass
                state = "open"
            except ConnectionRefusedError:
                state = "closed"
            except asyncio.TimeoutError:
                fut.cancel()
                state = "filtered"
            except OSError:
                fut.cancel()
                state = "filtered"
            return {
                "port": port,
                "state": state,
                "latency_ms": int((time.monotonic() - t0) * 1000),
            }

        results = await asyncio.gather(*(_one(p) for p in ports))
        open_ports = [r["port"] for r in results if r["state"] == "open"]
        out = {
            "target": str(target),
            "host": host,
            "ports": results,
            "open": open_ports,
            "transport": "direct-tcp",
            "duration_ms": int((time.monotonic() - started) * 1000),
        }
        self.audit({
            "action": "check_reachability",
            "target": str(target),
            "status": "ok",
            "bytes": 0,
            "duration_ms": out["duration_ms"],
            "detail": {"probed": len(ports), "open": open_ports[:32]},
        })
        return out

    def _parse_target(self, target: str, default_port: int) -> Tuple[str, int]:
        s = (target or "").strip()
        if "://" in s:
            parts = urlsplit(s)
            return parts.hostname or "", parts.port or default_port
        return _split_hostport(s, default_port)

    async def tls_query(
        self,
        target: str,
        min_version: Optional[str] = None,
        cipher: Optional[str] = None,
        timeout: float = 8.0,
    ) -> Dict[str, Any]:
        """Scoped TLS inspection: version, cipher, cert, min-version check."""
        self._require_profile()
        self._require_in_scope(target, action="tls.query")
        host, port = self._parse_target(target, default_port=443)
        self._tor_hostname_guard(host, "tls.query")
        self._consume_rate(1.0)

        ctx = ssl.create_default_context()
        if cipher:
            try:
                ctx.set_ciphers(cipher)
            except ssl.SSLError as e:
                raise PolicyViolationError(f"invalid cipher spec: {e}") from None

        version_map = {
            "tls1": ssl.TLSVersion.TLSv1,
            "tls1.0": ssl.TLSVersion.TLSv1,
            "tls1.1": ssl.TLSVersion.TLSv1_1,
            "tls1.2": ssl.TLSVersion.TLSv1_2,
            "tls1.3": ssl.TLSVersion.TLSv1_3,
        }
        min_v: Optional[ssl.TLSVersion] = None
        if min_version:
            min_v = version_map.get(str(min_version).lower())
            if min_v is None:
                raise PolicyViolationError(
                    f"unknown min_version {min_version!r}; use tls1|tls1.1|tls1.2|tls1.3"
                )
            ctx.minimum_version = min_v

        started = time.monotonic()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx),
                timeout=timeout,
            )
        except (OSError, ssl.SSLError, asyncio.TimeoutError) as e:
            self.audit({
                "action": "tls.query", "target": str(target),
                "status": "failed", "error": _clip(str(e)),
            })
            raise ComponentError(
                f"TLS connect to {host}:{port} failed: {type(e).__name__}: "
                f"{_clip(str(e), 256)}"
            ) from e

        ver_map = {
            "TLSv1": ssl.TLSVersion.TLSv1,
            "TLSv1.0": ssl.TLSVersion.TLSv1,
            "TLSv1.1": ssl.TLSVersion.TLSv1_1,
            "TLSv1.2": ssl.TLSVersion.TLSv1_2,
            "TLSv1.3": ssl.TLSVersion.TLSv1_3,
        }
        try:
            ssl_obj: ssl.SSLObject = writer.get_extra_info("ssl_object")
            cert = ssl_obj.getpeercert() or {}
            negotiated = ssl_obj.version()
            cipher_tuple = ssl_obj.cipher()
            negotiated_version = ver_map.get(negotiated or "")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass

        satisfies = True
        if min_v is not None and negotiated_version is not None:
            satisfies = negotiated_version >= min_v

        out = {
            "target": str(target),
            "host": host,
            "port": port,
            "tls_version": negotiated,
            "cipher": list(cipher_tuple) if cipher_tuple else [],
            "peer_subject": cert.get("subject"),
            "issuer": cert.get("issuer"),
            "not_after": cert.get("notAfter"),
            "min_version_requested": str(min_version) if min_version else None,
            "satisfies_min_version": satisfies,
            "duration_ms": int((time.monotonic() - started) * 1000),
        }
        self.audit({
            "action": "tls.query", "target": str(target), "status": "ok",
            "duration_ms": out["duration_ms"], "bytes": 0,
            "detail": {"tls_version": negotiated, "satisfies": satisfies},
        })
        return out

    # ------------------------------------------------------------------
    # VPN (OpenVPN subprocess, non-interactive, fail closed)
    # ------------------------------------------------------------------

    def link_profile(self, path: str) -> Dict[str, Any]:
        """Validate an OVPN file and attach it to the engagement profile.

        Returns parsed metadata (never secrets). Sets ``ovpn_meta`` so
        system.health can report ``ovpn_profile_loaded: true``.
        """
        meta = parse_ovpn_profile(path)
        self.ovpn_meta = meta
        if self.profile is not None:
            self.profile.vpn_profile_path = meta.path
            self.persist_profile()
        self.audit({
            "action": "vpn.profile.link",
            "target": meta.path,
            "status": "ok",
            "detail": {"remote": f"{meta.remote_host}:{meta.remote_port}",
                       "warnings": list(meta.warnings)},
        })
        out = meta.to_dict()
        out["loaded"] = True
        return out

    def _vpn_paths(self) -> Dict[str, Path]:
        d = self._engagement_dir()
        return {
            "pid": d / "raphael-vpn.pid",
            "status": d / "raphael-vpn.status",
            "log": d / "raphael-vpn.log",
        }

    async def connect_vpn(
        self,
        *,
        profile: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        connect_timeout: float = DEFAULT_VPN_CONNECT_TIMEOUT,
    ) -> Dict[str, Any]:
        """Bring up the engagement VPN with openvpn (non-interactive).

        Fail-closed requirements: loaded engagement scope, a valid OVPN
        profile, and non-empty credentials when the profile asks for them.
        Secrets are written to a 0600 tempfile that is removed on exit and
        are never echoed in responses, logs or errors.
        """
        prof = self._require_profile()  # fail closed on engagement scope

        if profile:
            meta = self.link_profile(profile)
        elif self.ovpn_meta is not None:
            meta = self.ovpn_meta.to_dict()
        elif prof.vpn_profile_path:
            meta = self.link_profile(prof.vpn_profile_path)
        else:
            raise NotConfiguredError(
                "no OpenVPN profile: pass profile= to vpn.connect or set "
                "VPN_PROFILE_PATH / call vpn/profile/load first",
                data={"hint": "see scripts/install_vpn_deps.sh and .env"},
            )

        user = username or prof.vpn_username
        pw = password or prof.vpn_password
        needs_creds = meta["requires_auth"] and not meta["auth_from_file"]
        if needs_creds and (not user or not pw):
            raise NotConfiguredError(
                "OpenVPN profile requires auth-user-pass but no username/"
                "password provided (fail closed; secrets are never echoed)",
                data={"hint": "pass credentials via targets.set or vpn.connect"},
            )

        if not shutil.which("openvpn"):
            raise NotConfiguredError(
                "openvpn binary not found; run scripts/install_vpn_deps.sh "
                "(apt-get install openvpn)",
            )
        if not Path("/dev/net/tun").exists():
            raise ComponentError(
                "/dev/net/tun missing; in WSL2 ensure a TUN-capable kernel "
                "(see bridge README: VPN section); in docker use "
                "cap_add [NET_ADMIN] + devices ['/dev/net/tun']",
            )
        if self._vpn.get("connected") and _pid_alive(int(self._vpn.get("pid", 0) or 0)):
            return {**self._vpn_summary(), "note": "already connected"}

        paths = self._vpn_paths()
        paths["pid"].parent.mkdir(parents=True, exist_ok=True)
        for p in paths.values():
            try:
                p.unlink()
            except OSError:
                pass

        # Credential file: 0600, unlinked immediately after openvpn read it.
        auth_file: Optional[Path] = None
        cmd = [
            "openvpn",
            "--config", meta["path"],
            "--daemon",
            "--writepid", str(paths["pid"]),
            "--status", str(paths["status"]), "10",
            "--log-append", str(paths["log"]),
            "--verb", "3",
            "--script-security", "1",   # never run profile scripts
            "--connect-retry-max", "3",
        ]
        if needs_creds:
            fd, name = tempfile.mkstemp(prefix="raphael-vpn-auth-", suffix=".txt")
            auth_file = Path(name)
            with os.fdopen(fd, "w") as f:
                f.write(f"{user}\n{pw}\n")
            os.chmod(auth_file, stat.S_IRUSR | stat.S_IWUSR)
            cmd += ["--auth-user-pass", str(auth_file)]

        started = time.monotonic()
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                # daemon forks quickly; drain the little the parent emits
                await asyncio.wait_for(proc.communicate(), timeout=10.0)
            except asyncio.TimeoutError:
                proc.kill()

            pid = await self._await_pidfile(paths["pid"], timeout=10.0)
            if pid is None:
                raise ComponentError(
                    "openvpn daemonized but no pid written; inspect "
                    f"{paths['log']} (tail clipped)",
                    data={"log_tail": _clip(self._read_text(paths["log"]), 512)},
                )

            ok, tail = await self._await_vpn_init(paths["log"], timeout=connect_timeout)
            if not ok:
                await self._kill_pid(pid)
                raise ComponentError(
                    "openvpn did not reach 'Initialization Sequence Completed'",
                    data={"log_tail": tail},
                )

            latency_ms = int((time.monotonic() - started) * 1000)
            session_id = f"vpn-{uuid.uuid4().hex[:12]}"
            self._vpn = {
                "session_id": session_id,
                "pid": pid,
                "connected": True,
                "profile": meta["path"],
                "exit_node": f"{meta['remote_host']}:{meta['remote_port']}",
                "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                "started_ts": time.time(),
                "mtu": self._parse_mtu(paths["log"]),
            }
            self._vpn["exit_ip"] = (
                await self._canary_ip(None) if _tun_up() else None
            )
            out = self._vpn_summary()
            out["latency_ms"] = latency_ms
            self.audit({
                "action": "vpn.connect",
                "target": self._vpn["exit_node"],
                "session_id": session_id,
                "status": "ok",
                "duration_ms": latency_ms,
                "detail": {"mtu": self._vpn["mtu"]},
            })
            return out
        finally:
            if auth_file is not None:
                try:
                    auth_file.unlink()
                except OSError:
                    pass

    async def _await_pidfile(self, path: Path, timeout: float) -> Optional[int]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if path.is_file():
                try:
                    return int(self._read_text(path).strip() or 0)
                except ValueError:
                    pass
            await asyncio.sleep(0.25)
        return None

    async def _await_vpn_init(self, log: Path, timeout: float) -> Tuple[bool, str]:
        deadline = time.monotonic() + timeout
        needle = "Initialization Sequence Completed"
        while time.monotonic() < deadline:
            text = self._read_text(log)
            if needle in text:
                return True, ""
            if "AUTH_FAILED" in text:
                return False, _clip(text[-512:])
            await asyncio.sleep(0.5)
        return False, _clip(self._read_text(log)[-512:])

    def _read_text(self, p: Path, limit: int = MAX_CLIP) -> str:
        try:
            return p.read_text(errors="replace")[:limit]
        except OSError:
            return ""

    def _parse_mtu(self, log: Path) -> int:
        m = re.search(r"(?:tun-mtu|TUN MTU)\s+(\d{2,5})", self._read_text(log))
        return int(m.group(1)) if m else 1500

    async def _kill_pid(self, pid: int) -> None:
        try:
            os.kill(pid, 15)
            for _ in range(20):
                if not _pid_alive(pid):
                    return
                await asyncio.sleep(0.25)
            os.kill(pid, 9)
        except (ProcessLookupError, PermissionError, OSError):
            pass

    async def disconnect_vpn(self, session_id: Optional[str] = None) -> Dict[str, Any]:
        if session_id and self._vpn.get("session_id") != session_id:
            raise PolicyViolationError(
                f"session_id {session_id!r} does not match active session "
                f"{self._vpn.get('session_id')!r}"
            )
        if not self._vpn.get("connected"):
            return {"connected": False, "note": "no active VPN session"}
        pid = int(self._vpn.get("pid") or 0)
        duration_s = int(time.time() - self._vpn.get("started_ts", time.time()))
        await self._kill_pid(pid)
        for p in self._vpn_paths().values():
            try:
                p.unlink()
            except OSError:
                pass
        summary = {
            "connected": False,
            "session_id": self._vpn.get("session_id"),
            "duration_s": max(0, duration_s),
        }
        self.audit({
            "action": "vpn.disconnect",
            "session_id": self._vpn.get("session_id"),
            "status": "ok",
            "duration_ms": max(0, duration_s) * 1000,
        })
        self._vpn = {}
        return summary

    def _vpn_summary(self) -> Dict[str, Any]:
        if not self._vpn.get("connected"):
            return {"connected": False}
        return {
            "connected": True,
            "session_id": self._vpn["session_id"],
            "pid": self._vpn["pid"],
            "profile": self._vpn["profile"],
            "exit_node": self._vpn["exit_node"],
            "ip": self._vpn.get("exit_ip"),
            "mtu": self._vpn.get("mtu", 1500),
            "started_at": self._vpn.get("started_at"),
            "tun_up": _tun_up(),
        }

    async def vpn_status(self) -> Dict[str, Any]:
        out = self._vpn_summary()
        if not out.get("connected"):
            # stale pid from a previous run?
            pid_path = self._vpn_paths()["pid"]
            if pid_path.is_file():
                try:
                    pid = int(self._read_text(pid_path).strip())
                except ValueError:
                    pid = 0
                if pid and _pid_alive(pid):
                    out["connected"] = True
                    out["pid"] = pid
                    out["note"] = "recovered from pid file"
                    out["tun_up"] = _tun_up()
        out["openvpn_installed"] = bool(shutil.which("openvpn"))
        out["tun_device_present"] = Path("/dev/net/tun").exists()
        return out

    # ------------------------------------------------------------------
    # Tool routing — REUSES kali.run, never a parallel tool catalog
    # ------------------------------------------------------------------

    async def run_tool(
        self,
        tool: str,
        args: Sequence[Any],
        target: str,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Scoped, sanitized, audited tool run routed to kali-tools.

        Kali is the executor (single tool catalog); the bridge only enforces
        scope + rate and routes. When Kali is unreachable an opt-in local
        allowlisted fallback (BRIDGE_LOCAL_TOOLS=1) may run directly on the
        host, shell-free.
        """
        prof = self._require_profile()  # fail closed
        self._require_in_scope(str(target), action="kali.run")

        if not TOOL_NAME_RE.match(str(tool or "")):
            raise PolicyViolationError(f"invalid tool name {tool!r}")
        argv = [str(a) for a in (args or [])]
        for a in argv:
            if "\x00" in a:
                raise PolicyViolationError("null byte in args rejected")
            if len(a) > 2048:
                raise PolicyViolationError("arg too long (max 2048)")
        self._consume_rate(1.0)

        timeout = min(float(timeout or DEFAULT_TOOL_TIMEOUT), 3600.0)
        started = time.monotonic()

        kali_url = self._env("KALI_TOOLS_URL")
        out: Dict[str, Any] = {}
        if kali_url:
            try:
                out = await self._run_via_kali(kali_url, tool, argv, target, timeout)
            except (httpx.HTTPError, OSError) as e:
                self._kali_probe = (False, time.monotonic())
                if self._env("BRIDGE_LOCAL_TOOLS") not in ("1", "true", "yes"):
                    raise ComponentError(
                        f"kali-tools unreachable at {kali_url}: "
                        f"{type(e).__name__}: {_clip(str(e), 256)}",
                        data={"hint": "start kali container or set "
                                     "BRIDGE_LOCAL_TOOLS=1 for allowlisted "
                                     "local fallback"},
                    ) from e
                out = await self._run_local_allowlisted(tool, argv, timeout)
        elif self._env("BRIDGE_LOCAL_TOOLS") in ("1", "true", "yes"):
            out = await self._run_local_allowlisted(tool, argv, timeout)
        else:
            raise NotConfiguredError(
                "KALI_TOOLS_URL not configured; set it in .env (e.g. "
                "http://kali-tools:3800) or opt into local allowlist mode"
            )

        out.setdefault("tool", tool)
        out["target"] = str(target)
        out["routed"] = out.get("routed", "kali")
        out["engagement"] = prof.engagement_id
        out["duration_ms"] = out.get("duration_ms") or int(
            (time.monotonic() - started) * 1000
        )
        out["bytes"] = len(str(out.get("stdout", ""))) + len(str(out.get("stderr", "")))
        self.audit({
            "action": "kali.run",
            "target": str(target),
            "status": "ok" if out.get("exit_code") == 0 else "failed",
            "bytes": out["bytes"],
            "duration_ms": out["duration_ms"],
            "detail": {"tool": tool, "routed": out["routed"]},
        })
        return out

    async def _run_via_kali(
        self, base_url: str, tool: str, argv: List[str], target: str, timeout: float
    ) -> Dict[str, Any]:
        if self._http is None:
            self._http = httpx.AsyncClient(trust_env=False)
        r = await self._http.post(
            f"{base_url.rstrip('/')}/run",
            json={"tool": tool, "args": argv, "target": str(target)},
            timeout=timeout,
        )
        self._kali_probe = (True, time.monotonic())
        r.raise_for_status()
        body = r.json()
        return {
            "stdout": _clip(str(body.get("stdout", body.get("output", "")))),
            "stderr": _clip(str(body.get("stderr", ""))),
            "exit_code": int(body.get("exit_code", 0)),
            "routed": "kali",
            "fallback_used": False,
            "raw": body if not isinstance(body, dict) else None,
        }

    async def _run_local_allowlisted(
        self, tool: str, argv: List[str], timeout: float
    ) -> Dict[str, Any]:
        allowlist = {
            t.strip()
            for t in self._env(
                "BRIDGE_LOCAL_TOOL_ALLOWLIST", ",".join(DEFAULT_LOCAL_TOOL_ALLOWLIST)
            ).split(",")
            if t.strip()
        }
        if tool not in allowlist:
            raise PolicyViolationError(
                f"tool {tool!r} not in local allowlist {sorted(allowlist)}"
            )
        if not shutil.which(tool):
            raise NotConfiguredError(f"{tool} not installed on this host")
        try:
            proc = await asyncio.create_subprocess_exec(
                tool, *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            self.audit({"action": "kali.run", "target": argv[-1] if argv else tool,
                        "status": "timeout"})
            return {
                "stdout": "", "stderr": f"timed out after {timeout}s",
                "exit_code": -1, "timed_out": True,
                "routed": "local", "fallback_used": True,
                "duration_ms": int(timeout * 1000),
            }
        return {
            "stdout": _clip(stdout.decode(errors="replace")),
            "stderr": _clip(stderr.decode(errors="replace")),
            "exit_code": proc.returncode or 0,
            "routed": "local",
            "fallback_used": True,
            "duration_ms": 0,
        }

    async def close(self) -> None:
        """Release subprocess handles / HTTP clients (idempotent)."""
        if self._ssh_proc is not None and self._ssh_proc.returncode is None:
            try:
                self._ssh_proc.kill()
            except ProcessLookupError:
                pass
            self._ssh_proc = None
        if self._http is not None:
            await self._http.aclose()
            self._http = None
