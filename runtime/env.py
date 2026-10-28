"""runtime.env — centralized environment resolution for native mode.

Single source of truth for paths and URLs. No Docker-only envs. Loads .env if
present (never committed; no secrets in source), applies native PATH bootstrap,
and exposes everything as module constants.

Replace every `sys.path.insert(0, "/raphael")` / `"/app"` with:
    from runtime.env import REPO_ROOT, ORCHESTRATOR_PATH
    sys.path.insert(0, str(ORCHESTRATOR_PATH))
"""
from __future__ import annotations

import os
from pathlib import Path

# Repo root = two levels above this file (runtime/env.py -> <repo>/runtime/env.py)
REPO_ROOT: Path = Path(__file__).resolve().parents[1]


def _load_dotenv(path: Path) -> None:
    """Minimal .env loader. Existing environment wins (no clobber)."""
    if not path.is_file():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        k, v = k.strip(), v.strip().strip('"').strip("'")
        if k and k not in os.environ:
            os.environ[k] = v


_load_dotenv(REPO_ROOT / ".env")

# ---------------------------------------------------------------- paths
ORCHESTRATOR_PATH: Path = Path(os.environ.get("ORCHESTRATOR_PATH", REPO_ROOT / "src" / "orchestrator"))
SRC_PATH: Path = Path(os.environ.get("SRC_PATH", REPO_ROOT / "src"))
SQLITE_DATA_DIR: Path = Path(os.environ.get("SQLITE_DATA_DIR", REPO_ROOT / "data"))
BRAIN_DB: Path = Path(os.environ.get("BRAIN_DB", SQLITE_DATA_DIR / "brain" / "brain.db"))
RUNTIME_DIR: Path = REPO_ROOT / "runtime"
PID_DIR: Path = RUNTIME_DIR / "pid"
LOG_DIR: Path = RUNTIME_DIR / "logs"
SLIVER_DIR: Path = Path(os.environ.get("SLIVER_DIR", REPO_ROOT / "sliver"))
TOR_DIR: Path = Path(os.environ.get("TOR_DIR", REPO_ROOT / "tor"))
VPN_DIR: Path = Path(os.environ.get("VPN_DIR", REPO_ROOT / "vpn"))
BRIDGE_DIR: Path = Path(os.environ.get("BRIDGE_DIR", REPO_ROOT / "bridge"))

# ---------------------------------------------------------------- service URLs (localhost-first, no Docker DNS)
KALI_TOOLS_URL: str = os.environ.get("KALI_TOOLS_URL", "http://127.0.0.1:3800")
TOR_SOCKS: str = os.environ.get("TOR_SOCKS", "127.0.0.1:9050")
TOR_CONTROL: str = os.environ.get("TOR_CONTROL", "127.0.0.1:9051")
SLIVER_GRPC: str = os.environ.get("SLIVER_GRPC", "127.0.0.1:31337")
SLIVER_HTTPS: str = os.environ.get("SLIVER_HTTPS", "127.0.0.1:31334")
SLIVER_OPERATOR_CONFIG: Path = Path(
    os.environ.get("SLIVER_OPERATOR_CONFIG", SLIVER_DIR / "operator.cfg")
)
NEO4J_URI: str = os.environ.get("NEO4J_URI", "bolt://127.0.0.1:7687")
EGRESS_STRATEGY: str = os.environ.get("EGRESS_STRATEGY", "tor")  # tor | vpn | direct

# ---------------------------------------------------------------- mode
RUNMODE: str = os.environ.get("RUNMODE", "native")  # native | docker
SANDBOX_BACKEND: str = os.environ.get("SANDBOX_BACKEND", "host")  # host | docker

# ---------------------------------------------------------------- PATH bootstrap (WSL host tool locations)
_EXTRA_PATH = [
    str(REPO_ROOT / "bin"),
    "/home/yaser/bin",
    "/home/yaser/.local/bin",
    "/home/yaser/go/bin",
]
_MISSING = [p for p in _EXTRA_PATH if p not in os.environ.get("PATH", "")]
if _MISSING:
    os.environ["PATH"] = ":".join(_MISSING) + ":" + os.environ.get("PATH", "")


def pythonpath() -> str:
    """Canonical PYTHONPATH for native mode."""
    return f"{SRC_PATH}:{REPO_ROOT}"


def ensure_dirs() -> None:
    for d in (SQLITE_DATA_DIR, PID_DIR, LOG_DIR, SLIVER_DIR, TOR_DIR, VPN_DIR,
              SQLITE_DATA_DIR / "brain", SQLITE_DATA_DIR / "neo4j"):
        d.mkdir(parents=True, exist_ok=True)


def as_export() -> dict[str, str]:
    """Environment snapshot for subprocess injection (no secrets ever echoed)."""
    return {
        "RAPHAEL_REPO_ROOT": str(REPO_ROOT),
        "ORCHESTRATOR_PATH": str(ORCHESTRATOR_PATH),
        "PYTHONPATH": pythonpath(),
        "KALI_TOOLS_URL": KALI_TOOLS_URL,
        "TOR_SOCKS": TOR_SOCKS,
        "TOR_CONTROL": TOR_CONTROL,
        "SLIVER_GRPC": SLIVER_GRPC,
        "SLIVER_HTTPS": SLIVER_HTTPS,
        "SLIVER_OPERATOR_CONFIG": str(SLIVER_OPERATOR_CONFIG),
        "NEO4J_URI": NEO4J_URI,
        "EGRESS_STRATEGY": EGRESS_STRATEGY,
        "RUNMODE": RUNMODE,
        "SANDBOX_BACKEND": SANDBOX_BACKEND,
    }
