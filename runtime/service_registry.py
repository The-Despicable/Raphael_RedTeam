"""runtime.service_registry — host services, ports, commands, dependencies.

Canonical port schema (identical to the Docker compose; localhost replaces
raphael-net DNS):

  raphael-api    3900   c2-server      3501   cloak-service  3401
  brain          3700   recon-pipeline 3503   mhddos-service 3301
  cai-service    3201   phishing       3502   sword          3600
  kali-tools     3800
  tor            9050/9052 (socks/dns)  sliver-server 31337/31334
  neo4j          7474/7687

configs/services.json is the single source of truth. It is loaded over the
built-in defaults below; any service it names wins on every field.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from runtime.env import REPO_ROOT, RAPHAEL_PY

REGISTRY_PATH = REPO_ROOT / "configs" / "services.json"


@dataclass
class ServiceSpec:
    name: str
    command: list[str]                # argv; run via subprocess (no shell)
    port: Optional[int] = None        # HTTP port if uvicorn service
    host: str = "127.0.0.1"
    health_path: str = "/health"
    health_kind: str = "http"         # http | tcp | none
    depends_on: list[str] = field(default_factory=list)
    optional: bool = False            # skip missing without failing the stack
    env: dict[str, str] = field(default_factory=dict)
    uid_guard: bool = False           # requires file caps / elevated privs
    description: str = ""
    cwd: str = "."                    # relative to REPO_ROOT
    secondary_port: Optional[int] = None


def _uv(module: str, port: int) -> list[str]:
    return ["python3", "-m", "uvicorn", module, "--host", "127.0.0.1", "--port", str(port)]


DEFAULT_SERVICES: list[ServiceSpec] = [
    ServiceSpec(
        name="raphael-api", port=3900, health_path="/health",
        command=["python3","-m","uvicorn","orchestrator.api.main:app","--app-dir","src","--host","127.0.0.1","--port","3900"],
        description="Integration API (GLM orchestrator entrypoint)"),
    ServiceSpec(
        name="brain", port=3700, health_path="/health",
        command=["python3","-m","uvicorn","brain.main:app","--host","127.0.0.1","--port","3700"],
        description="Autonomous brain (FastAPI, passes smoke tests)"),
    ServiceSpec(
        name="c2-server", port=3501, health_path="/health",
        command=["python3","-m","uvicorn","main:app","--app-dir","src/c2-server","--host","127.0.0.1","--port","3501"],
        description="Command-and-control surface"),
    ServiceSpec(
        name="recon-pipeline", port=3503, health_path="/health",
        command=["python3","-m","uvicorn","main:app","--app-dir","src/recon-pipeline","--host","127.0.0.1","--port","3503"],
        description="Recon pipeline"),
    ServiceSpec(
        name="cloak-service", port=3401, health_path="/health",
        command=["python3","-m","uvicorn","main:app","--app-dir","src/cloak-service","--host","127.0.0.1","--port","3401"],
        description="Cloak / identity rotation"),
    ServiceSpec(
        name="cai-service", port=3201, health_path="/health",
        command=["python3","-m","uvicorn","main:app","--app-dir","src/cai-service","--host","127.0.0.1","--port","3201"],
        description="CAI service (likely minimal)"),
    ServiceSpec(
        name="mhddos-service", port=3301, health_path="/health",
        command=["python3","-m","uvicorn","main:app","--app-dir","src/mhddos-service","--host","127.0.0.1","--port","3301"],
        description="Network stress service", uid_guard=True),
    ServiceSpec(
        name="phishing", port=3502, health_path="/health",
        command=["python3","-m","uvicorn","main:app","--app-dir","src/phishing","--host","127.0.0.1","--port","3502"],
        description="Phishing infrastructure service"),
    ServiceSpec(
        name="sword", port=3600, health_path="/health",
        command=["python3","-m","uvicorn","sword.api:app","--app-dir","src","--host","127.0.0.1","--port","3600"],
        description="Sword exploitation service", uid_guard=True),
    ServiceSpec(
        name="kali-tools", port=3800, health_path="/health",
        command=["python3","-m","uvicorn","server:app","--app-dir","src/kali-tools","--host","127.0.0.1","--port","3800"],
        env={"KALI_TOOLS_URL": "http://127.0.0.1:3800"},
        description="Host tools API executing allowlisted tool names directly"),
    # ---- platform services (host binaries, not uvicorn) ----
    ServiceSpec(
        name="tor", port=9050, health_kind="tcp",
        command=["tor", "-f", str(REPO_ROOT / "tor" / "torrc")],
        optional=True,
        description="Tor SOCKS 9050 / DNS 9052 (host package)"),
    ServiceSpec(
        name="sliver-server", port=31337, health_kind="tcp",
        command=[str(REPO_ROOT / "sliver" / "sliver-server"), "daemon"],
        optional=True,
        description="Sliver server gRPC 31337 / HTTPS 31334"),
    ServiceSpec(
        name="neo4j", port=7687, health_kind="tcp",
        command=[str(REPO_ROOT / "data" / "neo4j" / "bin" / "neo4j"), "console"],
        optional=True,
        description="Neo4j community (HTTP 7474 / Bolt 7687)"),
]


def load_registry(path: Path = REGISTRY_PATH) -> list[ServiceSpec]:
    """Built-in defaults, overridden by the JSON registry if present.

    JSON shape: {"services": [{"name": ..., "command": [...], "port": ..., ...}]}
    Unknown names are appended (operator extensions); known names merge.
    """
    services = {s.name: s for s in DEFAULT_SERVICES}
    if path.is_file():
        data = json.loads(path.read_text())
        for entry in data.get("services", []):
            name = entry["name"]
            base = services.get(name)
            raw_command = entry.get("command", base.command if base else [])
            spec = ServiceSpec(
                name=name,
                # Expand ${RAPHAEL_PY}, ${TOR_BIN}, ${TORRC_PATH} ... at load time.
                command=[os.path.expandvars(str(a)).replace("${RAPHAEL_PY}", RAPHAEL_PY)
                         for a in raw_command],
                port=entry.get("port", base.port if base else None),
                host=entry.get("host", base.host if base else "127.0.0.1"),
                health_path=entry.get("health_path", base.health_path if base else "/health"),
                health_kind=entry.get("health_kind", base.health_kind if base else "http"),
                depends_on=entry.get("depends_on", base.depends_on if base else []),
                optional=entry.get("optional", base.optional if base else False),
                env=entry.get("env", base.env if base else {}),
                uid_guard=entry.get("uid_guard", base.uid_guard if base else False),
                description=entry.get("description", base.description if base else ""),
                cwd=entry.get("cwd", base.cwd if base else "."),
                secondary_port=entry.get("secondary_port", base.secondary_port if base else None),
            )
            services[name] = spec
    return list(services.values())


def order_by_dependencies(services: list[ServiceSpec]) -> list[ServiceSpec]:
    """Topological sort on depends_on. Raises on cycles."""
    by_name = {s.name: s for s in services}
    visited: dict[str, int] = {}
    out: list[ServiceSpec] = []

    def visit(s: ServiceSpec) -> None:
        state = visited.get(s.name, 0)
        if state == 2:
            return
        if state == 1:
            raise ValueError(f"dependency cycle involving {s.name!r}")
        visited[s.name] = 1
        for dep in s.depends_on:
            if dep in by_name:
                visit(by_name[dep])
        visited[s.name] = 2
        out.append(s)

    for s in services:
        visit(s)
    return out


def ports_in_use_report() -> dict[int, str]:
    """Map port -> service name for collision detection."""
    return {s.port: s.name for s in load_registry() if s.port}


SHADOW_BASE = 3980


def shadow_ports(services: list[ServiceSpec], base: int = SHADOW_BASE) -> dict[str, int]:
    """Deterministic shadow-port map: 3980, 3981, ... in alphabetical order.

    Shared by runtime.launcher and scripts/status.py so the supervisor and the
    health sweep can never disagree about which port a service is on.
    """
    core = sorted(
        s.name for s in services
        if s.port and not s.optional and s.health_kind == "http"
    )
    return {name: base + i for i, name in enumerate(core)}
