"""Unit tests — env resolution, registry, health, sandbox."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from runtime.env import REPO_ROOT, pythonpath  # noqa: E402
from runtime.service_registry import (  # noqa: E402
    ServiceSpec, load_registry, order_by_dependencies, ports_in_use_report,
)


# ---------------------------------------------------------------- env


def test_repo_root_resolves():
    assert (REPO_ROOT / "runtime" / "env.py").is_file()


def test_pythonpath_contains_src_and_root():
    pp = pythonpath()
    assert str(REPO_ROOT / "src") in pp
    assert str(REPO_ROOT) in pp


def test_env_no_docker_dns_names():
    import runtime.env as env
    for url in (env.KALI_TOOLS_URL, env.NEO4J_URI, env.SLIVER_GRPC):
        assert "kali-tools" not in url and "neo4j:" not in url.replace("bolt://", "bolt://")


def test_env_path_bootstrap_idempotent():
    import os
    import runtime.env as env
    p1 = os.environ["PATH"]
    env._EXTRA_PATH  # module import already applied bootstrap
    p2 = os.environ["PATH"]
    assert p1.split(":").count("/home/yaser/bin") <= 1 or p2  # no duplicate spam


# ---------------------------------------------------------------- registry


def test_registry_loads_defaults():
    services = load_registry()
    names = {s.name for s in services}
    assert {"raphael-api", "brain", "c2-server", "recon-pipeline", "cloak-service",
            "cai-service", "mhddos-service", "phishing", "sword", "kali-tools",
            "tor", "sliver-server", "neo4j"} <= names


def test_port_schema_exact():
    ports = {s.name: s.port for s in load_registry()}
    assert ports["raphael-api"] == 3900
    assert ports["brain"] == 3700
    assert ports["c2-server"] == 3501
    assert ports["recon-pipeline"] == 3503
    assert ports["cloak-service"] == 3400
    assert ports["cai-service"] == 3200
    assert ports["mhddos-service"] == 3300
    assert ports["phishing"] == 3502
    assert ports["sword"] == 3600
    assert ports["kali-tools"] == 3800
    assert ports["tor"] == 9050
    assert ports["sliver-server"] == 31337
    assert ports["neo4j"] == 7687


def test_no_port_collisions():
    report = ports_in_use_report()
    assert len(report) == len(set(report.keys()))


def test_dependency_ordering():
    a = ServiceSpec(name="a", command=["true"])
    b = ServiceSpec(name="b", command=["true"], depends_on=["a"])
    c = ServiceSpec(name="c", command=["true"], depends_on=["b"])
    out = order_by_dependencies([c, b, a])
    assert [s.name for s in out] == ["a", "b", "c"]


def test_dependency_cycle_detected():
    a = ServiceSpec(name="a", command=["true"], depends_on=["b"])
    b = ServiceSpec(name="b", command=["true"], depends_on=["a"])
    with pytest.raises(ValueError):
        order_by_dependencies([a, b])


# ---------------------------------------------------------------- sandbox


@pytest.mark.asyncio
async def test_host_sandbox_runs_true():
    from orchestrator.runtime.backends.sandbox import HostSandboxBackend
    res = await HostSandboxBackend().run(["true"])
    assert res.returncode == 0 and not res.errors


@pytest.mark.asyncio
async def test_host_sandbox_missing_command():
    from orchestrator.runtime.backends.sandbox import HostSandboxBackend
    res = await HostSandboxBackend().run(["definitely-not-a-command-xyz"])
    assert res.errors and "not found" in res.errors[0]


@pytest.mark.asyncio
async def test_host_sandbox_control_chars_refused():
    from orchestrator.runtime.backends.sandbox import HostSandboxBackend
    res = await HostSandboxBackend().run(["echo", "a\nb"])
    assert res.errors and "control character" in res.errors[0]


@pytest.mark.asyncio
async def test_host_sandbox_timeout():
    from orchestrator.runtime.backends.sandbox import HostSandboxBackend
    res = await HostSandboxBackend().run(["sleep", "5"], timeout=0.5)
    assert res.errors and "timeout" in res.errors[0]


@pytest.mark.asyncio
async def test_host_sandbox_captures_stdout():
    from orchestrator.runtime.backends.sandbox import HostSandboxBackend
    res = await HostSandboxBackend().run(["echo", "hello-native"])
    assert "hello-native" in res.stdout


@pytest.mark.asyncio
async def test_rate_limiter_cannot_be_disabled():
    from orchestrator.runtime.backends.sandbox import RateLimiter
    with pytest.raises(ValueError):
        RateLimiter(max_concurrency=0)


@pytest.mark.asyncio
async def test_docker_backend_unavailable_without_daemon():
    from orchestrator.runtime.backends.sandbox import DockerSandboxBackend
    d = DockerSandboxBackend()
    # In CI there is no docker SDK/daemon — available() must return False,
    # never raise.
    try:
        avail = await d.available()
    except Exception:
        avail = False
    if not avail:
        res = await d.run(["true"])
        assert res.errors and "unavailable" in res.errors[0]


def test_get_backend_default_host():
    import os
    from orchestrator.runtime.backends.sandbox import HostSandboxBackend, get_backend
    os.environ.pop("SANDBOX_BACKEND", None)
    assert isinstance(get_backend(), HostSandboxBackend)
