"""runtime.health — health polling with dependency ordering support.

HTTP probe expects the project contract: 200 + {"status": "ok"}.
TCP probe (tor socks, neo4j bolt, sliver grpc) just checks connectability.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass

import httpx

from runtime.service_registry import ServiceSpec


@dataclass
class HealthResult:
    name: str
    ok: bool
    detail: str

    def __str__(self) -> str:
        return f"{'OK  ' if self.ok else 'DOWN'} {self.name}: {self.detail}"


async def probe_http(url: str, timeout: float = 3.0) -> HealthResult:
    try:
        r = await httpx.AsyncClient(timeout=timeout).get(url)
        body = r.text[:200]
        if r.status_code == 200 and '"status"' in body and "ok" in body:
            return HealthResult("http", True, body)
        return HealthResult("http", False, f"HTTP {r.status_code}: {body}")
    except Exception as e:
        return HealthResult("http", False, repr(e))


async def probe_tcp(host: str, port: int, timeout: float = 3.0) -> HealthResult:
    try:
        fut = asyncio.open_connection(host, port)
        r, w = await asyncio.wait_for(fut, timeout=timeout)
        w.close()
        try:
            await w.wait_closed()
        except Exception:
            pass
        return HealthResult("tcp", True, f"connect {host}:{port}")
    except Exception as e:
        return HealthResult("tcp", False, repr(e))


async def probe_service(spec: ServiceSpec) -> HealthResult:
    if spec.health_kind == "none" or not spec.port:
        return HealthResult(spec.name, True, "no probe defined")
    if spec.health_kind == "tcp":
        res = await probe_tcp(spec.host, spec.port)
    else:
        res = await probe_http(f"http://127.0.0.1:{spec.port}{spec.health_path}")
    return HealthResult(spec.name, res.ok, res.detail)


async def wait_for_service(spec: ServiceSpec, attempts: int = 30, delay: float = 1.0) -> HealthResult:
    """Poll until healthy or attempts exhausted. Used by the launcher for
    dependency ordering (compose depends_on equivalent)."""
    last: HealthResult | None = None
    for _ in range(attempts):
        last = await probe_service(spec)
        if last.ok:
            return last
        await asyncio.sleep(delay)
    return last or HealthResult(spec.name, False, "no attempts made")


async def sweep(services: list[ServiceSpec]) -> list[HealthResult]:
    results = await asyncio.gather(*(probe_service(s) for s in services))
    return list(results)
