#!/usr/bin/env python3
"""Autonomous Brain smoke test.

Two modes:
  1. `python smoke_test.py`     -> in-process FastAPI TestClient round-trip.
  2. `python smoke_test.py --url http://localhost:3700` -> live HTTP smoke test.

Exercises:
  - GET /health returns 200 {status:"ok"}
  - POST /notes round-trip
  - POST /task returns task_id; GET tracks state
  - POST /tools/execute executes a tool (via stub fallback)
  - SQLite DB created under BRAIN_DB

Exits non-zero on any failure.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Optional


def _green(s: str) -> str:
    return f"\033[32m{s}\033[0m"


def _red(s: str) -> str:
    return f"\033[31m{s}\033[0m"


def _check(label: str, ok: bool, detail: str = "") -> bool:
    mark = _green("PASS") if ok else _red("FAIL")
    print(f"[{mark}] {label}" + (f" -- {detail}" if detail else ""))
    return ok


async def in_process_smoke() -> int:
    """Spin up the app via TestClient and exercise the endpoints."""
    print("=" * 60)
    print("In-process smoke test (FastAPI TestClient)")
    print("=" * 60)

    # Use a temp DB so we don't pollute /data.
    tmpdir = tempfile.mkdtemp(prefix="brain-smoke-")
    db_path = str(Path(tmpdir) / "brain.db")
    os.environ["BRAIN_DB"] = db_path
    os.environ.setdefault("LOG_LEVEL", "WARNING")
    os.environ.setdefault("KALI_TOOLS_URL", "http://kali-tools:3800")

    # Reset cached settings (in case module was imported before).
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from brain.config import get_settings  # noqa: WPS433

    get_settings.cache_clear()

    from brain.db import init_db, close_db  # noqa: WPS433
    from brain.main import app  # noqa: WPS433
    from brain.coordinator import _new_id  # noqa: WPS433

    from fastapi.testclient import TestClient

    results: list[bool] = []

    with TestClient(app) as client:
        # --- /health ------------------------------------------------------
        r = client.get("/health")
        results.append(_check("GET /health returns 200", r.status_code == 200, f"got {r.status_code}"))
        if r.status_code == 200:
            data = r.json()
            results.append(_check("status == ok", data.get("status") == "ok", json.dumps(data)))
            results.append(_check("brain_db path populated", bool(data.get("brain_db"))))
            results.append(_check("subsystems snapshot present", isinstance(data.get("subsystems"), dict)))

        # --- /capabilities ------------------------------------------------
        r = client.get("/capabilities")
        results.append(_check("GET /capabilities returns 200", r.status_code == 200))
        if r.status_code == 200:
            data = r.json()
            results.append(_check("capabilities list non-empty", len(data.get("capabilities", [])) > 0))

        # --- /version -----------------------------------------------------
        r = client.get("/version")
        results.append(_check("GET /version returns 200", r.status_code == 200))

        # --- /notes round-trip --------------------------------------------
        key = f"smoke-{uuid.uuid4().hex[:8]}"
        r = client.post("/notes", json={"key": key, "value": {"hello": "world"}, "tags": ["smoke"]})
        results.append(_check("POST /notes returns 200", r.status_code == 200, str(r.status_code)))
        r = client.get(f"/notes/{key}")
        results.append(_check("GET /notes/{key} returns 200", r.status_code == 200))
        if r.status_code == 200:
            note = r.json()
            results.append(_check("note value preserved", note.get("value", {}).get("hello") == "world"))

        # --- /task create + track -----------------------------------------
        r = client.post("/task", json={"target": "127.0.0.1", "mode": "recon", "goal": "smoke test"})
        results.append(_check("POST /task returns 202", r.status_code == 202, str(r.status_code)))
        if r.status_code == 202:
            task_id = r.json()["task_id"]
            # Give the coordinator a moment to start.
            time.sleep(0.5)
            r = client.get(f"/task/{task_id}")
            results.append(_check("GET /task/{id} returns 200", r.status_code == 200))
            if r.status_code == 200:
                view = r.json()
                results.append(_check("task target preserved", view.get("target") == "127.0.0.1"))
                # Wait a bit for completion (default plan is fast with stub).
                for _ in range(20):
                    r = client.get(f"/task/{task_id}")
                    if r.status_code == 200:
                        st = r.json().get("state")
                        if st in {"completed", "failed", "aborted"}:
                            break
                    time.sleep(0.25)
                final = client.get(f"/task/{task_id}").json()
                results.append(
                    _check(
                        "task reached terminal state",
                        final.get("state") in {"completed", "failed", "aborted", "running", "paused", "awaiting_approval"},
                        f"state={final.get('state')}",
                    )
                )
                # Regression: plan steps must surface the parsed tool args.
                if final.get("plan"):
                    first_step = final["plan"][0]
                    results.append(
                        _check(
                            "plan steps expose parsed args",
                            any(isinstance(p.get("args"), list) for p in final["plan"]),
                            f"plan[0]: step_id={first_step.get('step_id')} tool={first_step.get('tool')} args={first_step.get('args')}",
                        )
                    )
                # Regression: control actions on a finished task must be rejected.
                if final.get("state") in {"completed", "failed", "aborted"}:
                    r = client.post(f"/task/{task_id}/control", json={"action": "pause"})
                    results.append(
                        _check(
                            "control on terminal task rejected (409)",
                            r.status_code == 409,
                            f"got {r.status_code}",
                        )
                    )

        # --- /tools/execute (stub fallback) -------------------------------
        r = client.post("/tools/execute", json={"tool": "nmap", "args": ["-sV"], "target": "127.0.0.1"})
        results.append(_check("POST /tools/execute returns 200", r.status_code == 200, str(r.status_code)))
        if r.status_code == 200:
            data = r.json()
            results.append(_check("tool result has exit_code", "exit_code" in data))
            # Regression: broker gate decision must reach the API response.
            results.append(
                _check(
                    "tools response includes broker_decision",
                    isinstance(data.get("broker_decision"), dict),
                    f"keys={sorted(data.keys())}",
                )
            )

        # --- /evidence/ingest ---------------------------------------------
        r = client.post(
            "/evidence/ingest",
            json={
                "nodes": [{"id": "host-1", "kind": "host", "attributes": {"ip": "127.0.0.1"}}],
                "edges": [{"src": "host-1", "dst": "port-22", "relation": "has_port"}],
            },
        )
        results.append(_check("POST /evidence/ingest returns 200", r.status_code == 200))
        if r.status_code == 200:
            first = r.json()
            results.append(_check("first ingest adds 1 node", first.get("nodes_added") == 1, json.dumps(first)))
            # Regression: re-ingesting the same node_id must be deduplicated.
            r2 = client.post(
                "/evidence/ingest",
                json={"nodes": [{"id": "host-1", "kind": "host", "attributes": {"ip": "127.0.0.1"}}]},
            )
            if r2.status_code == 200:
                second = r2.json()
                results.append(
                    _check(
                        "re-ingest same node_id is deduplicated",
                        second.get("nodes_added") == 0,
                        json.dumps(second),
                    )
                )
        r = client.get("/evidence")
        results.append(_check("GET /evidence returns 200", r.status_code == 200))

        # --- /findings ----------------------------------------------------
        r = client.get("/findings")
        results.append(_check("GET /findings returns 200", r.status_code == 200))

        # --- /hypotheses --------------------------------------------------
        r = client.post("/hypotheses", json={"statement": "target is vulnerable", "confidence": 0.4})
        results.append(_check("POST /hypotheses returns 200", r.status_code == 200))

        # --- /contradictions/check ----------------------------------------
        r = client.post(
            "/contradictions/check",
            json={"observations": [{"port": "22"}, {"port": "80"}, {"port": "22"}]},
        )
        results.append(_check("POST /contradictions/check returns 200", r.status_code == 200))

        # --- /strategy/build ---------------------------------------------
        r = client.post("/strategy/build", json={"target": "127.0.0.1", "profile": {}, "findings": []})
        results.append(_check("POST /strategy/build returns 200", r.status_code == 200))

        # --- /checkpoint --------------------------------------------------
        r = client.post("/checkpoint", json={"label": "smoke", "note": "after smoke test"})
        results.append(_check("POST /checkpoint returns 201", r.status_code == 201, str(r.status_code)))

        # --- /webhook/notify ---------------------------------------------
        r = client.post("/webhook/notify", json={"event": "smoke.done", "payload": {}})
        results.append(_check("POST /webhook/notify returns 200", r.status_code == 200))

    # --- DB file exists ----------------------------------------------------
    db_exists = Path(db_path).exists()
    results.append(_check("SQLite DB file exists", db_exists, db_path))

    print()
    passed = sum(results)
    total = len(results)
    print(f"Result: {passed}/{total} checks passed")
    return 0 if passed == total else 1


async def live_smoke(base_url: str) -> int:
    """Run against a live service via httpx."""
    print("=" * 60)
    print(f"Live smoke test against {base_url}")
    print("=" * 60)
    import httpx

    results: list[bool] = []
    async with httpx.AsyncClient(base_url=base_url, timeout=10.0) as client:
        r = await client.get("/health")
        results.append(_check("GET /health", r.status_code == 200, str(r.status_code)))
        if r.status_code == 200:
            results.append(_check("status == ok", r.json().get("status") == "ok"))

        key = f"smoke-{uuid.uuid4().hex[:8]}"
        r = await client.post("/notes", json={"key": key, "value": "x"})
        results.append(_check("POST /notes", r.status_code == 200, str(r.status_code)))
        r = await client.get(f"/notes/{key}")
        results.append(_check("GET /notes/{key}", r.status_code == 200))

        r = await client.post("/task", json={"target": "127.0.0.1", "mode": "recon"})
        results.append(_check("POST /task", r.status_code == 202, str(r.status_code)))
        if r.status_code == 202:
            tid = r.json()["task_id"]
            r = await client.get(f"/task/{tid}")
            results.append(_check("GET /task/{id}", r.status_code == 200))

        r = await client.post("/tools/execute", json={"tool": "nmap", "args": ["-sV"]})
        results.append(_check("POST /tools/execute", r.status_code == 200, str(r.status_code)))

    passed = sum(results)
    total = len(results)
    print(f"\nResult: {passed}/{total} checks passed")
    return 0 if passed == total else 1


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--url", help="live service base URL (default: in-process TestClient)")
    args = p.parse_args()
    if args.url:
        return asyncio.run(live_smoke(args.url.rstrip("/")))
    return asyncio.run(in_process_smoke())


if __name__ == "__main__":
    sys.exit(main())
