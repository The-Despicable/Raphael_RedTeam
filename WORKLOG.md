---
Task ID: 1
Agent: main (Z.ai)
Task: Implement the Autonomous Brain microservice for Raphael 2.0.

Work Log:
- Created /home/z/my-project/brain/ with 13 files matching the spec layout
- config.py: pydantic v2 Settings, env-driven, safe defaults, health snapshot
- schemas.py: all Pydantic models at API boundary (15+ request/response types)
- db.py: aiosqlite wrapper, idempotent schema (11 tables incl. audit_log),
  in-flight task recovery on startup
- llm_service.py: async OpenAI-compatible client, deterministic fallback
  string when no key, total_tokens_used tracking, reuses orchestrator.brain
  .reasoning_chain / strategy.build_strategy when available
- system_service.py: Tor/Sliver/Neo4j/Kali health probes, all async, all
  degrade gracefully when unreachable
- tools_service.py: KaliToolsClient (orchestrator impl or direct httpx),
  StubToolExecutor fallback, CapabilityBrokerService (orchestrator broker
  or permissive local policy), ToolsService facade
- evidence_service.py: EvidenceGraph + WorldModel wrappers around SQLite,
  ingest/create_entity/create_relationship
- coordinator.py: per-task async planner/executor, TaskRegistry, pause/
  resume/abort/approve_step via asyncio.Event, broker approval gate,
  concurrency semaphore (default 2), crash-safe with finding recording
- main.py: FastAPI app with lifespan (init_db, init_llm, init_tools,
  recover_pending, SystemHealthService), all 35+ endpoints from spec,
  CORS, error handlers, signal handler guarded for TestClient use
- Dockerfile: python:3.11-slim base, non-root user, healthcheck, build-time
  import smoke check
- schema.sql: standalone SQL for inspection
- requirements.txt: pinned deps (fastapi 0.115.6, uvicorn 0.32.1, pydantic
  2.10.4, aiosqlite 0.20.0, httpx 0.28.1, neo4j 5.27.0)
- smoke_test.py: in-process TestClient mode + live HTTP mode, 25 checks
- README.md: full endpoint reference, env table, compose snippet,
  acceptance test matrix
- orchestrator/ stubs (reasoning.py, strategy.py, brain/__init__.py) so the
  brain can be imported standalone in tests; production replaces with the
  real mounted orchestrator package

Stage Summary:
- All 25 in-process smoke checks pass (health, version, capabilities, notes
  round-trip, task lifecycle, tools execute, evidence ingest, findings,
  hypotheses, contradictions, strategy build, checkpoint, webhook, DB file
  exists)
- Live uvicorn server smoke test also passes: /health returns ok with all
  4 subsystems probed (tor/sliver/neo4j/kali_tools), POST /notes round-trip
  works, POST /task creates task that reaches "completed" state, POST
  /tools/execute falls back to stub when Kali unreachable (fallback_used=true),
  SQLite DB created under BRAIN_DB path
- Service starts in <2s with no external keys (spec requires <30s)
- All spec acceptance tests (§10) verified except the docker compose build
  step (no docker daemon available in this environment)
- Files produced:
  /home/z/my-project/brain/__init__.py
  /home/z/my-project/brain/main.py
  /home/z/my-project/brain/config.py
  /home/z/my-project/brain/db.py
  /home/z/my-project/brain/schemas.py
  /home/z/my-project/brain/coordinator.py
  /home/z/my-project/brain/tools_service.py
  /home/z/my-project/brain/evidence_service.py
  /home/z/my-project/brain/llm_service.py
  /home/z/my-project/brain/system_service.py
  /home/z/my-project/brain/Dockerfile
  /home/z/my-project/brain/requirements.txt
  /home/z/my-project/brain/schema.sql
  /home/z/my-project/brain/smoke_test.py
  /home/z/my-project/brain/README.md
  /home/z/my-project/orchestrator/__init__.py
  /home/z/my-project/orchestrator/brain/__init__.py
  /home/z/my-project/orchestrator/brain/reasoning.py
  /home/z/my-project/orchestrator/brain/strategy.py
