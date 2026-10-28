# Autonomous Brain — Raphael 2.0

The autonomous planning/decision-loop microservice for the Raphael 2.0
offensive-security platform. Runs as FastAPI on port 3700 inside Docker,
reuses the existing orchestrator.brain library modules, integrates with
Kali Tools, Sliver, Neo4j, Tor and OpenAI-compatible LLM providers, and
persists all brain state to SQLite at `BRAIN_DB=/data/brain.db`.

## Quick start

```bash
# from the raphael repo root
docker compose build autonomous-brain
docker compose up -d autonomous-brain
curl -s http://localhost:3700/health | jq
```

Smoke test (in-process via FastAPI TestClient):

```bash
python brain/smoke_test.py
```

Live smoke test against a running service:

```bash
python brain/smoke_test.py --url http://localhost:3700
```

## Files

| File                  | Responsibility                                            |
| --------------------- | --------------------------------------------------------- |
| `main.py`             | FastAPI app, all routes, lifespan, error handlers          |
| `config.py`           | Pydantic v2 settings, env parsing, health snapshot        |
| `schemas.py`          | All Pydantic request/response models at the API boundary  |
| `db.py`               | aiosqlite wrapper, schema, async access layer             |
| `coordinator.py`      | Per-task async planner/executor, registry, control signals|
| `tools_service.py`    | KaliToolsClient + CapabilityBroker facade + stub fallback |
| `evidence_service.py` | EvidenceGraph + WorldModel wrapper around SQLite           |
| `llm_service.py`      | OpenAI-compatible async client, reasoning/strategy helpers|
| `system_service.py`   | Tor / Sliver / Neo4j / Kali health probes                  |
| `schema.sql`          | Standalone SQL schema for inspection / pre-provisioning   |
| `smoke_test.py`       | Round-trip smoke test (TestClient or live HTTP)           |
| `Dockerfile`          | python:3.11-slim build, non-root user, healthcheck       |
| `requirements.txt`    | Pinned Python deps                                        |

## Endpoints

All under `/docs` (Swagger UI).

### A. Health / introspection

| Method | Path             | Description                                          |
| ------ | ---------------- | ---------------------------------------------------- |
| GET    | `/health`        | status, version, brain_db, uptime, capabilities_count, active_target?, timestamp, subsystems snapshot |
| GET    | `/capabilities`  | capabilities list, engines list, tools_known count   |
| GET    | `/version`       | version (+ optional commit from env)                |

### B. Task lifecycle

| Method | Path                          | Body / Query                                  |
| ------ | ----------------------------- | --------------------------------------------- |
| POST   | `/task`                       | `{target, engagement_id?, goal?, mode, constraints?, budget?}` → `{task_id, status, accepted_at, target}` |
| GET    | `/task/{task_id}`             | state, step, plan, findings_count, risk, budget |
| POST   | `/task/{task_id}/control`    | `{action: pause\|resume\|abort\|approve_step, step_id?}` |
| GET    | `/tasks?filter=&target=`      | list of task views                            |

### C. Tooling broker

| Method | Path                          | Body                                          |
| ------ | ----------------------------- | --------------------------------------------- |
| POST   | `/tools/execute`              | `{tool, args, target?, timeout?}` → KaliToolsClient.run result |
| GET    | `/tools`                      | proxied tools list                            |
| GET    | `/tools/registry`             | orchestrator chains tool registry             |
| POST   | `/tools/capability-check`     | `{agent, tool, action, scope?}` → broker decision |

### D. Evidence / world

| Method | Path                          | Body                                          |
| ------ | ----------------------------- | --------------------------------------------- |
| GET    | `/evidence`                   | EvidenceGraph serialized (optional `?task_id=`)|
| POST   | `/evidence/ingest`            | add/merge nodes & edges                       |
| GET    | `/world/entities?type=`       | WorldModel entities                            |
| POST   | `/world/entities`             | create entity                                  |
| POST   | `/world/relationships`         | create relationship                            |

### E. Findings

| Method | Path                                       | Description                                   |
| ------ | ------------------------------------------ | --------------------------------------------- |
| GET    | `/findings?target=&severity=&task_id=&limit=` | list findings                                |
| GET    | `/findings/{id}`                           | single finding                                |

### F. Contradictions

| Method | Path                          | Description                                   |
| ------ | ----------------------------- | --------------------------------------------- |
| POST   | `/contradictions/check`       | run contradiction detection on observations  |
| GET    | `/contradictions`             | list recorded contradictions                   |

### G. Hypothesis / strategy

| Method | Path                              | Description                                 |
| ------ | --------------------------------- | ------------------------------------------- |
| GET    | `/hypotheses`                     | list hypotheses                             |
| POST   | `/hypotheses`                     | create hypothesis                           |
| POST   | `/hypotheses/{id}/verify`         | run reasoning verification, bump confidence |
| POST   | `/strategy/build`                 | `{target, profile, findings}` → `{strategy: steps}` |
| GET    | `/strategy/{task_id}`             | plan for a task                              |

### H. Trust / reflection

| Method | Path                | Description                                |
| ------ | ------------------- | ------------------------------------------ |
| GET    | `/trust?subject=`   | trust score for a subject                   |
| POST   | `/reflection/run`   | run reflection loop, update hypotheses     |

### I. Notes (SQLite)

| Method | Path                | Description                                |
| ------ | ------------------- | ------------------------------------------ |
| GET    | `/notes`            | list all notes                              |
| POST   | `/notes`             | upsert note `{key, value, tags}`            |
| GET    | `/notes/{key}`      | get one note                                |
| POST   | `/notes/{key}`      | upsert by key (body = `{value, tags}`)      |
| DELETE | `/notes/{key}`      | delete note                                 |

### J. Checkpoints

| Method | Path             | Description                                |
| ------ | ---------------- | ------------------------------------------ |
| POST   | `/checkpoint`    | `{label, task_id?, note?, payload?}`       |
| GET    | `/checkpoints`   | list checkpoints (optional `?task_id=`)    |

### K. Webhook stub

| Method | Path              | Description                                |
| ------ | ----------------- | ------------------------------------------ |
| POST   | `/webhook/notify` | record event into audit_log                |

## Environment variables

Read from environment (and `.env` if present). All optional systems degrade
gracefully — unset values do NOT crash the service.

| Variable                  | Default                          | Description                              |
| ------------------------- | -------------------------------- | ---------------------------------------- |
| `SERVICE_NAME`            | `autonomous-brain`               | service identity                          |
| `PORT`                    | `3700`                           | HTTP port                                 |
| `LOG_LEVEL`               | `INFO`                           | logging level                             |
| `BRAIN_DB`                | `/data/brain.db`                 | SQLite path                               |
| `TOR_SOCKS`               | `tor-proxy:9050`                 | Tor SOCKS endpoint                        |
| `TOR_CONTROL`             | `tor-proxy:9051`                 | Tor control endpoint                      |
| `TOR_CONTROL_PASS`        | _(unset)_                        | Tor control password                      |
| `SLIVER_OPERATOR_CONFIG`  | _(unset)_                        | path to Sliver operator.cfg               |
| `KALI_TOOLS_URL`          | `http://kali-tools:3800`         | Kali tools HTTP base URL                  |
| `NEO4J_URI`               | _(unset)_                        | Neo4j bolt URI                            |
| `NEO4J_USER`              | _(unset)_                        | Neo4j user                                |
| `NEO4J_PASS`              | _(unset)_                        | Neo4j password                            |
| `OPENAI_BASE_URL`         | `https://api.openai.com/v1`      | OpenAI-compatible base URL                |
| `OPENAI_API_KEY`          | _(unset)_                        | preferred LLM key                         |
| `OMNIROUTE_API_KEY`       | _(unset)_                        | fallback LLM key                          |
| `LLM_MODEL`               | `gpt-4o-mini`                    | chat model name                           |
| `LLM_REQUEST_TIMEOUT`     | `60`                             | per-request timeout seconds              |
| `RAPHAEL_COST_CONTROL`    | `true`                           | enable token budget enforcement           |
| `MAX_SPEND_TOKENS`        | `200000`                         | lifetime token budget                     |
| `TASK_CONCURRENCY`       | `2`                              | max concurrent tasks                      |
| `APPROVAL_TIMEOUT_SECONDS`| `60`                             | how long a step may wait for operator approval before being skipped |
| `MAX_TOOL_TIMEOUT`        | `300`                            | hard cap for any per-call tool timeout (seconds) |
| `BRAIN_API_KEY`           | _(unset)_                        | when set, all endpoints except `/health`, `/version`, `/` require header `X-API-Key: <key>` |
| `CORS_ALLOW_ORIGINS`       | `*`                              | comma-separated allowed origins (restrict in prod!) |
| `RAPHAEL_ENABLE_ML`       | `0`                              | toggle torch/transformers (not in base image) |

## Security

- **API key (opt-in).** Set `BRAIN_API_KEY` and every mutating / data
  endpoint requires `X-API-Key`. `/health`, `/version` and `/` stay open so
  the Docker HEALTHCHECK keeps working.
- **CORS.** Default `*` is convenient for dev; on an offensive-security
  control plane it lets any web page drive tool execution — set
  `CORS_ALLOW_ORIGINS=https://console.raphael.local` in production.
- **Non-root container**, read-only mounts for `orchestrator/`, dedicated
  volume for `/data`.
- Tool calls are double-gated: capability broker check before execution,
  plus a per-call timeout cap (`MAX_TOOL_TIMEOUT`).

## Persistence

SQLite at `BRAIN_DB`. Tables (defined idempotently in `db.py` and
`schema.sql`):

```
tasks, steps, findings, evidence, evidence_edges,
hypotheses, contradictions, trust_logs, notes, checkpoints, audit_log
```

- Schema is applied on startup via `CREATE TABLE IF NOT EXISTS`.
- On startup, any task left in `running` state is recovered to `paused` so
  the operator can resume explicitly.
- All DB access is async (`aiosqlite`) so the FastAPI event loop never blocks.

## Execution model

```
coordinator.create_task()                  # registers DB row, returns Task
coordinator.spawn(task)                    # asyncio.Task under semaphore
  └─ _run_task():
       1. plan = await llm.build_strategy() or default_plan()
          (resumed tasks reuse the plan loaded from the DB instead)
       2. for action in plan:
            a. broker.check(...) → require_approval?
               - task state := awaiting_approval, waits on its OWN approval
                 event (with `APPROVAL_TIMEOUT_SECONDS`); timeout → step is
                 SKIPPED, never executed; abort interrupts the wait instantly
            b. pause gate — the semaphore slot is RELEASED while blocked, so
               paused/gated tasks never starve the worker pool
            c. token-budget gate — once exhausted, remaining steps are skipped
               and a finding is recorded
            d. tools.execute(tool, args, target)  # via KaliToolsClient or stub
            e. record evidence + findings, checkpoint
       3. state := completed | aborted | failed
```

- Concurrency cap: `TASK_CONCURRENCY` (default 2).
- Pause/resume via `asyncio.Event`; abort via `Event` + cancellation.
- Terminal tasks are evicted from the in-memory registry; their views are
  served from SQLite. Control actions on finished tasks are rejected (409).
- **Resume after restart**: tasks recovered as `paused` exist only in the
  DB; `POST /task/{id}/control {"action":"resume"}` rehydrates them from
  their persisted plan (settled steps are not re-run) and re-spawns them.
- Budgets: per-task `budget` (or global `MAX_SPEND_TOKENS` when unset) is
  enforced by the coordinator; `LLMService` also refuses provider calls
  once the lifetime spend cap is reached.
- Heavy tool work goes to the Kali Tools HTTP service; if unreachable, a
  deterministic stub executor returns simulated output (marked
  `fallback_used=true`) so the loop keeps progressing.
- Manual `approve_step` unblocks actions that the broker flagged as
  `require_approval`.

## External system access

| System   | Integration path                                       | Graceful degrade |
| -------- | ------------------------------------------------------ | ---------------- |
| Kali     | `KaliToolsClient` → orchestrator impl OR direct httpx  | stub executor     |
| Sliver   | `orchestrator.c2.sliver_backend.SliverBackend`          | `None` if missing |
| Tor      | `tor_socks`/`tor_control` TCP probes                   | skip if unreachable |
| Neo4j    | `neo4j.AsyncGraphDatabase.driver`                       | skip if no creds  |
| LLM      | OpenAI-compatible `/chat/completions` via `httpx`      | deterministic fallback string |

All optional failures are surfaced in the `/health` response under
`subsystems`.

## Docker compose snippet

```yaml
services:
  autonomous-brain:
    build:
      context: .
      dockerfile: brain/Dockerfile
    ports:
      - "3700:3700"
    volumes:
      - brain-data:/data
      - sliver-config:/sliver-config
      - ./orchestrator:/app/orchestrator:ro
      - ./brain:/app/brain:ro
    env_file:
      - .env
    networks:
      - raphael-net
    healthcheck:
      test: ["CMD", "curl", "-fsS", "http://localhost:3700/health"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 15s

volumes:
  brain-data:
  sliver-config:

networks:
  raphael-net:
    external: true
```

## Acceptance tests (from spec §10)

| Test                                                | Status  |
| -------------------------------------------------- | ------- |
| `GET /health` returns 200 `{status:"ok"}`          | ✅      |
| `POST /notes` round-trip works                     | ✅      |
| `POST /task` returns `task_id`; GET tracks state   | ✅      |
| `POST /tools/execute` executes a tool              | ✅ (stub fallback when Kali unavailable) |
| SQLite DB created under `/data`                    | ✅      |
| Service starts <30s even without external keys     | ✅ (no required env beyond defaults) |
| `docker compose build autonomous-brain && up -d`    | ✅      |
| Does not break other services                      | ✅ (read-only mount of orchestrator/) |

## Quality notes

- **Structured logging**: `%(asctime)s %(levelname)s %(name)s %(message)s`.
- **Pydantic v2** at every API boundary; dataclasses inside coordinator.
- **Async I/O** everywhere: aiosqlite, httpx, asyncio primitives.
- **Graceful shutdown**: SIGINT/SIGTERM trigger `close_llm()` + `close_db()`.
- **Health accuracy**: `/health` probes Tor / Sliver / Neo4j / Kali live.
- **No fragile singletons**: services are explicitly constructed in
  lifespan and stored on `AppState`; module-level caches only for
  settings/db/tools that are inherently process-wide.
- **Cost control**: `LLMService.total_tokens_used` accumulates; budget
  enforcement is wired through the coordinator (skips LLM-heavy steps when
  budget exhausted — extend `coordinator._execute_action` to hard-enforce).
