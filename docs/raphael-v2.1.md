# Raphael 2.1 — v1 Engineering Plan

**Author:** Solo  
**Capacity:** 40-50 hrs/week  
**Deadline:** None — quality first  
**Target Ship:** Week 14-16  

---

## v1 Definition (Ship Criteria)

| Category | Criteria |
|----------|----------|
| **Core Daemon** | Rust binary runs 7 days without restart, self-heals Tor/Docker/binaries |
| **Brain** | Embedded in Rust, Thompson/UCB model selection, SQLite-vec memory, RL strategy learner |
| **C2** | Sliver + native backend (DGA + dead drops), auto-failover, implant builder |
| **Egress** | BPF kill switch, Tor enforcement, timing jitter, UA rotation, DNS leak prevention |
| **Exploit Engine** | 5-engine architecture (CrackerRecon/Exploit/PostEx/Exfil/Report), TechniqueDB with 50+ techniques. CrackerRecon: 5-layer operator-grade active recon (NetworkLayer → ServiceLayer → CoercionLayer → EvasionLayer → FootholdLayer) |
| **LLM Generation** | Generates exploit modules from TechniqueDB gaps, validates in sandbox |
| **AD Automation** | BloodHound ingest → DA path → Kerberoast/AS-REP → DCSync → Golden Ticket → persist |
| **OPSEC** | Kill switch + Tor + timing + UA rotation + DNS leak prevention (no traffic mimicry yet) |
| **Harvester** | CVE feeds + GitHub PoC scraping → TechniqueDB (runs continuous) |
| **Reporting** | Executive + Technical + NIST/ISO/PCI compliance export |
| **Health** | `/health` and `/metrics` (Prometheus) expose full system state |
| **Tests** | Integration test: full engagement against local vulnerable container (HTB Support or equivalent) |

---

## Core Architecture

### Data Contracts (The "Public API")
Every engine communicates through these structures only. No engine calls another engine's methods directly. Frozen Week 2, migrated thereafter.

```rust
/// Primary data types — all versioned, all typed
pub const SCHEMA_VERSION: u16 = 1;

pub struct EngagementId(Uuid);
pub struct SessionId(Uuid);
pub struct TargetId(Uuid);
pub struct TechniqueId(Uuid);
pub struct TaskId(Uuid);

pub enum Capability {
    PortScan, DNS, HTTP, SMB, LDAP, Kerberos, SQL,
    Exploit, PostEx, Exfil, Reporting, C2,
}

pub enum Objective {
    DiscoverAttackSurface,
    EnumerateIdentity,
    ObtainCredentials,
    GainExecution,
    EscalatePrivileges,
    CollectEvidence,
    ProduceReport,
}

/// Brain output — what to achieve (intent, not execution)
pub struct ExecutionPlan {
    pub version: u16,           // = SCHEMA_VERSION
    pub id: EngagementId,
    pub target: TargetProfile,
    pub objectives: Vec<Objective>,
    pub constraints: Constraints,
}

/// Orchestrator expansion — how to achieve it
pub struct Task {
    pub id: TaskId,
    pub capability: Capability,
    pub input: TaskInput,
    pub retry_policy: RetryPolicy,
}

/// Strongly typed task inputs — no serde_json::Value in the hot path
pub enum TaskInput {
    NetworkScan(NetworkScanInput),
    ServiceEnumeration(ServiceEnumerationInput),
    HttpProbe(HttpProbeInput),
    LdapEnumeration(LdapEnumerationInput),
    KerberosEnumeration(KerberosEnumerationInput),
    Exploit(ExploitInput),
    PostEx(PostExInput),
    Exfiltration(ExfilInput),
    Reporting(ReportInput),
    C2(C2Input),
}

// Supporting data contracts — all versioned
pub struct TargetProfile { pub version: u16, os, services, domains, users, ... }
pub struct Technique { pub version: u16, id, name, prerequisites, exploit_code, opsec_rating, ... }
/// Strongly typed engine outputs — mirrors TaskInput pattern
pub enum EngineOutput {
    Recon(ReconOutput),
    Exploit(ExploitOutput),
    PostEx(PostExOutput),
    Exfil(ExfilOutput),
    Report(ReportOutput),
    C2(C2Output),
}

pub struct ExecutionMetrics {
    pub duration_ms: u64,
    pub tokens_used: u64,
    pub techniques_tried: u32,
}

pub struct ExecutionResult {
    pub version: u16,
    pub task_id: TaskId,
    pub output: EngineOutput,
    pub metrics: ExecutionMetrics,
}
pub struct Finding { pub version: u16, type, severity, data, source, ... }
pub struct Credential { pub version: u16, realm, username, hash, password, source, ... }
pub struct Session { pub version: u16, id: SessionId, agent_type, transport, target_info, ... }
pub struct ReportArtifact { pub version: u16, type, content, format, ... }

/// Every engine receives this — eliminates parameter soup
pub struct EngagementContext {
    pub id: EngagementId,
    pub state: EngagementState,
    pub target: TargetProfile,
    pub plan: ExecutionPlan,
    pub sessions: SessionStore,
    pub findings: FindingStore,
    pub credentials: CredentialStore,
    pub knowledge: KnowledgeStore,
    pub metrics: EngagementMetrics,
    pub config: Arc<Config>,
}
```

### Engine Interface
Every subsystem implements the same trait:

```rust
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub enum EngineId {
    Recon, Exploit, PostEx, Exfil, Report, C2,
}

pub struct EngineMetadata {
    pub id: EngineId,
    pub version: &'static str,
    pub capabilities: Vec<Capability>,
}

pub enum EngineStatus {
    Stopped,
    Initializing,
    Ready,
    Busy,
    Recovering,
    Failed,
}

pub trait Engine: Send + Sync {
    fn metadata(&self) -> EngineMetadata;
    fn status(&self) -> EngineStatus;
    fn initialize(&mut self, config: &Config) -> Result<()>;
    fn execute(&mut self, ctx: &mut EngagementContext, task: &Task) -> Result<ExecutionResult>;
    fn validate(&self, result: &ExecutionResult) -> ValidationResult;
    fn checkpoint(&self) -> Result<EngineState>;
    fn rollback(&mut self, state: &EngineState) -> Result<()>;
}
```

### Engine Registry

Engines register themselves by `EngineId`. The Orchestrator resolves engines by ID — no capability-based routing in v1.

```rust
pub struct EngineRegistry {
    engines: HashMap<EngineId, Box<dyn Engine>>,
}

impl EngineRegistry {
    pub fn register(&mut self, engine: Box<dyn Engine>) {
        self.engines.insert(engine.metadata().id, engine);
    }

    pub fn engine(&self, id: EngineId) -> Option<&dyn Engine> {
        self.engines.get(&id).map(|e| e.as_ref())
    }
}
```

Adding a new engine:
```
registry.register(Box::new(MyReconEngine));
```
No orchestrator modification required.



### Event Bus

All cross-module communication is event-driven through typed events:

```rust
enum Event {
    TargetAcquired(TargetProfile),
    TechniqueSelected(Technique),
    ExploitValidated(ExecutionResult),
    CredentialDiscovered(Credential),
    SessionEstablished(Session),
    ReportGenerated(ReportArtifact),
    EngineFailure { engine: String, error: Error },
}
```

Modules publish events. Subscribers consume. Zero coupling between publisher and consumer.

### Event Store (Persistent)

Every event is written to SQLite by an async subscriber task — the Event Bus never waits for persistence:

```
Engine → Event Bus (in-memory, tokio::broadcast)
                    ↓
              Async Logger Task (tokio::spawn)
                    ↓
              SQLite events table (fire-and-forget)
```

```sql
-- Event Store schema
CREATE TABLE events (
    id UUID PRIMARY KEY,
    engagement_id UUID,
    timestamp TIMESTAMPTZ,
    event_type TEXT,
    payload BLOB
);
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
```

If SQLite stalls, only the Event Store is affected. The event pipeline remains operational.

### Engagement State Machine

```
Idle → Planning → Running → Completed
                        ↘ Failed
```

```rust
pub enum EngagementState {
    Idle,       // daemon alive, no engagement active
    Planning,   // Brain producing ExecutionPlan
    Running,    // Orchestrator dispatching Tasks
    Completed,  // all objectives met
    Failed,     // unrecoverable error
}
```

The Orchestrator manages only state transitions. Nothing else.

### Orchestrator vs Brain

- **Brain**: intelligence only — produces an `ExecutionPlan` containing high-level **Objectives** (what to achieve, not how)
- **Orchestrator**: execution only — expands Objectives into Capabilities, generates typed `Task` structs, resolves engines via `EngineRegistry`, dispatches execution, manages state transitions, retries, and rollbacks

```
Brain
  ↓
ExecutionPlan { objectives: [DiscoverAttackSurface, EnumerateIdentity] }
  ↓
Orchestrator
  ↓
Objective expansion → Capabilities → Task generation → EngineRegistry → Engine
```

Brain never executes. Orchestrator never decides.

### KnowledgeStore

Explicit ownership of persistent knowledge:

```
KnowledgeStore
├── TechniqueDB     → techniques, payloads, prerequisites, opsec_rating, confidence
├── FindingStore    → what was discovered
├── CredentialStore → what was captured
├── SessionStore    → what was established
├── MemoryStore     → what was learned (vector memory via SQLite-vec)
└── MetricsStore    → what was measured
```

Engines read via `KnowledgeReader`. Only the Orchestrator and Brain write via `KnowledgeWriter`.

```rust
pub trait KnowledgeReader {
    fn query_techniques(&self, service: &str, os: &str, version: &str) -> Vec<Technique>;
    fn get_findings(&self, engagement: EngagementId) -> Vec<Finding>;
    fn recall_memory(&self, query: &str, k: usize) -> Vec<MemoryEntry>;
    fn get_credentials(&self, engagement: EngagementId) -> Vec<Credential>;
    fn get_sessions(&self, engagement: EngagementId) -> Vec<Session>;
}

pub trait KnowledgeWriter {
    fn store_finding(&mut self, finding: Finding) -> Result<()>;
    fn store_credential(&mut self, cred: Credential) -> Result<()>;
    fn store_session(&mut self, session: Session) -> Result<()>;
    fn store_memory(&mut self, entry: MemoryEntry) -> Result<()>;
    fn update_metrics(&mut self, metrics: EngagementMetrics) -> Result<()>;
}
```

Engines receive `&impl KnowledgeReader`. The Orchestrator and Brain hold `&mut impl KnowledgeWriter`. Engines can read anything, write nothing.

---

## Phase Breakdown

### Phase 0: Foundation (Weeks 1-2) — **No Python, Pure Rust**

| Week | Task | Deliverable |
|------|------|-------------|
| 1 | **Rust project setup** — `cargo new raphael-core`, workspace with `crates/` for daemon, orchestrator, brain, c2, egress, weaponizer, common | Compiling binary with `cargo build --release` |
| 1 | **SQLite-vec integration** — `rusqlite` + `sqlite-vec` extension, schema for techniques/findings/memory | `cargo test` passes on vector similarity search |
| 1 | **BPF kill switch** — Write eBPF C, compile with `aya`/`libbpf-rs`, load at startup, verify blocks non-Tor | `curl --socks5 127.0.0.1:9050` works, direct `curl` fails |
| 1 | **Tor manager** — Start/stop/monitor Tor process, verify circuit, NEWNYM, exit IP check | `TorManager::verify()` returns `Ok(ExitIP)` |
| 1 | **Docker Compose manager** — `bollard` client, health checks, auto-restart failed services | `DockerManager::ensure_healthy()` maintains 11 services |
| 1 | **Binary verifier** — Check `nmap`, `sqlmap`, `gobuster`, `nuclei`, `subfinder` exist; auto-install via package manager | `BinaryVerifier::ensure_all()` returns `Ok(())` |
| 1 | **Core data types + Engine trait + Registry** — Define all versioned contracts: `TargetProfile`, `Technique`, `ExecutionPlan`, `ExecutionResult`, `Finding`, `Credential`, `Session`, `ReportArtifact` with `version: u16`. Add typed IDs: `EngagementId`, `SessionId`, `TargetId`, `TechniqueId`, `TaskId`. Add `Capability`, `Objective`, `TaskInput` enums. Define `trait Engine` with `metadata()`, `status()`, `initialize`, `execute`, `validate`, `checkpoint`, `rollback`. Define `EngineId`, `EngineMetadata`, `EngineStatus` (with `Stopped`). Implement `EngineRegistry` with `HashMap<EngineId, Box<dyn Engine>>`. Serde + bincode for serialization | `cargo test` passes on type serialization round-trips. Engine trait compiles with mock implementation. EngineRegistry registers and resolves by EngineId |
| 2 | **Config system** — Parse `.env` + `.env.example` → typed struct, validate all required vars, generate `.env.example` from `os.getenv()` scan | `Config::load()` returns validated struct or descriptive errors |
| 2 | **Event Bus + Event Store** — `tokio::broadcast` with typed `Event` enum in `common` crate. Async subscriber task (tokio::spawn) writes events to SQLite `events` table (fire-and-forget, non-blocking). SQLite initialized with WAL mode (`PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL`) | `EventBus::publish(TargetAcquired(...))` → all subscribers receive within 10ms. Events persist in `events` table regardless of subscriber success |
| 2 | **Tracing spans** — Structured `tracing` spans for every major action: `engagement`, `recon`, `exploit`, `postex`, `exfil`, `report`. Each span includes `target`, `phase`, `model`, `verdict` fields | `tracing-subscriber` JSON output shows nested spans with all fields |
| 2 | **Schema freeze** — All core data types marked `#[non_exhaustive]`. Schema migrations tested. No further schema changes without team review | `cargo test` confirms backward-compatible deserialization of all types |
| 2 | **Health/Metrics server** — `axum` on `:3900`, `/health` (full stack), `/metrics` (Prometheus) | `curl localhost:3900/health` → JSON with all component status |
| 2 | **Logging** — `tracing` + `tracing-subscriber` with JSON output, structured fields | Logs are parseable, include `target`, `phase`, `model`, `verdict` |

**Dependencies:** None — this is the foundation everything else builds on.

**Definition of Done (Phase 0):**
- ✓ Unit test coverage >80% on common crate
- ✓ Core data types serialize/deserialize correctly
- ✓ Engine trait compiles with mock implementation
- ✓ Event Bus passes multi-consumer integration test
- ✓ Tracing spans visible in JSON log output
- ✓ Schema frozen — no changes without migration
- ✓ Dev container builds from clean clone
- ✓ EngineRegistry registers and resolves engines by EngineId
- ✓ Event Store: events written to SQLite asynchronously with WAL mode
- ✓ EngagementState machine transitions tested (Idle→Planning→Running→Completed/Failed)
- ✓ Typed IDs (EngagementId, SessionId, TargetId, TechniqueId, TaskId) prevent cross-type confusion at compile time
- ✓ EngineStatus includes Stopped state

---

### Phase 1: Brain + Orchestrator (Weeks 3-4) — **Rust + pyo3**

| Week | Task | Deliverable |
|------|------|-------------|
| 3 | **pyo3 embed** — Initialize Python interpreter in Rust, expose `call_model()` to Python exploit modules | `Python::with_gil(|py| py.run("import orchestrator.providers", ...))` works |
| 3 | **ModelRouter (Rust)** — Thompson sampling + UCB1 + circuit breaker per (model, context), pre-seeded priors | `router.select("recon")` → `"wormgpt12"` with confidence score |
| 3 | **NeuralMemory (Rust)** — SQLite-vec for episodic + semantic, vector similarity for technique retrieval | `memory.store_episodic(...)` + `memory.retrieve_similar(embedding, k=10)` |
| 3 | **StrategyLearner (Rust, Brain side)** — Q-learning with ε-greedy, state = discretized target profile. Produces `ExecutionPlan` with high-level Objectives (not capabilities or engine names) | `brain.strategy_learner.plan(target_profile)` → `ExecutionPlan { objectives: [DiscoverAttackSurface, EnumerateIdentity] }` |
| 3 | **Orchestrator (Rust, execution side)** — Expands ExecutionPlan Objectives into Capabilities, generates typed `Task` structs with `TaskInput`. Includes `TaskScheduler` (FIFO queue, retry counter, max_retries). Resolves engines via `EngineRegistry` by `EngineId`. Manages `EngagementState` machine (Idle→Planning→Running→Completed/Failed). Implements rollback via `Engine::checkpoint()` | `orchestrator.execute(plan)` → expands objectives → schedules Tasks → dispatches to registered engines → manages state transitions → returns ExecutionResult |
| 4 | **TargetProfiler (Rust + Python)** — Rust orchestrates, calls Python `profile_target()` via pyo3. Publishes `TargetAcquired` event on completion | `profiler.profile("target.com")` → `TargetProfile` struct + Event Bus notification |
| 4 | **Prompt sanitizer (Rust)** — Port sanitization logic from `providers.py` to Rust, applied before `call_model()` | Safety-filtered models never see IPs/hostnames |
| 4 | **Cost tracking** — Token counting + budget enforcement in Rust. Published as `CostExceeded` event when limits hit | `CostTracker::check_limit()` raises `CostExceeded` event if `> MAX_SPEND_TOKENS` |

**Dependencies:** Phase 0 complete (daemon, config, SQLite-vec, EngineRegistry, Event Bus + Event Store, typed contracts frozen).

**Definition of Done (Phase 1):**
- ✓ Brain produces valid ExecutionPlan with rankings
- ✓ Orchestrator dispatches ExecutionPlan to correct engine via Engine trait
- ✓ TargetProfiler produces TargetProfile (schema-compliant)
- ✓ pyo3 bridge passes integration test (or REST fallback works)
- ✓ Event Bus wired to all modules
- ✓ Rollback from failed engine execution tested
- ✓ Cost tracking raises event on budget exceed
- ✓ Brain produces ExecutionPlan with Objectives (not capabilities/engine names)
- ✓ Orchestrator expands Objectives → Capabilities → typed Tasks
- ✓ EngagementState machine integrated into Orchestrator execution loop
- ✓ EngineRegistry populated and used for engine dispatch
- ✓ TaskScheduler queues tasks, tracks retries, enforces max_retries
- ✓ EngagementContext passed to every engine.execute() call

---

### Phase 2: C2 + Egress (Weeks 5-6) — **Rust**

| Week | Task | Deliverable |
|------|------|-------------|
| 5 | **SliverBackend** — gRPC client to Sliver (`sliver-client` crate or protobuf), session mgmt, implant generation | `SliverBackend::get_session(target)` → `Session` |
| 5 | **NativeBackend** — Custom beacon: DGA (seeded), dead-drop URLs (S3/GCS/Cloudflare R2), HTTPS with domain fronting | `NativeBackend::generate_implant(config)` → `bytes` |
| 5 | **C2Manager** — Multi-backend failover, session pooling, SOCKS proxy per session | `manager.ensure_session(target)` tries Sliver → Native → Pupy |
| 5 | **ImplantBuilder** — Weaponizer integration: XOR → UPX → module stomp → reflective load → codesign | `builder.build(profile)` → weaponized payload |
| 6 | **EgressRouter** — Strategy pattern: Tor, WireGuard, direct (dev), auto-select based on availability | `router.route(target)` → `reqwest::Client` with proxy |
| 6 | **TrafficShaper (stub)** — Interface for timing/profile, v1 = basic jitter + UA rotation | `shaper.wrap(client)` → client with enforced delays |

**Dependencies:** Phase 0 (daemon, Tor, Docker), Phase 1 (pyo3 for weaponizer Python modules).

**Definition of Done (Phase 2):**
- ✓ SliverBackend establishes session on test target
- ✓ NativeBackend generates working implant
- ✓ C2Manager failover tested (Sliver down → Native)
- ✓ ImplantBuilder produces weaponized payload
- ✓ EgressRouter routes through Tor and direct
- ✓ Session established event published on Event Bus
- ✓ Engine trait implemented for C2 backend


---

### Phase 3: Exploit Engine + TechniqueDB + CrackerRecon (Weeks 7-10) — **Python (pyo3) + Rust orchestration**

| Week | Task | Deliverable |
|------|------|-------------|
| 7 | **TechniqueDB schema + migration** — Schema frozen in Phase 0. Week 7 extends with CrackerRecon fields: `bypass_methodology`, `waf_type`, `waf_bypass_payload`, `timing_oracle_data` (JSON), `rate_limit_threshold`, `credential_surface` (JSON), `foothold_type`, `decoy_strategy` | SQLite migration runs on startup |
| 7 | **Harvester → TechniqueDB** — Port `harvester_engine.py` to use new schema, LLM extracts `exploit_code` from PoCs; CrackerRecon probes seed TechniqueDB on success (AS-REP hashes, WAF bypass payloads, timing oracle validations) | `harvester.run_cycle()` → 10+ new techniques with runnable code; CrackerRecon findings auto-ingested |
| 7 | **TechniqueDB API (Rust)** — `query(service, os, version, vuln_type)` → ranked techniques by confidence × opsec; new: `query_by_waf(waf_type)` → bypass payloads, `query_footholds(target_profile)` → credential vectors | `db.query_techniques("nginx", "linux", "1.18", "rce")` returns exploits; `db.query_by_waf("cloudflare")` returns 5+ bypass strategies |
| 8 | **CrackerRecon NetworkLayer + ServiceLayer (Python)** — Implements `trait Engine`. Publishes `TargetAcquired` upon completion. Staged adaptive scanning: top-100 SYN → masscan/all-ports (no-WAF) or rate-limited nmap (WAF). Per-protocol deep probes: SMB (null/guest/share enum), LDAP (anonymous bind, base DN discovery, user/computer/group enumeration), Kerberos (domain extraction, user enum, AS-REP target ID), HTTP (verb coercion, full header analysis, path discovery), DNS (zone transfer, NSEC walk, recursion check), SNMP (community brute, MIB walk) | `crackerrecon.network_layer.run(target)` → open ports + OS fingerprint + service versions; `crackerrecon.service_layer.run(target, ports)` → protocol-specific deep profiles with extracted data (users, shares, domains, configs) |
| 8 | **ExploitEngine (Python)** — Implements `trait Engine`. Publishes `ExploitValidated` event on completion. Hypothesis → test → validate loop, ranks techniques, executes top-N in sandbox | `exploit.run(profile)` → `ShellSession` or `None` |
| 8 | **Sandbox validator** — `Dockerfile.sandbox` with network isolation (`--cap-drop=ALL --security-opt=no-new-privileges`), read-only rootfs, 512M memory limit, strace monitoring, `pdeath` signal | `sandbox.validate(exploit_code)` → `ValidationResult` |
| 9 | **CrackerRecon CoercionLayer + EvasionLayer (Python)** — Implements `trait Engine`. Publishes `TechniqueSelected` event on WAF bypass discovery. Coercion: timing oracles for username/data enumeration, error-message differential analysis, response-size oracle for IDOR, content-type switching (JSON/XML/multipart) for parsing bypass, chunked transfer encoding smuggling, HTTP verb override. Evasion: WAF fingerprint + bypass decision tree per platform (Cloudflare origin via CNAME chain, AWS header injection, Akamai edge chaining, ModSecurity encoding chains), rate-limit mapping with adaptive pacing, proxy rotation (Tor/residential/datacenter), decoy traffic injection to bury signal in noise | `crackerrecon.coercion_layer.run(profile)` → valid usernames confirmed, hidden endpoints, WAF rules mapped; `crackerrecon.evasion_layer.run(profile, bypass_strategy)` → working bypass chain, rate-limit threshold, optimal source rotation |
| 9 | **CrackerRecon FootholdLayer (Python)** — Implements `trait Engine`. Publishes `CredentialDiscovered` event on credential harvest. Default credential sweep on all discovered services (SSH, MySQL, Postgres, MSSQL, Redis, FTP, SMB, Jenkins, Tomcat, etc.). AS-REP roasting on enumerated Kerberos users. SMB null/guest session → full share harvest (password files, configs, backups, SSH keys, GPO XML). Constrained password spray (2-3 passwords, lockout-aware pacing). Anonymous service access (Redis, Memcached, MongoDB, Elasticsearch, Docker API, Kibana, Grafana) | `crackerrecon.foothold_layer.run(profile)` → `Vec<Foothold>` with credentials, hashes, accessed shares, validated access. Seeds TechniqueDB with successful vectors |
| 9 | **PostExEngine (Python)** — Implements `trait Engine`. Publishes `SessionEstablished` event. BloodHound + Impacket automation, AD kill chain, lateral movement | `postex.run(sessions)` → new sessions + DA/root |
| 9 | **ExfilEngine (Python)** — Implements `trait Engine`. Publishes event on exfil completion. Multi-channel (DNS/HTTPS/ICMP), priority-based loot selection | `exfil.run(loot, profile)` → delivery confirmation |
| 9 | **ReportEngine (Python)** — Implements `trait Engine`. Publishes `ReportGenerated` event. Executive + Technical + Compliance (NIST/ISO/PCI) templates | `report.generate(engagement)` → `bytes` (PDF/MD/HTML) |
| 10 | **Full pipeline integration** — Wire CrackerRecon → ExploitEngine → PostExEngine → ExfilEngine → ReportEngine into main loop. CrackerRecon feeds CrackerProfile (bypass methodology, credential surface, footholds, WAF rules) into ExploitEngine for targeted exploitation. Error handling, retry logic, state persistence | `engagement.run(target)` → full report with CrackerRecon deep-dive appendix (services extracted, bypasses discovered, footholds obtained) |

**Dependencies:** Phase 1 (Brain, pyo3), Phase 2 (C2 for PostEx, EgressRouter for proxy rotation). CrackerRecon EvasionLayer integrates with Phase 2 EgressRouter for Tor/proxy rotation.

**Definition of Done (Phase 3):**
- ✓ All engines implement Engine trait (initialize, execute, validate, checkpoint, rollback)
- ✓ Each engine publishes at least one Event on completion
- ✓ Schema migrations pass without data loss
- ✓ Sandbox validator rejects malicious payloads
- ✓ CrackerRecon produces valid CrackerProfile (schema-compliant)
- ✓ Integration test: CrackerRecon → ExploitEngine → PostEx → Report produces output
- ✓ Unit test coverage >70% per engine module

---

### Phase 4: AD Automation + Lateral (Week 11) — **Python**

| Week | Task | Deliverable |
|------|------|-------------|
| 11 | **ADKillChain** — Full automation: ingest → DA path → Kerberoast/AS-REP → DCSync → Golden Ticket → GPO persist | `ad_kill_chain.run(session)` → `DomainAdminSession` |
| 11 | **LateralEngine** — SSH keys, PtH, PtT, WinRM, PSRemoting, SMB relay, Docker escape scoring | `lateral.run(sessions, network)` → new sessions |
| 11 | **CredentialHarvester** — LSASS (sekurlsa), SAM, browser, SSH agent, K8s, cloud env | `harvest_creds(session)` → `Vec<Credential>` |

**Dependencies:** Phase 3 (PostExEngine, C2 sessions).

**Definition of Done (Phase 4):**
- ✓ ADKillChain produces DA session via BloodHound → DCSync → Golden Ticket
- ✓ LateralEngine establishes session on remote target
- ✓ CredentialHarvester extracts credentials from at least 3 sources
- ✓ All engines implement Engine trait, publish events
- ✓ Integration test: C2 session → AD escalation → lateral movement succeeds

---

### Phase 5: OPSEC v1 + Weaponizer (Week 12) — **Rust + Python**

| Week | Task | Deliverable |
|------|------|-------------|
| 12 | **Weaponizer (Rust)** — Payload pipeline: raw → XOR → UPX → module stomp → reflective → codesign | `weaponizer.build(profile)` → weaponized bytes |
| 12 | **Delivery vectors** — Phishing (Gophish API), watering hole (JS injection), supply chain (npm typosquat stub) | `delivery.send(payload, vector, target)` |
| 12 | **Log scrubber** — Journald, bash history, auth logs, Windows Event Log cleanup | `scrub.clean(session)` → `CleanResult` |

**Dependencies:** Phase 2 (Weaponizer interface), Phase 3 (ExploitEngine needs payloads).

**Definition of Done (Phase 5):**
- ✓ Weaponizer produces working payload (XOR → UPX → codesign)
- ✓ Payload executes on target without AV detection (test container only)
- ✓ Engine trait implemented, `ImplantBuilt` event published

---

### Phase 6: Integration + Hardening + v1 Tests (Weeks 13-14)

| Week | Task | Deliverable |
|------|------|-------------|
| 13 | **Full integration** — Wire daemon → brain → engines → C2 → egress → weaponizer | `raphael engage target.com --persona z3r0` works end-to-end |
| 13 | **Config validation** — All 42 env vars documented, defaults set, `.env.example` auto-generated | `config.validate()` passes on fresh clone |
| 13 | **Error handling** — Circuit breakers, retries, graceful degradation (e.g., Sliver down → native C2) | No single component failure crashes daemon |
| 14 | **Integration test** — Deploy HTB Support (or equivalent) locally, run full engagement, capture flags | Test passes: user flag + root flag + report generated |
| 14 | **Soak test** — Run daemon for 48h with periodic engagements, verify no memory leaks, no crashes | `valgrind`/`heaptrack` clean, metrics stable |
| 14 | **Documentation** — `README.md` with deploy steps, architecture diagram, API reference | New user can deploy in <30 min |

**Dependencies:** All prior phases.

**Definition of Done (Phase 6):**
- ✓ Full engagement: `raphael engage target.com --persona z3r0` captures user + root flags
- ✓ Report generated in PDF/MD/HTML
- ✓ Soak test: 48h continuous run, zero crashes, stable memory
- ✓ Documentation covers deploy, API reference, architecture diagram
- ✓ README can be followed by new developer in <30 min

---

## Dependency Graph (Critical Path)

```
Phase 0 (Foundation)
    │
    ├─→ Phase 1 (Brain + Orchestrator) ──────┐
    │                                 │
    ├─→ Phase 2 (C2 + Egress) ────────┼─→ Phase 3 (Exploit Engine)
    │                                 │       │
    └─→ Phase 5 (Weaponizer) ─────────┤       ├─→ Phase 4 (AD + Lateral)
                                      │       │
                                      └───────┴─→ Phase 6 (Integration + Test)
```

**Critical Path:** Phase 0 → Phase 1 → Phase 3 → Phase 6 = **14 weeks minimum**

**Parallel Tracks:**
- Phase 2 (C2/Egress) can run parallel with Phase 1 after Week 3
- Phase 5 (Weaponizer) can run parallel with Phase 3 after Week 8

---

## Risk Register

| Risk | Likelihood | Impact | Contingency |
|------|------------|--------|-------------|
| **pyo3 embedding unstable / GIL issues** | High | High | Fallback: REST API between Rust daemon and Python worker pool |
| **SQLite-vec compilation issues on target arch** | Medium | High | Fallback: Pure Rust `hnsw` crate for vector search |
| **Sliver gRPC API changes break backend** | Medium | Medium | Pin Sliver version in Dockerfile, maintain `sliver-client` fork |
| **TechniqueDB LLM extraction produces broken exploits** | High | Medium | Sandbox validation rejects non-working code; human review queue |
| **BPF kill switch blocks Docker bridge on some kernels** | Medium | High | Test on target kernel (5.15+); fallback: iptables with `DOCKER-USER` chain |
| **Harvester GitHub API rate limits** | High | Low | Use multiple tokens, exponential backoff, prioritize high-CVSS CVEs |
| **Model API costs exceed budget** | Low | Medium | Hard limit in `CostTracker`; graceful degradation to local Ollama models |
| **WAF bypass payload maintenance** | High | Medium | Build framework (header injection, encoding chains, protocol confusion) not hardcoded payloads. LLM generates mutations from base payloads. Monthly WAF rule update sync |
| **Rate-limit discovery burns source IP** | Medium | Low | Use disposable proxy pool for discovery phase. Tiered sources: residential (slow/discover), datacenter (fast/exploit), Tor (anonymous/fallback) |
| **FootholdLayer blurs recon/exploit boundary** | Medium | Medium | Configurable toggle: `--foothold-passive-only` (identify only), `--foothold-aggressive` (AS-REP, spray, null session). Default: passive. Explicit opt-in for aggressive |
| **Solo burnout at Week 10-12** | Medium | High | Mandatory 1-week buffer; cut scope if needed |

---

**Execution Rhythm:** One objective per week. No parallel subsystem development. Deep focus on one engine, one crate, one deliverable until merged and tested.

---

## Revised Timeline Summary

| Phase | Weeks | Cumulative | Buffer |
|-------|-------|------------|--------|
| 0: Foundation | 2 | 2 | — |
| 1: Brain + pyo3 | 2 | 4 | — |
| 2: C2 + Egress | 2 | 6 | — |
| 3: Exploit Engine + TechniqueDB | 4 | 10 | — |
| 4: AD + Lateral | 1 | 11 | — |
| 5: OPSEC v1 + Weaponizer | 1 | 12 | — |
| 6: Integration + Test | 2 | 14 | **2 weeks** |

**Total: 14 weeks + 2 weeks buffer = 16 weeks**

---

## Go/No-Go Decision Points

| Week | Gate | Criteria |
|------|------|----------|
| 2 | Foundation solid? | Daemon runs 24h, Tor/Docker/binaries self-heal, health endpoint green |
| 4 | Brain + Orchestrator work? | Model router selects, memory stores/retrieves, Brain produces ExecutionPlan, Orchestrator dispatches to engines, pyo3 stable |
| 6 | C2 + Egress work? | Sliver session → command → output; Tor enforced; direct traffic blocked |
| 10 | Exploit engine cracks? | TechniqueDB → exploit → shell against local HTB target |
| 12 | Full engagement? | `raphael engage target.com` → user flag + root flag + report |
| 14 | v1 ready? | Soak test passes, integration test passes, docs complete |

---

## Scope Decisions (Locked)

| Question | Answer |
|----------|--------|
| Team | Solo, 40-50 hrs/wk |
| Deadline | None — quality first |
| Rust scope | Daemon, C2, egress, weaponizer, core loop. Python via pyo3 for exploits + LLM |
| Fuzzing | v1.1 |
| Target | Linux + AD, no hypervisor/K8s for v1 |
| OPSEC staging | v1 = BPF kill switch + Tor + basic timing. v1.1 = traffic mimicry + infra opacity. v1.2 = full anti-forensics |
| FootholdLayer aggression | Default passive (identify only). `--foothold-aggressive` enables AS-REP roasting, constrained spray, null/guest session access, default cred testing |

---


---

## Architecture Freeze

The following components are frozen for v1:

- Data Contracts (all versioned types, typed IDs, Capability, Objective, TaskInput, EngineOutput)
- Engine Trait (with metadata, status, EngagementContext parameter)
- Engine Registry (register + engine by EngineId, no capability routing)
- Event Bus + Event Store (in-memory bus, async SQLite subscriber, WAL mode)
- EngagementContext (single context object for all engine calls)
- Brain ↔ Orchestrator boundary (Brain produces Objectives, Orchestrator expands)
- Objective → Capability → Task pipeline
- KnowledgeStore ownership (TechniqueDB, Findings, Credentials, Sessions, Memory, Metrics)
- KnowledgeReader / KnowledgeWriter split
- Engagement State Machine (Idle → Planning → Running → Completed → Failed)
- TaskScheduler (FIFO queue, retry counter, max_retries)

**No architectural redesigns will be accepted during implementation unless:**
1. A correctness issue is discovered.
2. A security issue requires redesign.
3. The change reduces complexity without expanding scope.

All future effort goes to implementation, testing, and integration — not architecture.


## Next Action

**Start Phase 0, Week 1:**

1. `cargo new raphael-core --bin`
2. Set up workspace with crates: `daemon`, `orchestrator`, `brain`, `c2`, `egress`, `weaponizer`, `common`
3. Add dependencies: `tokio`, `axum`, `rusqlite`, `sqlite-vec`, `bollard`, `aya`/`libbpf-rs`, `tracing`, `clap`, `serde`, `config`
4. Write eBPF kill switch C code
5. Implement `TorManager`, `DockerManager`, `BinaryVerifier`
6. Health server on `:3900` with `/health` and `/metrics`

---

*Generated from planning session — this is the working plan for v1.*