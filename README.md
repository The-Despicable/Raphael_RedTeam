# Raphael V3 — Autonomous Cognitive Offensive AI Platform

A self-growing offensive AI organism that autonomously probes targets, builds belief-state profiles via a **D-Series (Brain)**, continuously researches techniques via an **S-Series (Student)**, and executes stateful shell operations via an **E-Series (Hands)** — all within a strict, brokered authorization envelope.

## Architecture

Raphael V3 is a **unified cognitive agent**. Three core series (D, S, E) operate asynchronously with a **P-Series** stealth layer embedded within them — all communicating through shared WorldModel state, converging on a single objective: find a weakness, validate it, exploit it, and learn from it.

```
┌──────────────────────────────────────────────────────────────────────────┐
│                        RAPHAEL COGNITIVE AGENT v3                        │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐    │
│  │  D-SERIES — BRAIN  (orchestrator/brain/)                         │    │
│  │  ┌──────────┐  ┌────────────┐  ┌───────────┐  ┌──────────────┐  │    │
│  │  │ Planner  │  │WorldModel  │  │Capability │  │Falsification │  │    │
│  │  │ (action) │  │ (world)    │  │ Broker    │  │ Manager      │  │    │
│  │  └──────────┘  └────────────┘  └───────────┘  └──────────────┘  │    │
│  │  ┌──────────┐  ┌────────────┐  ┌───────────┐  ┌──────────────┐  │    │
│  │  │Candidate │  │ Contradict │  │ Reflection│  │ Strategy     │  │    │
│  │  │Generator │  │ Detection  │  │ Engine    │  │ Learner      │  │    │
│  │  └──────────┘  └────────────┘  └───────────┘  └──────────────┘  │    │
│  │  ┌──────────────┐  ┌────────────┐  ┌──────────────┐             │    │
│  │  │ ScopeParser  │  │RateLimiter │  │ WAFDetector  │  ← P1       │    │
│  │  │ (SS-01)      │  │ (SS-02)    │  │ (SS-03)      │             │    │
│  │  └──────────────┘  └────────────┘  └──────────────┘             │    │
│  └──────────────────────────────────────────────────────────────────┘    │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐    │
│  │  S-SERIES — STUDENT  (orchestrator/student/)                      │    │
│  │  ┌────────────────┐  ┌────────────────┐  ┌────────────────────┐  │    │
│  │  │ Research       │  │ Chain          │  │ Knowledge          │  │    │
│  │  │ Scheduler      │  │ Synthesizer    │  │ Background Service │  │    │
│  │  └────────────────┘  └────────────────┘  └────────────────────┘  │    │
│  │  ┌────────────────┐  ┌────────────────┐  ┌────────────────────┐  │    │
│  │  │ Coverage Gap   │  │ Stack          │  │ PayloadMutator     │  │    │
│  │  │ Filler         │  │ Matcher        │  │ (SS-04)     ← P1   │  │    │
│  │  └────────────────┘  └────────────────┘  └────────────────────┘  │    │
│  └──────────────────────────────────────────────────────────────────┘    │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐    │
│  │  E-SERIES — HANDS  (orchestrator/capabilities/interactive_shell/) │    │
│  │  ┌────────────────┐  ┌────────────────┐  ┌────────────────────┐  │    │
│  │  │ SSH Shell      │  │ Reverse Shell  │  │ Command Filter     │  │    │
│  │  │ Capability     │  │ Capability     │  │ Pipeline (T1+T2)   │  │    │
│  │  └────────────────┘  └────────────────┘  └────────────────────┘  │    │
│  │  ┌────────────────┐  ┌────────────────┐  ┌────────────────────┐  │    │
│  │  │ Shell Session  │  │ TTY Normalizer │  │ Listener           │  │    │
│  │  │ Store          │  │ + Evidence Ext │  │ Manager (Broker)   │  │    │
│  │  └────────────────┘  └────────────────┘  └────────────────────┘  │    │
│  └──────────────────────────────────────────────────────────────────┘    │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐    │
│  │  CORE INFRASTRUCTURE  (orchestrator/)                             │    │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌───────────┐       │    │
│  │  │Harvester │  │ Mesh     │  │Privesc   │  │Propagation│       │    │
│  │  │(CVE feed)│  │(P2P net) │  │(27 LPE)  │  │(lateral)  │       │    │
│  │  └──────────┘  └──────────┘  └──────────┘  └───────────┘       │    │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌───────────┐       │    │
│  │  │Weaponizer│  │Social    │  │Survivabil│  │CICD/Cloud │       │    │
│  │  │(C/Go/Rust)│ │(phish)   │  │(kill sw) │  │/ML Attack │       │    │
│  │  └──────────┘  └──────────┘  └──────────┘  └───────────┘       │    │
│  └──────────────────────────────────────────────────────────────────┘    │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐    │
│  │  IMPLANT  (agent/)                                               │    │
│  │  syscall (Hell's Gate/Halo's Gate) | injection | stealth         │    │
│  │  credtheft | exfil | persistence | lateral | cleanup | audit     │    │
│  └──────────────────────────────────────────────────────────────────┘    │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐    │
│  │  VALIDATION  (arena/ + tests/)                                   │    │
│  │  Arena cognitive evaluation · 88 regression tests · SENTINEL     │    │
│  └──────────────────────────────────────────────────────────────────┘    │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐    │
│  │  SERVICES                                                       │    │
│  │  cli/  sword/  c2-server/  cai-service/  cloak-service/         │    │
│  │  kali-tools/  phishing/  recon-pipeline/  mcp-hub/              │    │
│  │  sliver/  mhddos-service/  bridge/                              │    │
│  └──────────────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## D-Series — The Brain (`orchestrator/brain/`)

The Brain is the cognitive core. It perceives the target environment, plans actions, authorizes execution, and resolves contradictions in its belief state.

### Cognitive Loop

```
  ┌──────────┐     ┌──────────────┐     ┌───────────┐     ┌──────────────┐
  │  Student  │────>│  Candidate   │────>│  Planner  │────>│ Capability   │
  │ (S-Series)│     │  Generator   │     │ (scoring) │     │ Broker       │
  └──────────┘     └──────────────┘     └───────────┘     └──────┬───────┘
         ^                                                        │
         │                                                        v
  ┌──────┴───────┐     ┌──────────────┐     ┌───────────┐     ┌──────────┐
  │ WorldModel   │<────│  Evidence    │<────│ Interactive│<────│ Authorized│
  │ + Entities   │     │  Ingestion   │     │ Shell      │     │ Action    │
  └──────────────┘     └──────────────┘     └───────────┘     └──────────┘
```

| Module | Description |
|--------|-------------|
| `action.py` | Action planner — scores candidates (shell, recon, exploit) by utility/cost/risk. Rationale codes drive transparency. |
| `world.py` | WorldModel — entity store with 20+ `EntityType`s (HOST, PORT, SERVICE, PROCESS, FILE, CREDENTIAL, VULNERABILITY, etc.) and 15+ `RelationshipType`s. Factory functions for evidence ingestion. |
| `capability_broker.py` | Brokered authorization — dual-gate for shell sessions (connection + per-command), termination, cleanup. Extended with P1 RateLimiter, ScopeParser, PayloadMutator, and Student integration. |
| `candidate_generators/` | Generates action candidates from triggers: `shell_generator.py` (E2) for T1/T2/T3 shell triggers + M1/M2 command proposals; `student_generator.py` for technique proposals from S-Series (with P1 WAF-aware confidence adjustments). |
| `contradiction.py` | ContradictionManager — detects `CONTRADICTS` relationships between evidence, generates falsification tasks for continuous belief resolution. |
| `evidence.py` | Evidence dataclass — captures observations with type, content, confidence, source. 8 shell-specific evidence types + `waf_blocked` type. |
| `hypothesis.py` | Hypothesis generation — forms conjectures from partial evidence patterns. |
| `reasoning.py` | Reasoning engine — multi-step inference over WorldModel entities and relationships. |
| `reflection.py` | Post-engagement reflection — updates strategy weights, prunes stale beliefs. |
| `strategy.py` / `strategy_learner.py` | Adaptive strategy selection — learns which action types succeed in which target profiles. |
| `target_profiler.py` / `target_state.py` | Target profiling — builds constraint vectors, tracks owned vs. unknown affordances. |
| `trust.py` | Trust engine — scores evidence sources by reliability, weights evidence confidence. |
| `neural_memory.py` | Neural memory — episodic case-based reasoning for pattern recall. |
| `skill_indexer.py` | Skill indexer — maps technique names to capability implementations. |
| `adaptive_brain.py` | Adaptive brain — orchestrates the cognitive loop with dynamic cadence. |
| `phases/` | Phase-specific executors: CICD pipeline poisoning, cloud abuse, container escape, ML model attack. Each phase has a plan→authorize→execute→ingest lifecycle. |
| `scope_parser.py` | **P1-SS-01** — HackerOne JSON/Markdown scope parsing. Wildcard domains, CIDR, exclusions, URL-path prefixes. Fail-closed on ambiguous targets. |
| `rate_limiter.py` | **P1-SS-02** — Per-target + global rate limiting. Configurable jitter (5-15s), emergency brake, shell keepalive bypass. Async-safe with `asyncio.Lock`. |
| `waf_detector.py` | **P1-SS-03** — 7 WAF signature fingerprints (Cloudflare, ModSecurity, AWS WAF, F5, Akamai, Sucuri, Wordfence). Benign probe-based detection with 5-min TTL cache. |

---

## S-Series — The Student (`orchestrator/student/`)

The Student continuously researches the threat landscape and proposes operational techniques to the Brain. It never executes — it only advises.

| Module | Description |
|--------|-------------|
| `research_scheduler.py` | Cron-driven research of CVE feeds, GitHub PoCs, security blogs. Categorizes findings by target stack. |
| `chain_synthesizer.py` | Synthesizes multi-step attack chains from atomic technique descriptions. Produces ranked proposals for the Planner. |
| `knowledge_background_service.py` | Persistent background service maintaining a technique knowledge base with versioning, dependencies, and success metrics. |
| `coverage_gap_filler.py` | Analyzes coverage gaps between known techniques and target profile. Probes research sources for missing technique variants. |
| `stack_matcher.py` | Matches target software stack (nginx 1.2, PostgreSQL 15, etc.) to known CVEs and technique applicability. |
| `scihub.py` | Scientific paper ingestion — parses PDF research papers for technique extraction. |
| `integration_pipeline.py` | End-to-end pipeline: research → categorize → synthesize → propose to Planner. |
| `payload_mutator.py` | **P1-SS-04** — 7 deterministic mutation methods (case variation, comment injection, encoding, whitespace, unicode, parameter pollution, boundary) + LLM-based fuzzing. WAF-specific strategy maps. Max 3 mutation rounds. |
| `student.py` | `Student` class — WAF-aware `technique_proposer()` delegates to WAFDetector before candidate generation. `propose_mutations()` wraps PayloadMutator for WAF-blocked command retry. |

**Student→Brain integration:** The Student submits `technique_proposal` candidates to the CandidateGenerator pool. The Planner scores these alongside shell candidates and recon actions. Accepted techniques are ingested into the WorldModel as `TECHNIQUE` entities. WAF detection results from P1 flow through StudentGenerator to tag candidates with `waf_type`, `waf_confidence`, and adjusted confidence scores.

---

## E-Series — The Hands (`orchestrator/capabilities/interactive_shell/`)

The Hands provide stateful, interactive shell execution within a strict brokered envelope.

| Module | Description |
|--------|-------------|
| `capability.py` | `InteractiveShellCapability` ABC — contract for all shell implementations. |
| `ssh_shell.py` | `SSHShellCapability` — SSH connection with key-based or password auth, TTY normalization, keep-alive. |
| `reverse_shell.py` | `ReverseShellCapability` — reverse TCP shell accepts pre-attached client sockets from ListenerManager. |
| `session.py` / `session_store.py` | `ShellSession` state machine (PENDING→ACTIVE→TERMINATED) + `ShellSessionStore` with SQLite persistence, temp-fallback. |
| `command_filter.py` | Two-tier command filter: T1 static allowlist/blocklist (34 safe commands) + T2 LLM classifier for ambiguous commands. Shell injection chars (`;`, `\|`, `&`, `` ` ``) cause ESCALATE not DENY. |
| `listener_manager.py` | `ListenerManager` — Broker-exclusive reverse shell listener provisioning. No component bypasses this. |
| `tty_normalizer.py` | `TTYNormalizer` + `EvidenceExtractor` — normalizes raw TTY output, extracts 8 evidence types (process lists, file contents, network connections, credentials, etc.) for WorldModel ingestion. |

### Authorization Model (Dual-Gate)

```
  ┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
  │  shell_connect   │────>│ authorize_shell_ │────>│ Session Created  │
  │  candidate       │     │ session()        │     │ (ACTIVE)         │
  └──────────────────┘     └──────────────────┘     └──────────────────┘
                                                                │
                                                        ┌───────┴───────┐
                                                        │   Per-command  │
                                                        │   Authorization │
                                                        └───────┬───────┘
                                                                │
  ┌──────────────────┐     ┌──────────────────┐     ┌───────────┘
  │  shell_command   │────>│ authorize_shell_ │────>│ T1 Filter (allow/
  │  candidate       │     │ command()        │     │ block/injection)
  └──────────────────┘     └──────────────────┘     └───────┬──────────┐
                                                    ESCALATE?           │
                                                        │              DENY
                                                        v
  ┌──────────────────┐     ┌──────────────────┐                         │
  │ T2 LLM Classifier│────>│ Authorized /      │<────────────────────────┘
  │ (Gemma 31B)      │     │ Denied            │
  └──────────────────┘     └──────────────────┘
```

### Evidence Feedback Loop

Every shell command output is processed by `TTYNormalizer` → `EvidenceExtractor` → `WorldModel.ingest_shell_evidence()` → 8 entity types (PROCESS, FILE, CREDENTIAL, VULNERABILITY, etc.) with relationships. Contradictions against prior beliefs generate `FalsificationTasks`.

---

## Arena — Cognitive Evaluation Framework (`arena/`)

Arena provides end-to-end validation of Raphael's cognitive capabilities using controlled scenarios with known ground truth.

| Module | Description |
|--------|-------------|
| `runner.py` | Ablation runner — orchestrates Raphael instances with configurable component masking (FULL, NO_LLM, NO_STUDENT, etc.) |
| `environment.py` | Scenario environment — sandboxed target simulation with predefined vulnerabilities. |
| `episode.py` | Single evaluation episode — one Raphael instance × one scenario × N action rounds. |
| `evaluator.py` | Outcome evaluation — truth comparison, pass/fail determination, metric aggregation. |
| `conclusion.py` / `conclusion_adapters.py` / `conclusion_evaluator.py` | Evidence-weighted conclusion reasoning. |
| `defeater.py` | Adversarial defeater — tests Raphael's robustness against contradictions and false leads. |
| `ablation.py` | Ablation study orchestrator — runs full matrix of component combinations. |
| `d6_manifest.py` through `d13_diagnostic_runner.py` | D-series regression diagnostics — 10 suites covering D3 through D13. |
| `scenarios/` | 5 scenario definitions: known open port, vulnerability with noise, false lead, contradictory observations, forbidden resource. |

**Tests:** `tests/` contains 88 regression tests: 34 E1 (shell), 36 E2 (candidate gen), 7 Stage 1 invariants, 10 D5 preflight, 1 D5 seven-gate proof. All passing.

---

## Core Infrastructure (`orchestrator/`)

| Module | Description |
|--------|-------------|
| `harvester/` | CVE feed ingestion, GitHub PoC scraping, technique extraction |
| `mesh/` | P2P gossip protocol, encrypted routing, peer discovery |
| `privesc/` | 27 LPE vectors, auto-updating GTFOBins/LOLBAS |
| `propagation/` | Subnet discovery, TCP scanning, credential reuse |
| `social/` | Target recon, LLM lure generation, credential harvesting |
| `survivability/` | Snapshots, integrity checks, kill switches, auto-update |
| `weaponizer/` | C/Go/Rust compilation, UPX packing, AES encryption |
| `ttp_playbook/` | 6 adversary-profiled attack chains |
| `cicd/` | CI/CD pipeline poisoning: token harvesting, runner fingerprinting, workflow parser |
| `cloud_abuse/` | Cloud exploitation: API gateway abuse, IAM pathfinding, metadata service abuse, cloud enumeration |
| `ml_attack/` | ML supply chain attacks: HF Hub API client, pickle payload factory, model format analyzer |
| `container_escape/` | Container breakout: Docker escape, K8s escape, sandbox detection |
| `hardening/` | Action receipt generation for post-engagement hardening analysis |
| `validation/` | Exploit validator — checks exploit preconditions against target profile |

---

## Implant (`agent/`)

Multi-platform implant with OPSEC-hardened modules:

| Module | Techniques |
|--------|-----------|
| `syscall.py` | Hell's Gate + Halo's Gate indirect syscall resolution |
| `inject.py` | Process injection via indirect syscalls, PPID spoofing |
| `stealth.py` | HWBP AMSI bypass, ETW-TI suppression, sleep mask, stack spoofing |
| `credtheft.py` | Chrome Linux key decryption, LSASS, SAM, browser harvest |
| `exfil.py` | DNS tunnel, HTTPS camouflage, ICMP tunnel, cloud storage |
| `persistence.py` | systemd, cron, LD_PRELOAD, Registry, WMI, Scheduled Tasks |
| `lateral.py` | SSH, WMI, PSExec, SMB, WinRM, Docker, MSSQL |
| `cleanup.py` | Log wiping (journald, auditd, wevtutil, macOS log) |
| `audit.py` | Security audit of implant configuration and dependencies |

## CLI (cli/)

TypeScript/Bun-based CLI with OpenClaude integration:

- 9 command dialogs: autonomous, brain, c2, community, debate, deep-research, exploit, harvester, kali
- 3 personas: stealth, aggressive (z3r0), full-spectrum (ghost)
- Raphael orchestrator provider with SSE streaming
- 6 pentest tools: nmap, sqlmap, bloodhound, metasploit, crackmapexec, chisel

## Services

| Service | Port | Description |
|---------|------|-------------|
| `cai-service/` | 3201 | LLM AI orchestration (Ollama/OpenAI) |
| `mhddos-service/` | 3301 | DDoS simulation engine |
| `cloak-service/` | 3401 | Traffic cloaking & proxy chaining (Tor) |
| `c2-server/` | 3501 | C2 implant management (Sliver) |
| `phishing/` | 3502 | Phishing campaign manager (Gophish) |
| `recon-pipeline/` | 3503 | Automated reconnaissance (Shodan/Spiderfoot) |
| `sword/` | 3600 | Main orchestration engine |
| `kali-tools/` | 3800 | Kali toolset wrapper (netexec, nmap, etc.) |
| `mcp-hub/` | - | MCP server with HMAC auth |
| `bridge/` | - | Python↔TypeScript bridge |

## Quick Start

```bash
# Clone and configure
cp .env.example .env
# Edit .env — set at minimum: TOR_CONTROL_PASS, API_KEY, LLM_PROVIDER

# Build and start
docker compose build
docker compose up -d

# Check health
curl http://localhost:3900/health

# Run the full cognitive agent (Python 3.11+)
pip install -r requirements.txt
python -m arena.runner --mode full --target <target>

# Run with specific components
python -m arena.runner --mode ablation                  # Run ablation studies
python -m arena.ablation --scenario 001_known_open_port # Single scenario test

# Run the brain directly
python -m orchestrator.modes.autonomous --target <target>

# Run tests
python -m pytest tests/ -v                              # All 88 regression tests
python -m pytest tests/e2_shell_candidate_generation_test.py -v  # E2 only (36 tests)

# Run SENTINEL audit
python JUDGE.py                                         # Codebase governance check

# Interactive shell capability test
python -m pytest tests/e1_interactive_shell_test.py -v  # E1 only (34 tests)
```

## Validation Status

| Series | Tests | Status | SENTINEL |
|--------|-------|--------|----------|
| D-Series Brain | Stage 1 invariants (7), D5 preflight (10), D5 gate proof (1) | ✅ 18/18 | ✅ Frozen |
| E1 Interactive Shell | Session lifecycle, auth, filter, TTY (34) | ✅ 34/34 | ✅ Sealed |
| E2 Shell Candidate Gen | T1/T2/T3 triggers, M1/M2 proposals, invariants (36) | ✅ 36/36 | ✅ Accepted |
| D-Series Arena | D3–D13 regression diagnostics (10 suites) | ✅ All pass | ✅ Verified |
| P1 Stealth & Evasion | ScopeParser (7), RateLimiter (7), WAFDetector (6), PayloadMutator (all) | ✅ All pass | ✅ Sealed |
| P1 Integration | CapabilityBroker + P1 modules (6) | ✅ 6/6 | ✅ Verified |
| P1 Operational Val. | WAF Bypass Arena (Target-05) | ✅ 37/37 | ✅ FLAG=SUCCESS |
| **Total** | **158 regression + integration + operational tests** | **✅ 158/158** | **🛡️ Governance locked** |

---

## P-Series — Stealth & Evasion (`orchestrator/brain/`, `orchestrator/student/`)

P1 adds four stealth and evasion modules that harden Raphael against operational detection. These integrate into the existing CapabilityBroker authorization flow without modifying core D-Series logic.

| Module | Location | Description |
|--------|----------|-------------|
| **P1-SS-01 ScopeParser** | `orchestrator/brain/scope_parser.py` | Parses HackerOne JSON/Markdown scope definitions. Supports wildcard domains, CIDR notation, exclusions, URL-path prefixes. Fail-closed — ambiguous or out-of-scope targets are denied. Self-test: 7/7. |
| **P1-SS-02 RateLimiter** | `orchestrator/brain/rate_limiter.py` | Per-target + global rate tracking with configurable jitter (5-15s default). Emergency brake halts all actions when anomaly threshold exceeded. Shell keepalive heartbeat bypasses limiter. Async-safe with `asyncio.Lock`. Self-test: 7/7. |
| **P1-SS-03 WAFDetector** | `orchestrator/brain/waf_detector.py` | Fingerprints 7 WAF types (Cloudflare, ModSecurity, AWS WAF, F5 ASM, Akamai, Sucuri, Wordfence) via benign probe responses. Cached per target with 5-min TTL. Self-test: 6/6. |
| **P1-SS-04 PayloadMutator** | `orchestrator/student/payload_mutator.py` | 7 deterministic mutation methods (case, comment injection, encoding, whitespace, unicode, parameter pollution, boundary) plus LLM-based fuzzing. WAF-specific strategy selection. Max 3 rounds. |

### Integration Architecture

```
  ┌──────────────┐    ┌─────────────┐    ┌────────────────┐
  │  WAFDetector  │───>│   Student   │───>│ PayloadMutator │
  │  (fingerprint)│    │(technique   │    │ (7 mutations)  │
  └──────────────┘    │ proposer)   │    └────────────────┘
                      └──────┬──────┘
                             │ waf_info
  ┌──────────────┐    ┌──────▼──────┐    ┌────────────────┐
  │  ScopeParser  │───>│ Capability  │───>│  RateLimiter   │
  │  (fail-closed)│    │ Broker      │    │ (5-15s jitter) │
  └──────────────┘    └─────────────┘    └────────────────┘
```

### H1 Live Engagement Spec

| Parameter | Value |
|-----------|-------|
| **Target** | Nextcloud 34.0.2 (Local Docker, 172.18.0.20) |
| **Spec** | `H1_LIVE_ENGAGEMENT_SPEC.json` (SEALED) |
| **Stack** | Apache 2.4.68 + PHP 8.5.8 + MariaDB 10.11 |
| **Accounts** | admin:admin_password, operator:operator_password |
| **Scope** | 172.18.0.0/16 (fail-closed) |
| **Rate Limit** | 10-20s jitter |
| **Max Actions** | 20 per engagement |
| **Policy Constraints** | No destructive actions, all HTTP responses stored as Evidence |

## Operational Security

- **Do not run on personal/work machines.** Raphael modifies network config, installs kernel modules, and generates traffic that triggers alarms.
- **Default credentials are placeholders.** Validate with `scripts/validate_env.py`.
- **CDN fronting and TLS SNI spoofing** use placeholder domains — configure your own fronting infra.
- **Agent communications** are encrypted. Set `EGRESS_VERIFY_CERT=true` for MITM protection.
- **Logs** capture C2 traffic at DEBUG level. Commands matching `REDACT_PATTERNS` are redacted.
- **Shell sessions** are dual-gate authorized (connection + per-command) with auto-termination on 3 denials in 60s.
- **Reverse shell listeners** are Broker-exclusive — no component can provision a listener bypassing CapabilityBroker.

## Key Design Decisions

- **Four-series cognitive architecture** — D-Series (Brain) plans and falsifies, S-Series (Student) researches and advises, E-Series (Hands) executes within brokered envelope, P-Series (Phantom) provides stealth and evasion across all layers
- **No unbrokered execution path** — every shell action passes through `authorize_shell_session()` + `authorize_shell_command()`
- **Shell injection chars cause ESCALATE, not DENY** — `;`, `|`, `&`, `` ` `` trigger Tier 2 LLM classification rather than blind rejection
- **Evidence drives cognition** — 8 shell evidence types continuously ingested into WorldModel, contradictions generate falsification tasks
- **Candidate generation is trigger-based** — T1 credential discovery, T2 exploit confirmation, T3 student advisory — each produces `shell_connect` candidates
- **Brain is never idle** — when no technique executable → ModelRefiner ∥ Hypothesizer → heuristic fallback → report stuck
- **Memory is episodic** — full narratives via case-based reasoning in WorldModel
- **Student is read-only** — it proposes techniques but never executes. All operations are brokered.

## Legal & Ethical Use

This software is intended for **authorized security testing only**. You must:
1. Have written permission from the target system owner
2. Comply with all applicable laws (CFAA, Computer Misuse Act, etc.)
3. Never use against systems you do not own or have explicit permission to test
