# Architecture — Project Raphael v2.0

> **Purpose**: Complete system architecture specification. Append-only per SENTINEL §42.

---

## 1. System Overview

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                        RAPHAEL COGNITIVE AGENT v2.0                          │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │  D-SERIES — BRAIN  (src/orchestrator/brain/)                           │  │
│  │  ┌──────────┐  ┌────────────┐  ┌───────────┐  ┌────────────────────┐  │  │
│  │  │ Planner  │  │ WorldModel │  │Capability │  │ Falsification Mgr  │  │  │
│  │  │ (action) │  │  (world)   │  │  Broker   │  │                    │  │  │
│  │  └──────────┘  └────────────┘  └───────────┘  └────────────────────┘  │  │
│  │  ┌──────────┐  ┌────────────┐  ┌───────────┐  ┌────────────────────┐  │  │
│  │  │Candidate │  │ Contradict │  │Reflection │  │  Strategy Learner  │  │  │
│  │  │Generator │  │ Detection  │  │ Engine    │  │                    │  │  │
│  │  └──────────┘  └────────────┘  └───────────┘  └────────────────────┘  │  │
│  │  ┌──────────────┐  ┌────────────┐  ┌──────────────┐                   │  │
│  │  │  RateLimiter │  │ScopeParser │  │ WAFDetector  │  ← P1 Stealth    │  │
│  │  │   (SS-02)    │  │   (SS-01)  │  │   (SS-03)    │                   │  │
│  │  └──────────────┘  └────────────┘  └──────────────┘                   │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │  S-SERIES — STUDENT  (src/orchestrator/student/)                        │  │
│  │  ┌────────────────┐  ┌────────────────┐  ┌──────────────────────────┐  │  │
│  │  │ Research       │  │ Chain          │  │ Knowledge                │  │  │
│  │  │ Scheduler      │  │ Synthesizer    │  │ Background Service       │  │  │
│  │  └────────────────┘  └────────────────┘  └──────────────────────────┘  │  │
│  │  ┌────────────────┐  ┌────────────────┐  ┌──────────────────────────┐  │  │
│  │  │ Coverage Gap   │  │ Stack          │  │ PayloadMutator           │  │  │
│  │  │ Filler         │  │ Matcher        │  │ (SS-04)                  │  │  │
│  │  └────────────────┘  └────────────────┘  └──────────────────────────┘  │  │
│  │  ┌────────────────┐                                                 │  │
│  │  │ Student        │  ← WAF-aware technique proposer, mutation proxy │  │
│  │  └────────────────┘                                                 │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │  E-SERIES — HANDS  (src/orchestrator/capabilities/interactive_shell/)   │  │
│  │  ┌────────────────┐  ┌────────────────┐  ┌──────────────────────────┐  │  │
│  │  │ SSH Shell      │  │ Reverse Shell  │  │ Command Filter           │  │  │
│  │  │ Capability     │  │ Capability     │  │ Pipeline (T1+T2)         │  │  │
│  │  └────────────────┘  └────────────────┘  └──────────────────────────┘  │  │
│  │  ┌────────────────┐  ┌────────────────┐  ┌──────────────────────────┐  │  │
│  │  │ Shell Session  │  │ TTY Normalizer │  │ Listener                 │  │  │
│  │  │ Store          │  │ + Evidence Ext │  │ Manager (Broker)         │  │  │
│  │  └────────────────┘  └────────────────┘  └──────────────────────────┘  │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │  CORE INFRASTRUCTURE  (src/orchestrator/)                               │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌───────────┐              │  │
│  │  │Harvester │  │ Mesh     │  │Privesc   │  │Propagation│              │  │
│  │  │(CVE feed)│  │(P2P net) │  │(27 LPE)  │  │(lateral)  │              │  │
│  │  └──────────┘  └──────────┘  └──────────┘  └───────────┘              │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌───────────┐              │  │
│  │  │Weaponizer│  │Social    │  │Survivabil│  │CICD/Cloud │              │  │
│  │  │(C/Go/Rust)│ │(phish)   │  │(kill sw) │  │/ML Attack │              │  │
│  │  └──────────┘  └──────────┘  └──────────┘  └───────────┘              │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌───────────┐              │  │
│  │  │Container │  │Hardening │  │Action    │  │Validation │              │  │
│  │  │Escape    │  │(kill sw) │  │Receipts  │  │(exploit)  │              │  │
│  │  └──────────┘  └──────────┘  └──────────┘  └───────────┘              │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │  IMPLANT  (src/agent/)                                                 │  │
│  │  syscall (Hell's Gate/Halo's Gate) | injection | stealth              │  │
│  │  credtheft | exfil | persistence | lateral | cleanup | audit           │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. D-Series — The Brain (`src/orchestrator/brain/`)

### 2.1 Core Modules

| Module | Responsibility |
|--------|----------------|
| `action.py` | Action planner — scores candidates by utility/cost/risk; rationale codes for transparency |
| `world.py` | WorldModel — entity store (20+ `EntityType`s, 15+ `RelationshipType`s); factory functions for evidence ingestion |
| `capability_broker.py` | Brokered authorization — dual-gate shell sessions (connection + per-command); reverse shell listeners exclusive to Broker; P1 modules integrated |
| `candidate_generators/` | `shell_generator.py` (E2): T1/T2/T3 triggers + M1/M2 proposals; `student_generator.py`: S-Series technique proposals |
| `contradiction.py` | ContradictionManager — detects `CONTRADICTS` relationships; generates falsification tasks |
| `evidence.py` | Evidence dataclass — 8 shell-specific evidence types + `waf_blocked` |
| `hypothesis.py` | Hypothesis generation from partial evidence patterns |
| `reasoning.py` | Multi-step inference over WorldModel entities/relationships |
| `reflection.py` | Post-engagement reflection — strategy weight updates, belief pruning |
| `strategy.py` / `strategy_learner.py` | Adaptive strategy selection with learning |
| `target_profiler.py` / `target_state.py` | Target profiling — constraint vectors, owned vs unknown affordances |
| `trust.py` | Trust engine — scores evidence source reliability, weights confidence |
| `neural_memory.py` | Episodic memory — case-based reasoning for pattern recall |
| `skill_indexer.py` | Technique → capability mapping |
| `adaptive_brain.py` | Orchestrates cognitive loop with dynamic cadence |
| `phases/` | Phase executors: CICD, cloud abuse, container escape, ML attack |

### 2.2 P1 Stealth Modules (Integrated into CapabilityBroker)

| Module | File | Function |
|--------|------|----------|
| **ScopeParser (SS-01)** | `scope_parser.py` | HackerOne JSON/Markdown scope parsing; wildcard domains, CIDR, exclusions, URL-path prefixes; fail-closed |
| **RateLimiter (SS-02)** | `rate_limiter.py` | Per-target + global tracking; configurable jitter (5-15s); emergency brake; shell keepalive heartbeat; async-safe with `asyncio.Lock` |
| **WAFDetector (SS-03)** | `waf_detector.py` | 7 signatures (Cloudflare, ModSecurity, AWS WAF, F5, Akamai, Sucuri, Wordfence); benign probes; 5-min TTL cache |
| **PayloadMutator (SS-04)** | `payload_mutator.py` | 7 deterministic methods (case, comment, encoding, whitespace, unicode, param pollution, boundary) + LLM mutation; WAF-specific strategy maps; max 3 rounds |

---

## 3. S-Series — The Student (`src/orchestrator/student/`)

| Module | Responsibility |
|--------|----------------|
| `research_scheduler.py` | Cron-driven CVE feed, GitHub PoC, security blog research; stack categorization |
| `chain_synthesizer.py` | Multi-step attack chain synthesis from atomic techniques; ranked Planner proposals |
| `knowledge_background_service.py` | Persistent technique KB with versioning, dependencies, success metrics |
| `coverage_gap_filler.py` | Coverage gap analysis between known techniques and target profile |
| `stack_matcher.py` | Stack (nginx 1.2, PostgreSQL 15, etc.) → CVE/technique applicability matching |
| `scihub.py` | PDF research paper ingestion for technique extraction |
| `integration_pipeline.py` | End-to-end: research → categorize → synthesize → propose to Planner |
| `payload_mutator.py` | **P1-SS-04** — 7 deterministic mutations + LLM; WAF strategy maps; max 3 rounds |
| `student.py` | **Student class** — WAF-aware `technique_proposer()` (delegates to WAFDetector); `propose_mutations()` wraps PayloadMutator |

**Integration**: Student submits `technique_proposal` candidates to CandidateGenerator pool. Planner scores alongside shell/recon candidates. Accepted techniques ingested as `TECHNIQUE` entities in WorldModel.

---

## 4. E-Series — The Hands (`src/orchestrator/capabilities/interactive_shell/`)

| Module | Description |
|--------|-------------|
| `capability.py` | `InteractiveShellCapability` (ABC) — contract for all shells |
| `ssh_shell.py` | `SSHShellCapability` — SSH with key/password auth, TTY normalization, keep-alive |
| `reverse_shell.py` | `ReverseShellCapability` — accepts pre-attached client sockets from ListenerManager |
| `session.py` / `session_store.py` | `ShellSession` state machine (PENDING→ACTIVE→TERMINATED) + SQLite persistence |
| `command_filter.py` | Two-tier: T1 static allowlist/blocklist (34 safe commands) + T2 LLM classifier; shell injection chars (`;`, `\|`, `&`, `` ` ``) cause ESCALATE not DENY |
| `listener_manager.py` | `ListenerManager` — Broker-exclusive reverse shell listener provisioning |
| `tty_normalizer.py` | `TTYNormalizer` + `EvidenceExtractor` — normalizes raw TTY, extracts 8 evidence types |

### Authorization Model (Dual-Gate)

```
shell_connect candidate  ──► authorize_shell_session() ──► Session Created (ACTIVE)
                                                               │
                                        ┌──────────────────────┘
                                        ▼
                               Per-command Authorization
                                        │
                    ┌───────────────────┴───────────────────┐
                    ▼                                       ▼
                    T1 Filter                        T2 LLM Classifier
                    (allow/block/                     (Gemma 31B)
                    injection→ESCALATE)               │
                    │                                ▼
                    │                     Authorized / Denied
                    ▼
            ESCALATE?
                    │
                    ▼
            T2 LLM Classifier ──► Authorized / Denied
```

**No unbrokered execution path** — every shell action passes through `authorize_shell_session()` + `authorize_shell_command()`.

### Evidence Feedback Loop

Every shell command output → `TTYNormalizer` → `EvidenceExtractor` → `WorldModel.ingest_shell_evidence()` → 8 entity types (PROCESS, FILE, CREDENTIAL, VULNERABILITY, etc.) with relationships → Contradictions generate `FalsificationTasks`.

---

## 5. P-Series — Stealth & Evasion

| Module | Location | Description |
|--------|----------|-------------|
| **ScopeParser** | `orchestrator/brain/scope_parser.py` | HackerOne JSON/Markdown scope; wildcards, CIDR, exclusions, URL-path prefixes; fail-closed |
| **RateLimiter** | `orchestrator/brain/rate_limiter.py` | Per-target + global; jitter 5-15s; emergency brake; shell keepalive (raw `\n` to PTY); async-safe |
| **WAFDetector** | `orchestrator/brain/waf_detector.py` | 7 signatures via benign probes; 5-min TTL cache |
| **PayloadMutator** | `orchestrator/student/payload_mutator.py` | 7 deterministic + LLM; WAF strategy maps; max 3 rounds |

**Integration**: All four plug into CapabilityBroker authorization flow without modifying D-Series core.

---

## 6. Agent Implant (`src/agent/`)

| Module | Techniques |
|--------|------------|
| `syscall.py` | Hell's Gate + Halo's Gate indirect syscall resolution |
| `inject.py` | Process injection via indirect syscalls, PPID spoofing |
| `stealth.py` | HWBP AMSI bypass, ETW-TI suppression, sleep mask, stack spoofing |
| `credtheft.py` | Chrome Linux key decryption, LSASS, SAM, browser harvest |
| `exfil.py` | DNS tunnel, HTTPS camouflage, ICMP tunnel, cloud storage |
| `persistence.py` | systemd, cron, LD_PRELOAD, Registry, WMI, Scheduled Tasks |
| `lateral.py` | SSH, WMI, PSExec, SMB, WinRM, Docker, MSSQL |
| `cleanup.py` | Log wiping (journald, auditd, wevtutil, macOS log) |
| `audit.py` | Security audit of implant configuration and dependencies |

---

## 6. Services

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

---

## 7. Cognitive Loop

```
┌──────────┐     ┌──────────────┐     ┌───────────┐     ┌──────────────┐
│ Student  │────►│ Candidate    │────►│ Planner   │────►│ Capability   │
│ (S-Series)│     │ Generator    │     │ (scoring) │     │ Broker       │
└──────────┘     └──────────────┘     └───────────┘     └──────┬───────┘
       ▲                                                         │
       │                                                         ▼
┌──────┴───────┐     ┌──────────────┐     ┌───────────┐     ┌──────────┐
│ WorldModel   │◄────│  Evidence    │◄────│ Interactive│◄────│ Authorized│
│ + Entities   │     │  Ingestion   │     │  Shell     │     │  Action  │
└──────────────┘     └──────────────┘     └───────────┘     └──────────┘
```

1. **Student** proposes techniques based on target stack
2. **CandidateGenerator** produces action candidates (shell, recon, technique)
3. **Planner** scores by utility/cost/risk with rationale codes
4. **CapabilityBroker** authorizes (dual-gate for shells) with RateLimiter/ScopeParser
5. **InteractiveShell** executes → output normalized → EvidenceExtractor → WorldModel
6. **ContradictionManager** detects conflicts → FalsificationTasks → Student refines

---

## 8. Data Flow

```
Target → Recon → Stack Fingerprint → Student Proposes Techniques
    │
    ▼
CandidateGenerator (T1/T2/T3 triggers + Student) → Candidates
    │
    ▼
Planner (utility/cost/risk + rationale) → Ranked Actions
    │
    ▼
CapabilityBroker (ScopeParser + RateLimiter + PayloadMutator) → Authorize/Deny
    │
    ▼
InteractiveShell (SSH/Reverse) → Command Execution
    │
    ▼
TTYNormalizer → EvidenceExtractor → WorldModel.ingest_shell_evidence()
    │
    ▼
ContradictionManager → FalsificationTasks → Student Refines
```

---

## 8. Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| **Three-series cognitive architecture** | D-Series plans/falsifies, S-Series researches/advises, E-Series executes within brokered envelope |
| **No unbrokered execution path** | Every shell action passes through `authorize_shell_session()` + `authorize_shell_command()` |
| **Shell injection chars cause ESCALATE, not DENY** | `;`, `\|`, `&`, `` ` `` trigger Tier 2 LLM classification rather than blind rejection |
| **Evidence drives cognition** | 8 shell evidence types continuously ingested; contradictions generate falsification tasks |
| **Candidate generation is trigger-based** | T1 credential discovery, T2 exploit confirmation, T3 student advisory — each produces `shell_connect` |
| **Brain is never idle** | When no technique executable → ModelRefiner ∥ Hypothesizer → heuristic fallback → report stuck |
| **Memory is episodic** | Full narratives via case-based reasoning in WorldModel |
| **Student is read-only** | Proposes techniques but never executes. All operations brokered. |
| **P1 modules are broker extensions** | ScopeParser, RateLimiter, WAFDetector, PayloadMutator integrate into Broker auth flow without modifying D-Series core |

---

## 9. Legal & Ethical Use

This software is intended for **authorized security testing only**. You must:
1. Have written permission from the target system owner
2. Comply with all applicable laws (CFAA, Computer Misuse Act, etc.)
3. Never use against systems you do not own or have explicit permission to test

---

*Architecture frozen at v2.0 — No cognitive architecture modifications authorized on v2.x branch.*
