# Decision Log — Project Raphael v2.0

> **Purpose**: Immutable record of all architectural, procedural, and strategic decisions. Each entry is append-only and must reference the charter section authorizing it.

---

## D-001: Three-Series Cognitive Architecture (2026-07-15)
**Status**: ACCEPTED  
**Charter Ref**: §24, §43  
**Decision**: Separate Raphael into three concurrent series:
- **D-Series (Brain)**: Planning, WorldModel, CapabilityBroker, Falsification
- **S-Series (Student)**: Research, ChainSynthesis, KnowledgeBase
- **E-Series (Hands)**: InteractiveShell, SSH, ReverseShell, CommandFilter
**Rationale**: Prevents single-point-of-failure in reasoning; enforces brokered execution; enables independent validation per series.
**Impact**: All subsequent modules must declare their series affiliation.

---

## D-002: Brokered Authorization Envelope (2026-07-16)
**Status**: ACCEPTED & SEALED (E1)  
**Charter Ref**: §24, §58  
**Decision**: All shell execution must pass through CapabilityBroker via dual-gate:
1. `authorize_shell_session()` — connection-level
2. `authorize_shell_command()` — per-command
**Rationale**: No component may execute shell commands without explicit broker authorization. Reverse shell listeners provisioned exclusively by ListenerManager.
**Impact**: Frozen E1 shell package (8 files, ~2900 lines).

---

## D-003: Candidate Generation Triggers (2026-07-18)
**Status**: ACCEPTED & SEALED (E2)  
**Chart Ref**: §43, §49  
**Decision**: Three trigger tiers for shell candidates:
- **T1**: Credential Discovery → `shell_connect`
- **T2**: Exploit Confirmation → `shell_connect`  
- **T3**: Student Advisory → `shell_connect`
**Rationale**: Ensures every shell action has traceable causal origin in cognitive loop.
**Impact**: E2 ShellCandidateGenerator (589 lines) sealed; 36 tests passing.

---

## D-004: P1 Stealth & Evasion Modules (2026-07-25)
**Status**: ACCEPTED & SEALED  
**Charter Ref**: §30, §35, §49, §58  
**Decision**: Four stealth modules integrated into CapabilityBroker:
- **ScopeParser (SS-01)**: HackerOne JSON/Markdown parsing, fail-closed
- **RateLimiter (SS-02)**: Per-target jitter (5-15s), emergency brake, shell keepalive
- **WAFDetector (SS-03)**: 7 signatures, benign probe fingerprinting, 5-min TTL
- **PayloadMutator (SS-04)**: 7 deterministic mutations + LLM, max 3 rounds
**Rationale**: Operational stealth required for live engagements; must not modify D-Series core.
**Impact**: 158/158 tests passing; integrated into Broker authorization flow.

---

## D-005: Three-Tier Evaluation Framework (2026-07-29)
**Status**: ACCEPTED  
**Charter Ref**: §30, §35, §49, §58, §60  
**Decision**: Three-tier progression for live engagements:
- **Tier 1**: Self-hosted complex apps (GitLab CE, Mattermost) — local Docker
- **Tier 2**: Live HackerOne programs — read-only PAT, manual validation
- **Tier 3**: High-value targets — SENTINEL approval only
**Rationale**: Progressive complexity with strict scope/risk controls. Prevents premature live exposure.

---

## D-006: GitHub as Tier 2 Target (2026-07-30)
**Status**: ACCEPTED & SEALED  
**Charter Ref**: §30, §35, §49, §58, §60  
**Decision**: GitHub Bug Bounty selected as first Tier 2 target. Read-only PAT (`read:org`, `repo:read`, `user:read`). Manual validation mandatory.
**Rationale**: Explicitly allows automated tools (non-excessive); clear scope; legal safe harbor; complex API surface.
**Impact**: `H1_GITHUB_LIVE_SPEC.json` sealed; `GITHUB_SCOPE_CONFIG.json` loaded in ScopeParser.

---

## D-007: Repository Restructure to v2.0 Standard (2026-07-30)
**Status**: ACCEPTED & EXECUTING  
**Charter Ref**: §42, §46, §47, §51, §57  
**Decision**: Migrate to SENTINEL-mandated structure:
```
src/          → Core packages (orchestrator, agent, raphael)
tests/        → All test suites
configs/      → Specs, scope configs, docker-compose
benchmarks/   → RBS-v1 registration, targets
evaluations/  → Phase 0 audit reports, Phase 1+ results
failures/     → Failure registry (D6B_R1, D6C_Q2, etc.)
docs/         → DecisionLog, LIMITATIONS, DecisionLog
scripts/      → CI/CD, validation, deployment
```
**Rationale**: Enables reproducible evaluation, clear epistemic boundaries, auditability.

---

## D-008: Knowledge Layer Constraint for v3 (2026-07-30)
**Status**: ACCEPTED (Pre-emptive)  
**Charter Ref**: §42, §57  
**Decision**: When v3 "Knowledge Layer" is implemented, it MUST:
- Act only as evidence source → Hypothesis Generator
- NOT bypass Falsification Engine or CapabilityBroker
- Literature-suggested exploits still require Broker authorization
**Rationale**: Prevents knowledge-augmented reasoning from bypassing safety envelope.

---

## D-009: Manual Validation Gate (2026-07-30)
**Status**: ACCEPTED & SEALED  
**Charter Ref**: §58  
**Decision**: All vulnerability findings require manual validation before any report submission.
**Implementation**: `ENABLE_MANUAL_VALIDATION_GATE=true` in Tier 2 spec; cognitive loop HALTS on confirmed finding.
**Rationale**: Prevents automated exploitation/reporting; satisfies H1 policy and SENTINEL Rule 58.

---

## D-010: Tier 2 GitHub PAT Scopes (2026-07-30)
**Status**: ACCEPTED & SEALED  
**Charter Ref**: §30, §58  
**Decision**: GitHub PAT limited to read-only: `read:org`, `repo:read`, `user:read`. Explicitly forbidden: `repo`, `write:org`, `delete_repo`, `admin:org`, `admin:repo_hook`, `admin:public_key`, `gist`.
**Rationale**: Defense-in-depth — API enforces read-only; Broker denies write ops; safe harbor preserved.

---

*End of Decision Log — Append-only. Next entry: D-011*
