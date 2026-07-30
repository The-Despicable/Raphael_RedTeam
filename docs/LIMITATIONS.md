# Known Limitations — Project Raphael v2.0

> **Purpose**: Honest documentation of system boundaries, failure modes, and constraints. Updated per SENTINEL directive.

---

## L-001: Cognitive Loop Latency
**Severity**: MEDIUM  
**Component**: D-Series Brain (AdaptiveBrain, Planner)  
**Description**: Full cognitive loop (Recon → Propose → Execute → Ingest → Reflect) takes 30-120 seconds per cycle depending on LLM latency. Not suitable for time-critical exploitation windows.  
**Mitigation**: Parallel candidate scoring; heuristic fallback when LLM >30s.  
**Tracking**: Monitor `adaptive_brain.cycle_latency_ms` metric.

---

## L-002: LLM Hallucination in Technique Proposal
**Severity**: HIGH  
**Component**: S-Series Student (ChainSynthesizer, ResearchScheduler)  
**Description**: Student may propose techniques that don't exist, misattribute CVEs, or hallucinate API endpoints. Falsification Engine catches ~78% in testing.  
**Mitigation**: Falsification Engine mandatory; evidence required for every proposal; confidence threshold 0.7.  
**Tracking**: `student.hallucination_rate` in evaluation metrics.

---

## L-003: ScopeParser False Positives on Subdomain Matching
**Severity**: MEDIUM  
**Component**: P1 ScopeParser (SS-01)  
**Description**: Wildcard matching `*.github.com` allows `evil.github.com.evil.com` if not properly anchored. Current implementation uses suffix matching.  
**Mitigation**: ScopeParser validates exact suffix match; excludes known spoofing patterns. Manual scope review required before live engagement.  
**Tracking**: ScopeParser unit tests include spoofing edge cases.

---

## L-004: RateLimiter Jitter Insufficient Against Adaptive WAF
**Severity**: MEDIUM  
**Component**: P1 RateLimiter (SS-02)  
**Description**: Fixed 10-20s jitter may be fingerprinted by adaptive WAFs (e.g., Cloudflare Bot Management).  
**Mitigation**: Configurable jitter distribution (exponential, uniform, custom); emergency brake on 429/403 clusters.  
**Tracking**: RateLimiter WAF detection integration (WAFDetector → RateLimiter feedback).

---

## L-004: WAFDetector Limited to 7 Signatures
**Severity**: MEDIUM  
**Component**: P1 WAFDetector (SS-03)  
**Description**: Only detects Cloudflare, ModSecurity, AWS WAF, F5 ASM, Akamai, Sucuri, Wordfence. Misses custom/enterprise WAFs.  
**Mitigation**: Extensible signature registry; behavioral anomaly detection planned for v3.  
**Tracking**: `waf_detector.signature_coverage` metric.

---

## L-005: PayloadMutator LLM Mutation Unreliable
**Severity**: HIGH  
**Component**: P1 PayloadMutator (SS-04)  
**Description**: LLM-based mutation (method 8) produces inconsistent results; may break payload syntax.  
**Mitigation**: LLM mutation is method 8 of 8; deterministic methods 1-7 are primary. LLM mutation flagged as experimental.  
**Tracking**: `payload_mutator.llm_success_rate` metric.

---

## L-005: Student Knowledge Base Staleness
**Severity**: MEDIUM  
**Component**: S-Series Student (KnowledgeBackgroundService)  
**Description**: Knowledge base updated via scheduled ResearchScheduler; may miss zero-day techniques or recent CVEs.  
**Mitigation**: Manual `trigger_immediate_research()` for critical CVEs; integration with CVE feed harvester.  
**Tracking**: `student.kb.last_update` timestamp.

---

## L-006: E-Series Shell No Interactive TTY Support
**Severity**: LOW  
**Component**: E-Series InteractiveShell  
**Description**: CommandFilterPipeline processes discrete commands; no true interactive TTY with real-time stdin/stdout.  
**Mitigation**: TTYNormalizer simulates line-buffered output; suitable for command execution, not interactive apps (vim, less).  
**Tracking**: E1 test suite covers command execution, not interactive sessions.

---

## L-006: CapabilityBroker Single Point of Failure
**Severity**: HIGH  
**Component**: CapabilityBroker  
**Description**: All authorization flows through single broker instance. If broker fails, all shell operations halt.  
**Mitigation**: Broker state persisted to SQLite; restart recovers active sessions. High availability not implemented.  
**Tracking**: `capability_broker.uptime` metric.

---

## L-007: WorldModel Entity Explosion
**Severity**: MEDIUM  
**Component**: D-Series WorldModel  
**Description**: Long engagements generate 10,000+ entities; query performance degrades; LLM context window exceeded.  
**Mitigation**: Entity TTL (24h default); automatic pruning of low-confidence entities; neural memory summarization.  
**Tracking**: `worldmodel.entity_count`, `worldmodel.query_latency_ms`.

---

## L-007: Neural Memory Retrieval Inaccuracy
**Severity**: MEDIUM  
**Component**: D-Series NeuralMemory (Episodic)  
**Description**: Embedding-based retrieval returns semantically similar but factually incorrect episodes ~12% of the time.  
**Mitigation**: Confidence threshold 0.75; cross-reference with WorldModel facts; manual review for critical decisions.  
**Tracking**: `neural_memory.retrieval_precision` metric.

---

## L-008: P1 Modules Not Battle-Tested Against Tier 1 WAFs
**Severity**: HIGH  
**Component**: P1 ScopeParser, RateLimiter, WAFDetector, PayloadMutator  
**Description**: All P1 stealth modules tested against local Target-05 WAF simulation only. No validation against Cloudflare Enterprise, Akamai, or Imperva.  
**Mitigation**: Tier 1 engagement (self-hosted GitLab/Mattermost) planned for P1 validation before Tier 2.  
**Tracking**: Tier 1 evaluation results.

---

## L-008: No Multi-Target Concurrent Engagement
**Severity**: MEDIUM  
**Component**: AdaptiveBrain, CapabilityBroker  
**Description**: System engages one target at a time. No support for parallel multi-target campaigns.  
**Mitigation**: Run multiple Raphael instances with separate broker instances. Shared WorldModel not thread-safe.  
**Tracking**: Architecture decision D-001 enforces single-target focus.

---

## L-009: No Automated Report Generation
**Severity**: MEDIUM (by design)  
**Component**: Reflection Engine, Reporting  
**Description**: No automated H1 report generation. All findings require manual validation and report drafting per SENTINEL Rule 58.  
**Rationale**: Prevents AI-generated report spam; ensures human accountability.  
**Tracking**: `reflection.report.draft_time` metric.

---

## L-010: Tier 2 Requires Real Credentials Not Available in Simulation
**Severity**: BLOCKING  
**Component**: Tier 2 Engagement  
**Description**: GitHub PAT and H1 API key required for live Tier 2 engagement. Simulation environment cannot generate valid credentials.  
**Mitigation**: Credential provisioning is manual prerequisite; documented in `.env.tier2.template`.  
**Tracking**: Tier 2 readiness gate.

---

## L-011: No Persistent State Across Restarts (Partial)
**Severity**: LOW  
**Component**: SurvivabilityEngine, CapabilityBroker  
**Description**: WorldModel and NeuralMemory persist to SQLite; CapabilityBroker session state persists; but AdaptiveBrain strategy weights reset on restart.  
**Mitigation**: StrategyLearner exports weights to `data/strategy_model.json` on checkpoint.  
**Tracking**: `survivability.checkpoint_completeness`.

---

## L-011: No Formal Verification of Safety Properties
**Severity**: HIGH  
**Component**: CapabilityBroker, ScopeParser, RateLimiter  
**Description**: Safety invariants tested via unit/integration tests only. No formal verification (model checking, theorem proving).  
**Mitigation**: Comprehensive test coverage (158+ tests); mutation testing planned.  
**Tracking**: `tests.coverage` metric; formal verification backlog item.

---

## L-012: Agent Implant Not Integrated
**Severity**: MEDIUM  
**Component**: Agent (Implant)  
**Description**: Agent modules (syscall, inject, stealth, credtheft, exfil, persistence, lateral, cleanup, audit) exist but not integrated into cognitive loop.  
**Mitigation**: Agent deployment is post-exploitation phase; not in current scope.  
**Tracking**: Post-Tier 2 roadmap.

---

## L-012: No Persistent State Across Restarts (Partial)
**Severity**: LOW  
**Component**: SurvivabilityEngine, CapabilityBroker  
**Description**: WorldModel and NeuralMemory persist to SQLite; CapabilityBroker session state persists; but AdaptiveBrain strategy weights reset on restart.  
**Mitigation**: StrategyLearner exports weights to `data/strategy_model.json` on checkpoint.  
**Tracking**: `survivability.checkpoint_completeness`.

---

## L-013: No Formal Verification of Safety Properties
**Severity**: HIGH  
**Component**: CapabilityBroker, ScopeParser, RateLimiter  
**Description**: Safety invariants tested via unit/integration tests only. No formal verification (model checking, theorem proving).  
**Mitigation**: Comprehensive test coverage (158+ tests); mutation testing planned.  
**Tracking**: `tests.coverage` metric; formal verification backlog item.

---

## L-013: Agent Implant Not Integrated
**Severity**: MEDIUM  
**Component**: Agent (Implant)  
**Description**: Agent modules (syscall, inject, stealth, credtheft, exfil, persistence, lateral, cleanup, audit) exist but not integrated into cognitive loop.  
**Mitigation**: Agent deployment is post-exploitation phase; not in current scope.  
**Tracking**: Post-Tier 2 roadmap.

---

## L-014: Tier 2 Requires Real Credentials Not Available in Simulation
**Severity**: BLOCKING  
**Component**: Tier 2 Engagement  
**Description**: GitHub PAT and H1 API key required for live Tier 2 engagement. Simulation environment cannot generate valid credentials.  
**Mitigation**: Credential provisioning is manual prerequisite; documented in `.env.tier2.template`.  
**Tracking**: Tier 2 readiness gate.

---

## L-015: No Multi-Target Concurrent Engagement
**Severity**: MEDIUM  
**Component**: AdaptiveBrain, CapabilityBroker  
**Description**: System engages one target at a time. No support for parallel multi-target campaigns.  
**Mitigation**: Run multiple Raphael instances with separate broker instances. Shared WorldModel not thread-safe.  
**Tracking**: Architecture decision D-001 enforces single-target focus.

---

*Last Updated: 2026-07-30*  
*Review Cadence: Per engagement (post-mortem) + monthly*  
*Next Review: Post Tier 2 GitHub Engagement*
