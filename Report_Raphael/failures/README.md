# Failure Registry — Project Raphael v2.0

> **Purpose**: Immutable record of all significant failures, regressions, and their resolutions. Maintained per SENTINEL directive §47.

---

## F-001: D6B_R1 Canonical Index Invalidation
**Date**: 2026-07-18  
**Component**: Arena Ablation Runner  
**Failure**: Canonical index generation produced inconsistent ordering across runs, invalidating batch comparison.  
**Root Cause**: Non-deterministic dictionary iteration in `ablation_runner.py:_build_canonical_index()`.  
**Resolution**: Sorted keys before iteration; added deterministic hash verification.  
**Status**: RESOLVED — `D6B_R1_CANONICAL_INDEX.json` regenerated and sealed.  
**Regression Test**: `tests/test_state_isolation.py::test_canonical_index_determinism`

---

## F-002: D6B_R1 Partial Invalidation
**Date**: 2026-07-19  
**Component**: Ablation Runner — Batch 1  
**Failure**: Batch 1 results showed systematic bias toward FULL_RAPHAEL configuration due to shared LLM context between ablations.  
**Root Cause**: LLM client singleton shared across ablation runs; context pollution.  
**Resolution**: Isolated LLM client per ablation run; added `llm_context_reset()` hook.  
**Status**: RESOLVED — `D6B_R1_FULL_VS_ABLATION.json` re-run and sealed.  
**Regression Test**: `tests/test_state_isolation.py::test_llm_context_isolation`

---

## F-003: D6C_Q2 Step 1 Divergence
**Date**: 2026-07-22  
**Component**: D6C Reconciliation — Question 2, Step 1  
**Failure**: Divergence trace showed inconsistent candidate scoring between FULL_RAPHAEL and NO_STUDENT ablations on identical targets.  
**Root Cause**: Student knowledge background service cached stale technique proposals.  
**Resolution**: Added cache invalidation on target profile change; added cache TTL (1 hour).  
**Status**: RESOLVED — `D6C_DIVERGENCE_TRACE_Q2_5.json` documented; reconciliation re-run.  
**Regression Test**: `tests/test_d5_preflight.py::test_student_cache_invalidation`

---

## F-004: D6C Holdout Lockfile v2 Mismatch
**Date**: 2026-07-24  
**Component**: D6C Holdout Evaluation  
**Failure**: Holdout lockfile v2 hash mismatch between runner and evaluator.  
**Root Cause**: Timestamp field in lockfile not normalized.  
**Resolution**: Normalized timestamp to UTC epoch seconds; added hash verification.  
**Status**: RESOLVED — `D6C_HOLDOUT_LOCKFILE_v2.json` regenerated and sealed.  
**Regression Test**: `arena/tests/test_baseline_equivalence.py::test_lockfile_hash_consistency`

---

## F-005: D10 LLM Evidence Window Repair
**Date**: 2026-07-26  
**Component**: D10 LLM Evidence Window Diagnostic  
**Failure**: Evidence window sliding caused loss of critical early-recon evidence in long engagements.  
**Root Cause**: Fixed window size (50) discarded evidence beyond horizon; no importance weighting.  
**Resolution**: Implemented importance-weighted sliding window; critical evidence (credentials, vulnerabilities) pinned.  
**Status**: RESOLVED — `D10_LLM_EVIDENCE_WINDOW_REPAIR_SPEC.json` sealed; diagnostic re-run passed.  
**Regression Test**: `arena/tests/test_d10_diagnostic.py::test_evidence_window_importance`

---

## F-006: D11 Planner Scoring Repair
**Date**: 2026-07-27  
**Component**: D11 Planner Scoring Diagnostic  
**Failure**: Planner score inflation on T3 (Student Advisory) candidates — consistently scored 0.1 higher than empirical success.  
**Root Cause**: Planner heuristic over-weighted Student confidence without falsification check.  
**Resolution**: Added falsification penalty to planner scoring; score = base * (1 - falsification_rate).  
**Status**: RESOLVED — `D11_PLANNER_SCORING_REPAIR_SPEC.json` sealed.  
**Regression Test**: `arena/tests/test_d11_diagnostic.py::test_planner_calibration`

---

## F-007: D12 Contradiction Detector Repair
**Date**: 2026-07-28  
**Component**: D12 Contradiction Detection Diagnostic  
**Failure**: Contradiction detector missed temporal contradictions (evidence A at T1 contradicts evidence B at T2).  
**Root Cause**: Only spatial/logical contradiction rules implemented; no temporal logic.  
**Resolution**: Added temporal contradiction rules (entity state change without action, time-order violation).  
**Status**: RESOLVED — `D12_CONTRADICTION_DETECTOR_REPAIR_SPEC.json` sealed.  
**Regression Test**: `arena/tests/test_d12_diagnostic.py::test_temporal_contradiction`

---

## F-008: D13 Cognitive Efficacy Diagnosis
**Date**: 2026-07-29  
**Component**: D13 Cognitive Efficacy Diagnostic  
**Failure**: Cognitive efficacy metric showed false positive — high efficacy score despite zero validated findings.  
**Root Cause**: Metric weighted action count over outcome; didn't normalize to zero findings = zero efficacy.  
**Resolution**: Changed efficacy formula: `efficacy = (validated_findings / total_actions) * outcome_quality`.  
**Status**: RESOLVED — `D13_COGNITIVE_EFFICACY_DIAGNOSIS_SPEC.json` sealed.  
**Regression Test**: `arena/tests/test_d13_diagnostic.py::test_efficacy_zero_findings`

---

## F-009: D14 Cognitive Efficacy Repair
**Date**: 2026-07-29  
**Component**: D14 Cognitive Efficacy Repair Diagnostic  
**Failure**: Repair verification failed — D13 fix introduced regression in early-engagement scoring.  
**Root Cause**: New efficacy formula penalized early exploration (low findings, high actions).  
**Resolution**: Added exploration bonus: `efficacy = base * (1 + exploration_bonus)` where bonus decays over time.  
**Status**: RESOLVED — `D14_COGNITIVE_EFFICACY_REPAIR_SPEC.json` sealed.  
**Regression Test**: `arena/tests/test_d14_diagnostic.py::test_exploration_bonus`

---

## F-010: D15 T6 Log Injection Repair
**Date**: 2026-07-29  
**Component**: D15 T6 Log Injection Diagnostic  
**Failure**: T6 log injection detector missed second-order injection (payload in referrer header reflected in log).  
**Root Cause**: Only checked request body and URL params; missed headers.  
**Resolution**: Extended T6 detector to scan all HTTP headers, cookies, and body.  
**Status**: RESOLVED — `D15_T6_LOG_INJECTION_REPAIR_SPEC.json` sealed.  
**Regression Test**: `tests/test_stage1_invariants.py::test_t6_log_injection_headers`

---

## F-011: D16 Final Holdout Evaluation
**Date**: 2026-07-29  
**Component**: D16 Final Holdout Evaluation  
**Failure**: Holdout evaluation showed FULL_RAPHAEL score 1.000 vs NO_LLM 0.833 — suspiciously perfect.  
**Root Cause**: Holdout scenarios overlapped with training scenarios in arena manifest.  
**Resolution**: Regenerated holdout scenarios from disjoint seed; re-ran evaluation. New score: FULL 0.917, NO_LLM 0.833.  
**Status**: RESOLVED — `D16_FINAL_HOLDOUT_EVALUATION_SPEC.json` updated; `D16_HOLDOUT_SCORECARD.json` regenerated.  
**Regression Test**: `arena/tests/test_d16_holdout.py::test_scenario_disjointness`

---

## F-012: P1 WAFDetector False Negative on Custom WAF
**Date**: 2026-07-29  
**Component**: P1 WAFDetector (SS-03)  
**Failure**: Custom WAF (modified ModSecurity rules) not detected by any of 7 signatures.  
**Root Cause**: Signature set limited to default rule sets; custom rules evaded fingerprinting.  
**Resolution**: Added behavioral anomaly detection (response time variance, header anomaly scoring) as fallback.  
**Status**: PARTIAL — Behavioral detection added; signature set expansion planned for v3.  
**Tracking**: `waf_detector.custom_waf_coverage` metric.

---

## F-013: PayloadMutator LLM Mutation Syntax Errors
**Date**: 2026-07-29  
**Component**: P1 PayloadMutator (SS-04) — Method 8 (LLM)  
**Failure**: LLM mutation produced syntactically invalid SQL payloads 34% of the time.  
**Root Cause**: LLM prompt lacked syntax constraint examples.  
**Resolution**: Added syntax validation step; invalid mutations rejected and retried (max 3). Marked LLM mutation as experimental.  
**Status**: PARTIAL — Syntax validation reduces error rate to 8%; LLM mutation remains method 8/8.  
**Regression Test**: `tests/test_p1_payload_mutator.py::test_llm_mutation_syntax`

---

## F-014: GitHub ScopeParser Missing npmjs.org Exclusion
**Date**: 2026-07-30  
**Component**: ScopeParser (P1-SS-01) — GitHub Scope Config  
**Failure**: Initial scope config missed `npmjs.org` exclusion (not in scope per GitHub policy).  
**Root Cause**: Scope config generated from HTML parse; npmjs.org listed as in-scope but registry subdomains vary.  
**Resolution**: Added explicit `npmjs.org` and `*.npmjs.org` to in-scope; registry endpoints verified.  
**Status**: RESOLVED — `GITHUB_SCOPE_CONFIG.json` updated; ScopeParser validation passed.  
**Regression Test**: `tests/test_scope_parser.py::test_github_scope_npmjs`

---

## F-015: Nextcloud WebDAV Path Traversal False Positive
**Date**: 2026-07-30  
**Component**: Nextcloud Engagement — Cognitive Loop  
**Failure**: Multi-level path traversal (`../../../html/shell.php`) returned 200 but file not written.  
**Root Cause**: Nextcloud WebDAV normalizes path internally; returns 200 for "accepted" but sanitizes.  
**Resolution**: Cognitive loop now verifies file existence post-write via PROPFIND; false positive logged.  
**Status**: RESOLVED — Cognitive loop validation step added.  
**Tracking**: `nextcloud.webdav.traversal_false_positive_rate` metric.

---

*End of Failure Registry — Append-only. Next entry: F-016*
