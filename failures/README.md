# Failure Registry — Project Raphael v2.0

> **Purpose**: Immutable record of all significant failures, regressions, and their resolutions. Per SENTINEL directive §57.

---

## F-001: D6B_R1 Canonical Index Invalidation (2026-07-18)
**Type**: Evaluation Integrity  
**Severity**: CRITICAL  
**Root Cause**: Ablation runner incorrectly cached canonical index across component masks, causing NO_LLM condition to pollute FULL_RAPHAEL results.  
**Detection**: D6C diagnostic runner detected divergence in holdout scores.  
**Resolution**: 
- Fixed `ablation_runner.py` cache isolation (PR #d6c-fix)
- Added cache invalidation on mask change
- Re-ran D6B with clean state: observed FULL_RAPHAEL 1.000 > NO_LLM 0.833 (on current benchmark/seeds, N=1)
**Status**: RESOLVED — `D6B_R1_CANONICAL_INDEX.json` regenerated and sealed.  
**Regression Test**: `tests/test_state_isolation.py::test_canonical_index_determinism`

---

## F-002: D6B_R1 Partial Invalidation
**Date**: 2026-07-19  
**Type**: Evaluation Integrity  
**Severity**: HIGH  
**Root Cause**: Batch 1 results showed systematic bias toward FULL_RAPHAEL configuration due to shared LLM context between ablations. LLM client singleton shared across ablation runs; context pollution.  
**Resolution**: 
- Isolated LLM client per ablation run
- Added `llm_context_reset()` hook
- Re-ran D6B with clean state: observed FULL_RAPHAEL 1.000 > NO_LLM 0.833 (on current benchmark/seeds, N=1)
**Status**: RESOLVED — `D6B_R1_FULL_VS_ABLATION.json` re-run and sealed.  
**Regression Test**: `tests/test_state_isolation.py::test_llm_context_isolation`

---

## F-003: D6C Q2 Step 1 Divergence
**Date**: 2026-07-22  
**Type**: LLM Non-Determinism  
**Severity**: HIGH  
**Root Cause**: Student knowledge background service cached stale technique proposals. Divergence trace showed inconsistent candidate scoring between FULL_RAPHAEL and NO_STUDENT ablations on identical targets.  
**Resolution**: 
- Added cache invalidation on target profile change
- Added cache TTL (1 hour)
**Status**: RESOLVED — `D6C_DIVERGENCE_TRACE_Q2_5.json` documented; reconciliation re-run.  
**Regression Test**: `tests/test_d5_preflight.py::test_student_cache_invalidation`

---

## F-004: D6C Holdout Lockfile v2 Mismatch
**Date**: 2026-07-24  
**Component**: D6C Holdout Evaluation  
**Severity**: HIGH  
**Root Cause**: Timestamp field in lockfile not normalized.  
**Resolution**: Normalized timestamp to UTC epoch seconds; added hash verification.  
**Status**: RESOLVED — `D6C_HOLDOUT_LOCKFILE_v2.json` regenerated and sealed.  
**Regression Test**: `arena/tests/test_baseline_equivalence.py::test_lockfile_hash_consistency`

---

## F-005: D10 LLM Evidence Window Repair
**Date**: 2026-07-26  
**Component**: D10 LLM Evidence Window Diagnostic  
**Severity**: HIGH  
**Root Cause**: Fixed window size (50) discarded evidence beyond horizon; no importance weighting.  
**Resolution**: Implemented importance-weighted sliding window; critical evidence (credentials, vulnerabilities) pinned.  
**Status**: RESOLVED — `D10_LLM_EVIDENCE_WINDOW_REPAIR_SPEC.json` sealed; diagnostic re-run passed.  
**Regression Test**: `arena/tests/test_d10_diagnostic.py::test_evidence_window_importance`

---

## F-006: D11 Planner Scoring Repair
**Date**: 2026-07-27  
**Component**: D11 Planner Scoring Diagnostic  
**Severity**: HIGH  
**Root Cause**: Planner heuristic over-weighted Student confidence without falsification check. Score inflation on T3 (Student Advisory) candidates — consistently 0.1 higher than empirical success.  
**Resolution**: Added falsification penalty to planner scoring: `score = base * (1 - falsification_rate)`.  
**Status**: RESOLVED — `D11_PLANNER_SCORING_REPAIR_SPEC.json` sealed.  
**Regression Test**: `arena/tests/test_d11_diagnostic.py::test_planner_calibration`

---

## F-007: D12 Contradiction Detector Repair
**Date**: 2026-07-28  
**Component**: D12 Contradiction Detection Diagnostic  
**Severity**: HIGH  
**Root Cause**: Only spatial/logical contradiction rules implemented; no temporal logic. Missed temporal contradictions (evidence A at T1 contradicts evidence B at T2).  
**Resolution**: Added temporal contradiction rules (entity state change without action, time-order violation).  
**Status**: RESOLVED — `D12_CONTRADICTION_DETECTOR_REPAIR_SPEC.json` sealed.  
**Regression Test**: `arena/tests/test_d12_diagnostic.py::test_temporal_contradiction`

---

## F-008: D13 Cognitive Efficacy Diagnosis
**Date**: 2026-07-29  
**Component**: D13 Cognitive Efficacy Diagnostic  
**Severity**: HIGH  
**Root Cause**: Metric weighted action count over outcome; didn't normalize to zero findings = zero efficacy.  
**Resolution**: Changed efficacy formula: `efficacy = (validated_findings / total_actions) * outcome_quality`.  
**Status**: RESOLVED — `D13_COGNITIVE_EFFICACY_DIAGNOSIS_SPEC.json` sealed.  
**Regression Test**: `arena/tests/test_d13_diagnostic.py::test_efficacy_zero_findings`

---

## F-009: D14 Cognitive Efficacy Repair
**Date**: 2026-07-29  
**Component**: D14 Cognitive Efficacy Repair Diagnostic  
**Severity**: HIGH  
**Root Cause**: D13 fix introduced regression in early-engagement scoring (penalized exploration).  
**Resolution**: Added exploration bonus: `efficacy = base * (1 + exploration_bonus)` where bonus decays over time.  
**Status**: RESOLVED — `D14_COGNITIVE_EFFICACY_REPAIR_SPEC.json` sealed.  
**Regression Test**: `arena/tests/test_d14_diagnostic.py::test_exploration_bonus`

---

## F-009: D15 T6 Log Injection Repair
**Date**: 2026-07-29  
**Component**: D15 T6 Log Injection Diagnostic  
**Severity**: MEDIUM  
**Root Cause**: T6 detector only checked request body and URL params; missed second-order injection (payload in referrer header reflected in log).  
**Resolution**: Extended T6 detector to scan all HTTP headers, cookies, and body.  
**Status**: RESOLVED — `D15_T6_LOG_INJECTION_REPAIR_SPEC.json` sealed.  
**Regression Test**: `tests/test_stage1_invariants.py::test_t6_log_injection_headers`

---

## F-010: D11 Planner Receipt Regression
**Date**: 2026-07-29  
**Component**: D11 Planner Receipt Diagnostic  
**Severity**: HIGH  
**Root Cause**: Receipt generation failed for shell actions due to missing `session_id` in action receipt.  
**Resolution**: Added `session_id` propagation through CapabilityBroker → Planner → Receipt chain.  
**Status**: RESOLVED — `D11_PLANNER_RECEIPT_REPAIR_SPEC.json` sealed.  
**Regression Test**: `arena/tests/test_d11_diagnostic.py::test_receipt_session_propagation`

---

## F-010: D12 Contradiction Temporal Edge Case
**Date**: 2026-07-28  
**Component**: D12 Contradiction Detection Diagnostic  
**Severity**: MEDIUM  
**Root Cause**: Temporal contradiction detector missed contradictions where evidence A at T1 was implicitly contradicted by evidence B at T2 without explicit negation.  
**Resolution**: Added implicit temporal contradiction rules (state persistence without action, time-order violation).  
**Status**: RESOLVED — Part of F-007 remediation.  
**Regression Test**: `arena/tests/test_d12_diagnostic.py::test_implicit_temporal_contradiction`

---

## F-011: D13 Cognitive Efficacy False Positive
**Date**: 2026-07-29  
**Component**: D13 Cognitive Efficacy Diagnostic  
**Severity**: HIGH  
**Root Cause**: Metric showed high efficacy despite zero validated findings — weighted action count over outcome.  
**Resolution**: Changed efficacy formula to normalize by outcome quality.  
**Status**: RESOLVED — Part of F-008 remediation.  
**Regression Test**: `arena/tests/test_d13_diagnostic.py::test_efficacy_zero_findings`

---

## F-011: D14 Cognitive Efficacy Repair Regression
**Date**: 2026-07-29  
**Component**: D14 Cognitive Efficacy Repair Diagnostic  
**Severity**: HIGH  
**Root Cause**: D13 fix penalized early exploration (low findings, high actions).  
**Resolution**: Added exploration bonus decaying over time.  
**Status**: RESOLVED — Part of F-009 remediation.  
**Regression Test**: `arena/tests/test_d14_diagnostic.py::test_exploration_bonus`

---

## F-012: D15 T6 Log Injection Header Gap
**Date**: 2026-07-29  
**Component**: D15 T6 Log Injection Diagnostic  
**Severity**: MEDIUM  
**Root Cause**: Only checked request body and URL params; missed headers.  
**Resolution**: Extended detector to all HTTP headers, cookies, body.  
**Status**: RESOLVED — Part of F-009 remediation.  
**Regression Test**: `tests/test_stage1_invariants.py::test_t6_log_injection_headers`

---

## F-012: D16 Final Holdout Evaluation — Scenario Leakage
**Date**: 2026-07-29  
**Component**: D16 Final Holdout Evaluation  
**Severity**: CRITICAL  
**Root Cause**: Holdout scenarios overlapped with training scenarios in arena manifest.  
**Resolution**: Regenerated holdout scenarios from disjoint seed; re-ran evaluation. New score: FULL 0.917, NO_LLM 0.833.  
**Status**: RESOLVED — `D16_FINAL_HOLDOUT_EVALUATION_SPEC.json` updated; `D16_HOLDOUT_SCORECARD.json` regenerated.  
**Regression Test**: `arena/tests/test_d16_holdout.py::test_scenario_disjointness`

---

## F-012: P1 WAFDetector False Negative on Custom WAF
**Date**: 2026-07-29  
**Component**: P1 WAFDetector (SS-03)  
**Severity**: MEDIUM  
**Root Cause**: Custom WAF (modified ModSecurity rules) not detected by any of 7 signatures.  
**Resolution**: Added behavioral anomaly detection (response time variance, header anomaly scoring) as fallback.  
**Status**: PARTIAL — Behavioral detection added; signature set expansion planned for v3.  
**Tracking**: `waf_detector.custom_waf_coverage` metric.

---

## F-013: PayloadMutator LLM Mutation Syntax Errors
**Date**: 2026-07-29  
**Component**: P1 PayloadMutator (SS-04) — Method 8 (LLM)  
**Severity**: HIGH  
**Root Cause**: LLM prompt lacked syntax constraint examples.  
**Resolution**: Added syntax validation step; invalid mutations rejected and retried (max 3). Marked LLM mutation as experimental.  
**Status**: PARTIAL — Syntax validation reduces error rate to 8%; LLM mutation remains method 8/8.  
**Regression Test**: `tests/test_p1_payload_mutator.py::test_llm_mutation_syntax`

---

## F-013: GitHub ScopeParser Missing npmjs.org Exclusion
**Date**: 2026-07-30  
**Component**: ScopeParser (P1-SS-01) — GitHub Scope Config  
**Severity**: MEDIUM  
**Root Cause**: Scope config generated from HTML parse; npmjs.org listed as in-scope but registry subdomains vary.  
**Resolution**: Added explicit `npmjs.org` and `*.npmjs.org` to in-scope; registry endpoints verified.  
**Status**: RESOLVED — `GITHUB_SCOPE_CONFIG.json` updated; ScopeParser validation passed.  
**Regression Test**: `tests/test_scope_parser.py::test_github_scope_npmjs`

---

## F-014: Nextcloud WebDAV Path Traversal False Positive
**Date**: 2026-07-30  
**Component**: Nextcloud Engagement — Cognitive Loop  
**Severity**: LOW  
**Root Cause**: Multi-level path traversal (`../../../html/shell.php`) returned 200 but file not written. Nextcloud normalizes path internally.  
**Resolution**: Cognitive loop now verifies file existence post-write via PROPFIND; false positive logged.  
**Status**: RESOLVED — Cognitive loop validation step added.  
**Tracking**: `nextcloud.webdav.traversal_false_positive_rate` metric.

---

## F-015: GitHub ScopeParser Wildcard Matching Edge Case
**Date**: 2026-07-30  
**Component**: ScopeParser (P1-SS-01) — GitHub Scope Config  
**Severity**: MEDIUM  
**Root Cause**: Wildcard `*.github.com` matched `evil.github.com.evil.com` in initial implementation.  
**Resolution**: Strict suffix matching enforced; exclusions applied before wildcard expansion.  
**Status**: RESOLVED — ScopeParser validation passed all 8/8 tests.  
**Regression Test**: `tests/test_scope_parser.py::test_wildcard_spoofing_resistance`

---

## F-016: E1 Test Suite Import Failure After Migration
**Date**: 2026-07-30  
**Component**: Test Infrastructure  
**Severity**: CRITICAL  
**Root Cause**: Migration to `src/` layout broke imports in test files (`from orchestrator.capabilities...`).  
**Resolution**: Added `pyproject.toml` with `package-dir = "src"`; updated pytest config with `pythonpath = ["src"]`.  
**Status**: PENDING — Requires pyproject.toml installation in test environment.  
**Tracking**: `tests/test_import_resolution.py`

---

*End of Failure Registry — Append-only. Next entry: F-017*
