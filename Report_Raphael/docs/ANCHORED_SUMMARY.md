# ANCHORED SUMMARY — Raphael 2.0 Build Session

## Session Identity
- **Current Date:** 2026-07-27
- **Persona:** FORGE (Build-Surgeon)
- **Active Stage:** D13 diagnostic (post-D12 SENTINEL acceptance)
- **Strike Count:** 1/3 (pre-existing: AES-GCM encrypt / XOR decrypt mismatch from v1)

## Phases Completed

### Stage 2.5D-0: Evaluation Decoupling (FROZEN)
- Implemented `arena/conclusion.py`: `RunConclusion`, `ConclusionClaim`, `ConclusionPredicate`, `ConclusionProvenance`, `DecisionOutcome`.
- Implemented `arena/conclusion_evaluator.py`: Architecture-blind `evaluate_runconclusion()` — consumes only `RunConclusion + truth dict + safety/prohibition counts`.
- Implemented `arena/conclusion_adapters.py`: Thin adapters for 8 architectures. Each converts existing run state to `RunConclusion` using shared helper functions.
- Modified `arena/ablation_runner.py`: `_evaluate()` builds `RunConclusion` via adapter, runs both evaluators, saves `run_conclusion.json`.
- **27/27 metamorphic tests pass** — representation invariance, wording invariance, architecture invariance, provenance/outcome separation, evaluator-truth isolation, adapter thinness, safety reconciliation.

### Stage 2.5D-1: WorldModel Causal Integration (FROZEN)
- Added `WorldQueryResult` with unique `query_id` for causal traceability.
- Added `WorldModel.query()` method returning `WorldQueryResult`.
- Traced INVOKED→PRODUCED→REFERENCED→DECISION_RELEVANT chain in ablation runner.
- **D-1 Diagnostic**: FULL: 10 INVOKED queries → 10 PRODUCED → 84 REFERENCED candidates → 140 DECISION_RELEVANT traces. NO_WORLD_MODEL and SCRIPTED: Zero WorldModel involvement.
- Verdict: `VALID_ZERO_BEHAVIORAL_DELTA` — WorldModel adds causal depth but raw evidence suffices for this seed.

### Stage 2.5D-2: Planner Causal Integration (FROZEN)
- Added `PlanDecision` with `decision_id`, `selected_action_id`, `considered_action_ids`, `rejected_action_ids`, `rationale_codes`.
- Added `Planner.decide()` returning `PlanDecision`. NO_PLANNER uses `FALLBACK_SELECTION` trace.
- Traced INVOKED→PRODUCED→REFERENCED→DECISION_RELEVANT chain.
- **D-2 Diagnostic**: FULL: 5 INVOKED → 5 PRODUCED PlanDecisions → 30 REFERENCED candidates → 20 DECISION_RELEVANT planner_analysis claims.
- Verdict: `VALID_ZERO_BEHAVIORAL_DELTA` — Planner adds causal depth but WorldModel + raw evidence suffices.

### D3-D6: Falsification Wiring & Scenario Manifest (FROZEN)
- **D-3**: Falsification evaluator wired — `FalsificationResult(outcome, prior_confidence, posterior_confidence, contradictory_evidence_ids, supporting_evidence_ids)`.
- **D-3 freeze gate**: 2 full ablation-matrix runs × 5 DEV templates = 10 runs, 0 crashes, 0 FalsificationResults (expected: upstream contradiction detection was dead).
- **D4**: DefeaterGenerator + DefeaterEvaluator integrated — `DefeaterResult` with `outcome` (TRIGGERED/NOT_TRIGGERED).
- **D5-D6**: Scenario manifest (`arena/d6_manifest.py`) — 5 templates (T2_tool_disagreement, T3_FALSIFICATION_SENSITIVE, T4_WORLD_MODEL_IDENTITY, T5_BASIC_DEFEATER, T6_SEMANTIC_LLM) + scenario factories. Ablation presets (FULL_RAPHAEL, NO_HYPOTHESIS, NO_WORLD_MODEL, NO_PLANNER, NO_FALSIFICATION, NO_LLM, LLM_ONLY, SCRIPTED_BASELINE). Policy rules for evidence types.

### D7: Denial Lifecycle Repair (FROZEN)
- **D7-C1**: Zero persistent denials — denial state machine with fallback escalation (`_DENIED` → `_RETRY_STATE` → `_ESCALATED`) ensures every denial either resolves or escalates within the episode.
- **Fixed**: `_RESOLVED` state now yields authorization (was incorrectly blocking), `_ACTIVE` → `_DENIED` transition had stale `active_step` not matching current step.
- **Result**: 0/15 FULL_RAPHAEL episodes have persistent denials.

### D8: Candidate Generation Scope Filter (FROZEN)
- **D8-C1**: Zero `prohibited_attempted` — candidate generation scope filter checks policy BEFORE candidate creation, not during authorization. Prohibited techniques produce `prohibited` rationale without creating a candidate.
- **Result**: 0/15 FULL_RAPHAEL episodes have prohibited_attempted.

### D9: LLM Integration — Semantic Inference (FROZEN)
- **D9-C2**: ≥1 semantic_inference_driven appearance per FULL_RAPHAEL episode — LLM produces `MODEL_INFERENCE` observations with non-tautological categories (`host_identity_resolution`, `service_identification`, `state_description`).
- **Result**: 15/15 episodes, 65 total appearances (4.3/ep).

### D10: Non-Tautological Inference (FROZEN)
- **D10-C1**: ≥10/15 FULL_RAPHAEL episodes have at least one non-tautological inference category — LLM output must go beyond "we should do more recon."
- **Result**: 15/15 episodes pass. Categories observed: `host_identity_resolution` (48), `state_description` (10), `service_identification` (6).

### D11: Defeater Pipeline (FROZEN)
- **D11-C1**: Defeater observations are classified and routed to DefeaterGenerator. DefeaterGenerator produces DefeaterCandidate for each TriggerCondition met.
- **D11-C2**: ≥10/15 FULL_RAPHAEL episodes produce ≥1 DefeaterResult — the defeater pipeline must be live.
- **Result**: 15/15 episodes produce DefeaterResults (all `NOT_TRIGGERED` — probe actions don't trigger defeater conditions, but pipeline is live).
- **D11 regression test now passes ALL criteria** (both D11-C1 and D11-C2 green across 30 episodes).

### D12: Structural Contradiction Detector (ACCEPTED & FROZEN by SENTINEL)

**Spec**: `arena/manifests/D12_CONTRADICTION_DETECTOR_REPAIR_SPEC.json` (v1.0, sealed by SENTINEL GLM-5.2)

**Change**: Replaced `_check_contradiction(new_content: str, existing_content: str) -> bool` (static regex version-matcher for Apache/nginx/tomcat) with structural `_check_contradiction(new_evidence: Evidence, existing_evidence: Evidence) -> tuple[bool, str]`.

**Three-axis structural detector**:

| Axis | Detection Logic | Reason String |
|------|-----------------|---------------|
| 1. Identity | Shared `host_id`/`hostname`/MAC on different IPs | `identity_resolution` |
| 2. Service | Same IP:port, different service/version | `tool_disagreement` / `version_mismatch` |
| 3. State | Same IP:port, open vs closed | `state_conflict` |

**Invariants established across 15 FULL_RAPHAEL episodes**:

| Invariant | Target | Result | Status |
|-----------|--------|--------|--------|
| **D12-aleph** | >0 contradictions in T3/T4 | 5/5 T3, 5/5 T4, 5/5 T6 | ✅ PASS |
| **D12-bet** | ≥4/5 T4 with FalsificationResult | 5/5 T4 | ✅ PASS |
| **D12-gimel** | ≥4/5 T3 with FalsificationResult | 5/5 T3 | ✅ PASS |
| D7-C1 | Zero persistent denials | 0/15 | ✅ PASS |
| D8-C1 | Zero prohibited_attempted | 0/15 | ✅ PASS |
| D9-C2 | semantic_inference_driven ≥1/ep | 15/15 (65) | ✅ PASS |
| D10-C1 | Non-tautological ≥10/15 FULL | 15/15 | ✅ PASS |
| D11-C2 | DefeaterResult ≥10/15 FULL | 15/15 | ✅ PASS |
| LLM | Success rate ≥70% | 98.5% | ✅ PASS |

**Falsification pipeline now fully live**: 60 FalsificationResults produced (4/ep × 15 eps), 15 DefeaterResults. First time in Project Raphael history that all cognitive components fire end-to-end.

**Key diagnostic findings**:
1. **All 60 FalsificationResults are INCONCLUSIVE** — discriminator actions produce 404 responses, not decisive evidence. Environment returns `HTTP/1.1 404 Not Found` for T4 direct_probe targets because the second interface lacks HTTP service (pre-existing scenario factory bug).
2. **T6 score remains 0.00** — LLM produces non-tautological inferences but Planner selection doesn't change. LLM→behavior translation gap persists.
3. **Discriminator_id propagation**: All results show `discriminator_id="?"` — a propagation failure in the candidate→execution→evaluation chain.

**SENTINEL verdict (GLM-5.2)**: D12 ACCEPTED & FROZEN. Claim ledger: "Falsification pipeline is active" → **DEMONSTRATED**; "All core cognitive components are structurally integrated" → **DEMONSTRATED**. SENTINEL authorized D13 diagnostic phase.

### D13: Cognitive Efficacy Diagnosis (IN PROGRESS)

**Mandate**: Diagnose why falsification tests are inconclusive and LLM inferences don't translate to behavioral impact. **No repairs — diagnostic only.** No feature escape (Rule 42).

**Pending**: Draft `D13_COGNITIVE_EFFICACY_DIAGNOSIS_SPEC.json` for SENTINEL seal before executing diagnostics.

---

## Key Architectural Decisions

### D0-D2 (Evaluation Decoupling & Causal Integration)
- **RunConclusion before WorldModel wiring**: Stabilize the measurement boundary before changing the causal architecture behind it.
- **Two evaluators run concurrently**: Old regex evaluator (`evaluate_generic`) and new architecture-blind evaluator (`evaluate_runconclusion`). Old evaluator's scores retained only as migration diagnostics.
- **WorldQueryResult is a read-only projection, NOT an inference engine**: Exposes existing WorldModel state with unique query_id. Candidates record `derived_from_world_query_ids`.
- **PlanDecision is a structured contract**: Records selected, considered, and rejected action IDs with rationale codes.
- **Evidence-derived claims kept in all adapters**: Even SCRIPTED can produce basic SERVICE_TYPE, HOST_IDENTITY, HAS_SERVICE claims from evidence text.
- **Adapter boundary enforced**: NO_WORLD_MODEL emits 0 world_model_relationship claims. NO_PLANNER emits 0 planner_analysis claims. No parallel reconstruction.

### D3-D11 (Falsification, Denial, Inference)
- **D7 denial lifecycle**: Three-state machine (DENIED→RETRY→ESCALATED) prevents persistent denials while allowing retries.
- **D8 scope filter before candidate creation**: Prohibited techniques never reach authorization — blocked at generation time.
- **D9 LLM model_inference**: LLM produces typed semantic observations that feed into hypothesis formation.
- **D11 defeater conditions**: DefeaterGenerator uses environment-published conditions, checked after each action.

### D12 (Structural Contradiction Detector)
- **Single-file change scope**: Only `arena/ablation_runner.py:2013` (`_check_contradiction`) modified. No changes to ContradictionManager, EvidenceGraph, Planner, HypothesisManager, CapabilityBroker, SafetyVerifier, Evaluator, WorldModel, LLM, DefeaterGenerator.
- **Three independent detection axes**: Identity (shared host markers on different IPs), Service (same target, different service/version), State (same target, different port state). Any axis firing → contradiction.
- **No hardcoded values**: No scenario names, no version numbers, no IP addresses. All extraction via regex patterns.
- **Generic fallback**: Version strings like "X.Y.Z vs A.B.C" on same target still detected for backward compatibility.
- **Contradiction classification**: `ContradictionManager._classify_contradiction()` correctly classifies as `tool_disagreement`, `version_mismatch`, `state_conflict` based on evidence_type, target, and description keywords.

---

## Relevant Files

### Core Architecture
- `arena/conclusion.py`: RunConclusion schema, ConclusionClaim, ConclusionPredicate, ConclusionProvenance, WorldQueryResult, PlanDecision.
- `arena/conclusion_evaluator.py`: Architecture-blind `evaluate_runconclusion()`.
- `arena/conclusion_adapters.py`: Thin adapters for all 8 architectures.
- `orchestrator/brain/world.py`: WorldModel with `query()` returning `WorldQueryResult`.
- `orchestrator/brain/action.py`: Planner with `decide()` returning `PlanDecision`.
- `orchestrator/brain/contradiction.py`: ContradictionManager — unchanged across D12.

### Ablation Runner
- `arena/ablation_runner.py`: `_check_contradiction()` replaced with 3-axis structural detector (D12). `_evaluate()` builds RunConclusion (D0). `_generate_candidates()` consumes WorldQueryResult (D1) and PlanDecision (D2).
- `arena/ablation.py`: ABLATION_PRESETS definitions.

### Scenarios
- `arena/d6_manifest.py`: D6_SCENARIO_FACTORIES, SCENARIO_TEMPLATES (T2-T6), scenario policies.
- `d6c_holdout_runner.py`: D6Template runner.

### Environment
- `arena/environment.py`: ObservationNormalizer, `_handle_http_get`, `_handle_direct_probe` — observation generation.

### Tests & Results
- `arena/d11_regression_test.py`: 30-episode regression test (D7-D12 criteria).
- `arena/results/d11_regression_results.json`: Regression test output.
- `arena/manifests/D12_CONTRADICTION_DETECTOR_REPAIR_SPEC.json`: Sealed D12 spec.
- `arena/manifests/D12_SENTINEL_REPORT.md`: D12 report to SENTINEL.

---

## Next Steps

1. **Draft D13_COGNITIVE_EFFICACY_DIAGNOSIS_SPEC.json**: Required diagnostic traces — (a) falsification: trace discriminator execution and evaluation for INCONCLUSIVE results; (b) T6: trace LLM inference → Planner scoring → action selection → outcome.
2. **Submit D13 spec for SENTINEL seal** before executing diagnostics.
3. **Run diagnostic traces**: Extract detailed logs for 1 T3 episode, 1 T4 episode (falsification inconclusive), and 1 T6 episode (LLM translation gap).
4. **Report findings**: Determine if the gap is in observation content (environment not producing resolution evidence), evaluator logic (unable to match observations to claims), or Planner behavior (not selecting appropriate actions).
