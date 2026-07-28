# D-4 Verification Artifact — DECISION_RELEVANCE Proven

**Date:** 2026-07-26
**State:** 🟢 **`STAGE_2_5D_D4_LLM_CAUSAL_FROZEN`** (SENTINEL approved 2026-07-26)

## Planner Repair Summary

### Root cause of IndexError
The `Planner.decide()` method had two defects introduced during D-4 `rationale_codes` edits:
1. **Indentation error** — `scored.append(...)` was placed outside the candidate-scoring loop (wrong indentation level), causing only the last candidate's score to be appended once.
2. **Circular import** — `PlanDecision` was imported at module-runtime from `arena.conclusion` → triggered `arena.__init__` → `arena.runner` → `orchestrator.brain.action`, which was partially initialized, causing `ImportError`.

### Fixes applied
1. Restored correct loop indentation: `scored.append(...)` inside the `for c in candidates:` loop, `scored.sort(...)` and selection logic after it.
2. Replaced module-level runtime import with lazy import inside `decide()` method body.
3. Fixed `estimated_cost`/`estimated_risk` to use the selected candidate's values (not the last loop iteration's).
4. `empty-candidates` path returns early with minimal `PlanDecision` (no `scored[0]` indexing).

### Regression baseline restored
```
25/27 passing — same 2 pre-existing INFRA_FAILURE:
  test_scripted_has_only_evidence_claims:  AttributeError: _conclusion (SCRIPTED runner)
  test_no_planner_missing_service_type_claims: AttributeError: _conclusion (NO_PLANNER runner)
```

## D-4 Decision Relevance Audit

### Additive property ✅
SI-derived scoring (+0.5 for target match, +0.25 for evidence-seeking actions) is **added** to the existing `utility_score`, never replacing it. The pre-D-4 scoring (entity match, falsification priority, version detection, concrete action bonus) runs identically for all architectures.

### NO_LLM isolation ✅
```
NO_LLM:
  Hypothesis.semantic_inference_ids = []       (empty, no SI consumed)
  PlanDecision.rationale_codes      = ()        (no semantic_inference_driven)
  ConclusionProvenance.model_inference_ids = () (no SI provenance)
```

### Failure containment ✅
Structural guarantee: `HypothesisManager.consume_semantic_inference()` accepts `SemanticInferenceSuccess` only. `SemanticInferenceFailure` objects never enter cognitive machinery (evidence graph, hypothesis manager, planner, conclusion).

## ID-level DECISION_RELEVANT Chain

```
Evidence E17 [scan_result: TARGET_CONTROLLED]
    → LLM invocation (L3)
    → SemanticInference si_4 [state_description]
      model_id=deepseek-v4-flash-free, trust=MODEL_INFERENCE
    → Hypothesis H8 [semantic_inference_ids=['si_4']]
      entity_ids=['10.0.40.10']
    → Planner.decide(hypothesis_ids=(H8,))
      → SI-derived boost: +0.5 (target match) → utility=1.0
      → PlanDecision PD_2a7531441efc
        rationale=('semantic_inference_driven', 'hypothesis_driven')
        supporting_hypothesis_ids=(H8,)
    → ConclusionClaim cl_...
      provenance.model_inference_ids=('si_4',)
      provenance.hypothesis_ids=(H8,)
      provenance.plan_decision_ids=(PD_2a7531441efc,)
```

**Key proof:** The SI-derived hypothesis contributed a concrete scoring boost (+0.5) and a distinct rationale code (`semantic_inference_driven`) to the PlanDecision — not merely appearing in a provenance field. Removing that contribution would change the utility score (from 1.0 to 0.5 for the matching candidate), establishing decision relevance by SENTINEL's definition.

## Current Acceptance State

```text
D-0  FROZEN
D-1  FROZEN — WorldModel causal integration
D-2  FROZEN — Planner causal integration
D-3  FROZEN — Falsification causal integration
D-4  FROZEN — LLM semantic-inference causal integration
D-5  SPEC_V2_APPROVED — Implementation authorized (SENTINEL 2026-07-26)
```

## Claim Ledger (D-4)

| Claim | Status | Detail |
|---|---|---|
| LLM-01 | `SUPPORTED` | Causal integration: SI → Hypothesis → Planner → Conclusion |
| LLM-02 | `SUPPORTED` | Ablation isolation: NO_LLM removes all SI artifacts |
| LLM-03 | `SUPPORTED` | Failure containment: SemanticInferenceFailure never enters cognition |
| LLM-04 | `NOT ESTABLISHED` | Behavioral improvement: zero delta between FULL and NO_LLM |
| LLM-05 | `NOT ESTABLISHED` | Prompt-injection resistance |
| LLM-06 | `NOT ESTABLISHED` | Model quality/generalization |

## SENTINEL Freeze Directives

1. `FREEZE_D4.md` preserved as audit artifact (marked SUPERSEDED).
2. `FREEZE_D4_VERIFIED.md` is the authoritative freeze record.
3. **D-5 specification V2 approved** (2026-07-26, SHA256 `9d9b0589c57e88edc52ac7881faae468b09fc68183cbdd2834f2cba778546bd9`).
4. **D-5 implementation is now authorized.** Target: `STAGE_2_5D_D5_DEFEATER_CAUSAL_FROZEN`.
5. The two pre-existing INFRA_FAILURE tests remain technical debt (not D-4 regressions).

## D-5 Status

**Specification:** `D5_SPEC_V2_APPROVED` — Implementation authorized 2026-07-26.
**Target freeze:** `STAGE_2_5D_D5_DEFEATER_CAUSAL_FROZEN`
**Authoritative artifact:** `arena/SPEC_D5_DEFEATER_CAUSAL_INTEGRATION.md` (SHA256 `9d9b0589c57e88edc52ac7881faae468b09fc68183cbdd2834f2cba778546bd9`)
**V2 contract:** Seven-gate chain `INVOKED → PRODUCED → REFERENCED → EVALUATED → BELIEF_UPDATED → DECISION_RELEVANT → CONCLUSION`, `NOT_TRIGGERED` outcome, frozen belief-update tables, structural truth isolation, broker authority preservation, candidate-set invariance.

## D-5 Specification Directives (from SENTINEL 2026-07-26)

### Core architecture
The Defeater must answer: **"What would make hypothesis H unreliable?"** It is not another hypothesis generator, planner, or LLM cognition module. Its job is narrower:

```
Hypothesis H
    ↓
Defeater D — "What would make H unreliable?"
    ↓
DiscriminatingObservation / Action
    ↓
CapabilityBroker → Execution → Observation → Evidence
    ↓
Defeater evaluation → SUPPORTED / TRIGGERED / INCONCLUSIVE
    ↓
Hypothesis confidence/state transition
    ↓
Planner reconsideration
    ↓
RunConclusion
```

### Three prohibited shortcuts
1. **Deriving defeaters from evaluator truth** — the Defeater must not have access to the ground truth used for scoring.
2. **Encoding the correct answer** — a defeater so specifically defined that it directly encodes the correct answer rather than representing a generic reliability condition.
3. **Counting creation as integration** — instantiating a `Defeater` object does not constitute causal integration. The Defeater must trigger an observable belief/decision change.

### Methodology to retain (from D-1–D-4)
- Typed contracts between components
- Architecture-blind evaluation (RunConclusion)
- Explicit provenance fields
- Ablation path (NO_DEFEATER)
- ID-level causal tracing (INVOKED → PRODUCED → REFERENCED → DECISION_RELEVANT)
- Single targeted DEV diagnostic first
- Behavioral delta NOT required
- Hard stop for SENTINEL review before implementation
