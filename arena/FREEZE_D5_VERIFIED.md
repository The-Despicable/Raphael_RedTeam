# D-5 Verification Artifact — DEFEATER CAUSAL INTEGRATION Proven

**Date:** 2026-07-26
**State:** 🟢 **`STAGE_2_5D_D5_DEFEATER_CAUSAL_FROZEN`** (SENTINEL approved 2026-07-26)

## Specification

**Specification:** `SPEC_D5_DEFEATER_CAUSAL_INTEGRATION.md`
**V2 Contract:** SENTINEL-approved D-5 V2 (2026-07-26)

## Seven-Gate Chain (Verified)

```
H8  (hyp_29d64a8b3ea5)               — Hypothesis
 ↓
DF3 (df_0afcb7d25c90)                 — INVOKED → PRODUCED
 ↓
DC4 (defeater_probe_10.0.1.5_df_...)  — REFERENCED
 ↓
AR5 (AR5_20a1e007)                    — BROKER AUTHORIZATION
 ↓
E29 (ev_banner_collected)             — EVIDENCE COLLECTED
 ↓
DR7 (dr_3d49c4ae37c0)                 — EVALUATED (outcome=triggered)
 ↓
BT3 (bt_17c5f7af5a60)                 — BELIEF_UPDATED (0.617→0.432, ACTIVE→DOUBTFUL)
 ↓
PD9 (PD_9)                            — DECISION_RELEVANT (rationale=defeater_triggered)
 ↓
C14 (3 claims)                        — CONCLUSION (derivation=DEFEATER_TEST)
```

### ID-Level Assertions (all mechanically verified)

| Edge | Assertion | Status |
|------|-----------|--------|
| DC4 → DF3 | `DC4.defeater_trigger_id == DF3.defeater_id` | ✅ |
| DR7 → DF3 | `DR7.defeater_id == DF3.defeater_id` | ✅ |
| BT3 → DR7 | `BT3.defeater_result_id == DR7.result_id` | ✅ |
| BT3 → H8  | `BT3.hypothesis_id == H8.hypothesis_id` | ✅ |
| PD9 → BT3 | `BT3.transition_id in PD9.consumed_transition_ids` | ✅ |
| PD9 rationale | `"defeater_triggered" in PD9.rationale_codes` | ✅ |
| C14 → DR7 | `DR7.result_id in C14.provenance.defeater_result_ids` | ✅ |
| C14 derivation | `C14.derivation_type == DEFEATER_TEST` | ✅ |

## Transition Policy

**Policy version:** `D5_V2_2026-07-26` (literal constant)
**Tables:** `TRIGGERED_TRANSITIONS`, `NOT_TRIGGERED_TRANSITIONS` (module-level dict literals)
**No dynamic loading:** Verified by source inspection — policy is not config-file-driven

## Preflight Verification Results

### Truth Isolation ✅
- `DefeaterGenerator`, `DefeaterEvaluator`, `_defeater_to_claims()` have zero imports/dependencies on `evaluator_truth`, `EvaluationResult`, `expected_outcome`, `scoring_state`, or `architecture_id`.
- Static inspection + runtime signature audit passes.
- Parameters strictly cognitive-visible state.

### Hidden-Truth Counterfactual Invariance ✅
- Two runs with byte-identical cognitive-visible inputs + different hidden evaluator truth.
- `normalize(Triggers_A) == normalize(Triggers_B)` — identical after ID/timestamp normalization.
- 4 triggers each, all semantically equivalent.

### Candidate-Set Invariance ✅
- `normalize(BaseCandidates_FULL) == normalize(BaseCandidates(NO_DEFEATER))` — 3 each, identical.
- `Final_FULL = BaseCandidates + DefeaterCandidates` (append-only, 2 added).
- `Final_NO_DEFEATER = BaseCandidates` (no augmentation).
- All defeater candidates carry `_is_defeater`, `defeater_trigger_id`, `candidate_origin=DEFEATER`.

### Broker Isolation ✅
- All candidates go through `runner.propose_action()` → `receipt.decision` check → `env.handle_action()`.
- No defeater-specific bypass path exists.
- Denied actions (`broker_decision != "allow"`) produce `continue` — no external execution.

### Outcome Semantics ✅

| Outcome | Result Allowed | Belief Mutation | BELIEF_UPDATED | defeater_triggered |
|---------|---------------|-----------------|----------------|-------------------|
| TRIGGERED | Yes | Yes (frozen policy) | Yes | Required |
| NOT_TRIGGERED | Yes | Per frozen recovery | Yes if transition | No |
| INCONCLUSIVE | Yes | None | No | No |
| NOT_TESTABLE | Yes | None | No | No |

### Frozen Transition Policy ✅
- `POLICY_VERSION = "D5_V2_2026-07-26"` as literal constant.
- `TRIGGERED_TRANSITIONS` and `NOT_TRIGGERED_TRANSITIONS` are module-level dict literals.

### One-to-Many Claim Mapping ✅
- 1 DefeaterResult → 3 ConclusionClaims (outcome + belief_transition + discriminator).
- All 3 claims carry same `dr.result_id` in `defeater_result_ids` provenance.
- All 3 claims have `derivation_type=DEFEATER_TEST`.
- Not counted as multiple independent causal events.

### Defeater Does Not Encode ¬H ✅
- All triggers challenge reliability conditions (e.g., "Entity may not have properties that H assigns to it", "Service may not be present", "Version data may be inaccurate").
- None encode hypothesis negation.

## Regression & JUDGE Results

| Metric | Result |
|--------|--------|
| Total tests | **51/51 passing** |
| New D-5 tests | 11 (all pass) |
| JUDGE FAIL | 10 (all pre-existing, unchanged) |
| JUDGE CRASH | 0 |
| JUDGE FABRICATION | 0 |
| Strike counter | 1/3 (pre-existing, unchanged) |

## PlanDecision.consumed_transition_ids

Minimal typed provenance field added to `PlanDecision`:
```python
consumed_transition_ids: tuple[str, ...] = ()
```
This is causal provenance instrumentation only. No Planner scoring or selection logic was modified.

## Claims Status

| Claim | Status |
|-------|--------|
| Defeater generation is causally integrated | ✅ SUPPORTED |
| Defeater evaluation is causally integrated | ✅ SUPPORTED |
| Defeater results can change belief state | ✅ SUPPORTED |
| Changed belief state can affect subsequent planning | ✅ SUPPORTED |
| NO_DEFEATER/base candidate isolation | ✅ SUPPORTED |
| Hidden evaluator truth isolated from defeater generation | ✅ SUPPORTED |
| Defeater actions remain broker-controlled | ✅ SUPPORTED |
| RunConclusion preserves defeater provenance | ✅ SUPPORTED |
| Defeaters improve behavioral performance | ❌ NOT ESTABLISHED |
| Defeaters generalize to unseen scenarios | ❌ NOT ESTABLISHED |

## Limitations (Explicit)

1. **Behavioral efficacy not established.** The TRIGGERED result proves causal utilization, not behavioral superiority.
2. **Generalization not established.** All testing used controlled diagnostic scenarios, not unseen adversarial seeds.
3. **Single TRIGGERED observation.** The seven-gate proof used one naturally eligible result. Statistical claims require multi-seed evaluation.
4. **Arena scenario diversity limited.** Existing scenarios may not exercise full defeater range.

## Frozen Architecture Stack

```
D-0  RunConclusion / evaluation boundary          🟢 FROZEN
D-1  WorldModel                                   🟢 FROZEN
D-2  Planner                                      🟢 FROZEN
D-3  Falsification                                🟢 FROZEN
D-4  LLM semantic inference                       🟢 FROZEN
D-5  Defeater / counterfactual reasoning          🟢 FROZEN ← NEW
```

Stage 2.5D causal integration: **COMPLETE** ✅

Next phase: Behavioral efficacy evaluation (discriminative evaluation across unseen seeds/scenarios, paired ablations, safety, efficiency, counterexamples).
