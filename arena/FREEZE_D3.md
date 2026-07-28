# STAGE_2_5D_D3_FALSIFICATION_CAUSAL_FROZEN

**Date:** 2026-07-26
**Experiment:** Stage 2.5D — Causal Integration of Falsification
**Template:** `contradiction` (seed=0)
**Architectures tested:** FULL_RAPHAEL, NO_FALSIFICATION, SCRIPTED_BASELINE

## Freeze Verdict
🟢 `FREEZE_ACCEPTED` — SENTINEL confirmed.

## Causal Classification
**`CAUSAL_INTEGRATION_DEMONSTRATED`**

Chain proven:
```
CONTRADICTS → ContradictionManager → discriminators → Planner → Broker → environment
→ FalsificationResult → belief-processing boundary → RunConclusion
```

## Behavioral Classification
**`VALID_ZERO_BEHAVIORAL_DELTA`**

| Architecture | Outcome | Score | Claims | FT Claims |
|---|---|---|---|---|
| FULL_RAPHAEL | ABSTAIN_INCORRECT | 0.333 | 40 | 8 |
| NO_FALSIFICATION | ABSTAIN_INCORRECT | 0.333 | 13 | 0 |

Architecture-blind evaluator produced identical scores despite different internal reasoning artifacts.

## Falsification Results
4 FRs, 1 hypothesis, 3 contradictions, 4 discriminator IDs, 0 semantic duplicates.

All 4 outcomes: **`INCONCLUSIVE`** with `posterior_confidence=None`.

> No posterior update is itself a legitimate result of the falsification process. The falsification mechanism determined that the discriminator evidence was insufficient to justify definitive belief revision. `None` means "no posterior confidence was established", not that confidence became zero.

## Ablation Isolation
NO_FALSIFICATION exhibits:
- 0 falsification invocations
- 0 FalsificationResults
- 0 FR provenance in claims
- 0 falsification_test claims

Contradiction detection still occurs (5 traces) but does not trigger discriminator actions or produce falsification results.

## Verified Invariants
- Architecture ID not in evaluator logic
- Evaluator receives only `RunConclusion + truth`
- All 7 adapters have uniform `build()` interface
- Broker policies control all actions (0 denied in contradiction run)
- NO_BROKER configuration explicitly forbidden
- Safety failures propagate to evaluator

## Frozen Claim Ledger

| Claim | Status | Limitation |
|---|---|---|
| **WM-01:** WorldModel participates in operational decision-making | DEMONSTRATED | No behavioral advantage demonstrated |
| **PL-01:** Planner participates in action selection via typed PlanDecision | DEMONSTRATED | Deterministic fallback matched outcome on tested DEV seed |
| **FA-01:** Contradictions initiate discriminator actions; FR consumed downstream | DEMONSTRATED | Tested FRs all INCONCLUSIVE; definitive belief rejection not demonstrated |
| **FA-02:** Active falsification improves task success | UNTESTED | — |
| **LLM-01:** LLM inference materially participates in Raphael's cognitive decisions | UNTESTED | — |

## Known Limitations
- SCRIPTED_BASELINE produced `INFRA_FAILURE`; three-way behavioral comparison invalid
- 2 pre-existing Arena test failures (`KNOWN_BASELINE_INFRASTRUCTURE_GAPS`)
- `FALSIFICATION_FANOUT_HIGH` observed (4 FRs on 1 hypothesis) — not optimized
- Arena code not version-controlled — historical freeze integrity cannot be established via git

## Architecture Status
| Component | Implemented | Causally Integrated | Isolated by Ablation | Behavioral Benefit |
|---|---|---|---|---|
| RunConclusion | ✅ | ✅ | N/A | N/A |
| WorldModel | ✅ | ✅ | ✅ | ❌ |
| Planner | ✅ | ✅ | ✅ | ❌ |
| Falsification | ✅ | ✅ | ✅ | ❌ |
| LLM cognition | Partial | ❌ | Not demonstrated | ❌ |

## Next Authorized Action
D-4 LLM Causal-Integration **specification only** — no implementation until specification survives review.

## Referenced Freezes
- STAGE_2_5D_D0_FROZEN (RunConclusion)
- STAGE_2_5D_D1_WORLDMODEL_CAUSAL_FROZEN (WorldModel)
- STAGE_2_5D_D2_PLANNER_CAUSAL_FROZEN (Planner)
