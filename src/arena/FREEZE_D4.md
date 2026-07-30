# STAGE_2_5D_D4_LLM_CAUSAL — SUPERSEDED (Reopened for DECISION_RELEVANCE verification)

> **Status:** `SUPERSEDED` — This freeze record is preserved as an audit artifact only.
> The freeze was invalidated when planner changes introduced regressions and DECISION_RELEVANCE
> was not yet fully verified at the ID level.
>
> **Supersession chain:**
> 1. Original freeze (2026-07-26) — `FREEZE_ACCEPTED` (invalidated by planner regression)
> 2. Reopened for repair — D-4 `IMPLMENETED — REOPENED FOR DECISION_RELEVANCE VERIFICATION`
> 3. Planner repaired, regression restored to 25/27, DECISION_RELEVANCE proven at ID level
> 4. SENTINEL re-reviewed and confirmed: **`STAGE_2_5D_D4_LLM_CAUSAL_FROZEN`** (2026-07-26)
>
> See **`FREEZE_D4_VERIFIED.md`** for the authoritative freeze record.

**Original freeze date:** 2026-07-26
**Experiment:** Stage 2.5D — Causal Integration of LLM Semantic Inference
**Template:** `contradiction` (seed=0)
**Architectures tested:** FULL_RAPHAEL, NO_LLM, SCRIPTED_BASELINE

## Freeze Verdict (original)
🟢 `FREEZE_ACCEPTED` — SENTINEL confirmed (later invalidated).

D-4 has satisfied the causal-integration objective. **D-5 may now be planned, but implementation should not begin until its contract and experiment are specified.**

---

## 1. What D-4 has actually proven

The important achievement is not the four `MODEL_INFERENCE` claims.

It is this mechanically reconstructable chain:

```
TARGET_CONTROLLED observation (E17)
        │
        ▼
envelope (UNTRUSTED_DATA_BEGIN/END)
        │
        ▼
LLM semantic interpretation
        │
        ▼
raw provider response
        ├──────────────────────→ diagnostic episode record (redacted, non-operational)
        │
        ▼
parser / schema validator
        │
        ├── success ──→ SemanticInferenceSuccess
        │                    trust = TrustLevel.MODEL_INFERENCE
        │
        └── failure ──→ SemanticInferenceFailure
                             (never enters cognition)
        │
        ▼
validation / provenance attachment (externally assigned)
        │
        ▼
Evidence or Hypothesis machinery
        │
        ▼
cognitive component consumes SI (HypothesisManager)
        │
        ▼
SI-derived object affects belief/decision processing
        │
        ▼
decision or belief consequence
        │
        ▼
RunConclusion
```

And critically, removing the LLM removes that path:

```
NO_LLM

LLM invocations             = 0
SemanticInference produced  = 0
SI provenance               = 0
MODEL_INFERENCE claims      = 0
```

That establishes isolation.

### Causal classification

**`CAUSAL_INTEGRATION_DEMONSTRATED`**

### Behavioral classification

**`VALID_ZERO_BEHAVIORAL_DELTA`**

FULL and `NO_LLM` both produced:

`ABSTAIN_INCORRECT — 0.333`

despite substantially different internal reasoning artifacts.

That is also useful confirmation that the architecture-blind D-0 evaluator is behaving correctly: additional LLM traces and claims did not automatically buy FULL a higher score.

---

## 2. The INCONCLUSIVE results are legitimate

This deserves explicit preservation.

Your representative result was effectively:

```
E17 prior confidence = 0.67

        ↓

SI4 outcome = UNCLEAR (or low confidence)
posterior = None

        ↓

do NOT manufacture confidence reduction
```

That's preferable to forcing:

```
observation interpreted
→ therefore hypothesis false
```

The semantic inference supplied information, but the current falsification semantics determined that it was insufficient to justify a definitive belief revision.

Therefore:

> **No posterior update is itself a legitimate result of the semantic inference process.**

However, we should phrase one part of the D-4 claim carefully.

You reported:

> belief transition

For an `UNCLEAR` SI with `posterior_confidence=None`, there isn't really a numerical belief transition such as:

`0.67 → 0.31`.

What has been demonstrated is better described as:

> **semantic inference result consumed by the belief-processing path, with an explicit decision to preserve the existing belief because the result was inconclusive.**

That is still causal consumption.

Don't represent `0.67 → None` as though confidence became `None`. `None` means **no posterior confidence was established**, not that the hypothesis lost its confidence value.

This should become a regression invariant.

---

## 3. Freeze the distinction between three concepts

Raphael now needs to maintain these separately:

```text
OBSERVATION
    Target-controlled content.

SEMANTIC INTERPRETATION
    LLM performs an action intended to interpret the observation.

SEMANTIC INFERENCE RESULT
    Typed object (SemanticInferenceSuccess/Failure) with MODEL_INFERENCE trust,
    externally assigned provenance, and validation status.
```

D-4 demonstrated the first two and the **semantic inference evaluation mechanism**.

It did not yet produce a definitive `FALSIFIED` result in this diagnostic.

That is completely acceptable.

A future test should eventually demonstrate:

```text
SI = FALSIFIED
prior confidence = X
posterior confidence = Y
hypothesis state changes
```

but **do not modify D-4 or its scenario now to manufacture one**.

That belongs in later counterfactual/Defeater validation.

---

## 4. Gate counts

The six causal gates:

| Gate | FULL | NO_LLM | Verdict |
|------|------|--------|---------|
| INVOKED (`llm_inference`) | 4 | 0 | ✅ |
| PRODUCED (`produced_semantic_inference`) | 4 | 0 | ✅ |
| REFERENCED (`referenced_semantic_inference`) | 8 | 0 | ✅ |
| COGNITIVELY_CONSUMED (`cognitively_consumed_semantic_inference`) | 8 | 0 | ✅ |
| PROPOSED (hypothesis from SI) | 9 | 5 | ✅ |
| CONCLUSION (`MODEL_INFERENCE` claims) | 4 | 0 | ✅ |

This is stronger than the four-gate model used in D-1 through D-3 while preserving its spirit.

---

## 5. Failure semantics

All six failure modes produce `SemanticInferenceFailure` with zero cognitive artifacts:

| Failure mode | Detection | Downstream handling |
|---|---|---|
| **Provider timeout** | Call raises timeout or returns nothing within 15s | `SemanticInferenceFailure(failure_type="provider_timeout")`; zero evidence produced; no retry |
| **Provider API error** | HTTP 4xx/5xx, connection error | `SemanticInferenceFailure(failure_type="provider_api_error")`; zero evidence produced; no retry |
| **Refused response** | Provider returns structured refusal/finish reason (preferred); OR output fails to match schema | `SemanticInferenceFailure(failure_type="refused_response")`; zero evidence produced |
| **Malformed output** | JSON parse failure or schema validation failure | `SemanticInferenceFailure(failure_type="malformed_output")`; zero evidence produced |
| **Semantically unusable** | Parsed successfully but violates contract (category unknown, claim empty, confidence outside `[0,1]`) | `SemanticInferenceFailure(failure_type="semantically_unusable")`; inference not added to evidence graph |
| **Empty claim** | After `.strip()` the claim is empty | Treated as `semantically_unusable`; inference discarded |

**Invariant:** A `SemanticInferenceFailure` must never enter the evidence graph, hypothesis machinery, planner, or conclusion. It may be logged for diagnostics only.

**Invariant:** Provider failures must never cause downstream components to wait indefinitely. Hard timeout: 15s.

**Invariant:** Low confidence (`< 0.3`) is **not** a failure. It is valid epistemic information. Raphael should represent "the model weakly believes X" and the HypothesisManager can weight accordingly.

`SEMANTICALLY_UNUSABLE` is reserved for outputs that genuinely cannot map to the contract schema.

---

## 5. Architecture Status

Raphael has reached another milestone:

```text
D-0
RunConclusion / independent evaluation
              │
              ▼
D-1
WorldModel
INVOKED → PRODUCED → REFERENCED → DECISION_RELEVANT
              │
              ▼
D-2
Planner
INVOKED → PRODUCED → REFERENCED → DECISION_RELEVANT
              │
              ▼
D-3
Falsification
INVOKED → PRODUCED → REFERENCED → CONSUMED
              │
              ▼
D-4
LLM Semantic Inference
INVOKED → PRODUCED → REFERENCED → COGNITIVELY_CONSUMED → DECISION_RELEVANT → CONCLUSION
```

Status:

| Component | Implemented | Causally integrated | Isolated by ablation | Behavioral benefit proven |
|-----------|-------------|---------------------|----------------------|---------------------------|
| RunConclusion | ✅ | ✅ | N/A | N/A |
| WorldModel | ✅ | ✅ | ✅ | ❌ |
| Planner | ✅ | ✅ | ✅ | ❌ |
| Falsification | ✅ | ✅ | ✅ | ❌ |
| LLM cognition | Partial | ✅ | ✅ | ❌ |

Four cognitive mechanisms are now causally established. None has yet earned a generalized performance-improvement claim.

That's a substantially stronger position than simply having modules present.

---

## 6. Frozen Claim Ledger

I would add these exact entries.

**Claim WM-01:** WorldModel participates in operational decision-making.
**Status:** `DEMONSTRATED`
**Limitation:** no behavioral advantage demonstrated.

**Claim PL-01:** Planner participates in action selection through typed `PlanDecision`.
**Status:** `DEMONSTRATED`
**Limitation:** deterministic fallback matched outcome on tested DEV seed.

**Claim FA-01:** Contradictions can initiate discriminator actions and produce structured falsification results consumed downstream.
**Status:** `DEMONSTRATED`
**Limitation:** tested FRs were all `INCONCLUSIVE`; definitive belief rejection not demonstrated.

**Claim FA-02:** Active falsification improves task success.
**Status:** `UNTESTED`

**Claim SI-01:** LLM semantic interpretation produces typed inferences consumed by hypothesis machinery.
**Status:** `DEMONSTRATED`
**Limitation:** tested SIs were all `UNCLEAR` or low-confidence; definitive interpretation-driven belief update not demonstrated.

**Claim SI-02:** Active semantic interpretation improves task success.
**Status:** `UNTESTED`

**Claim LLM-01:** LLM inference materially participates in Raphael's cognitive decisions.
**Status:** `DEMONSTRATED`
**Limitation:** behavioral equivalence maintained; no performance claim.

That prevents future reports from accidentally upgrading architectural integration into performance claims.

---

## 7. D-5 is now authorized for specification only

The next target is:

> **D-5 — Defeater / Counterfactual Causal Integration**

But don't begin by "adding more Defeater calls."

The architectural question is:

> **What epistemic capability is the Defeater supposed to provide that falsification does not?**

The desired boundary should probably resemble:

```text
Contradictory evidence
        ↓
Defeater hypothesis
        ↓
Targeted discriminator
        ↓
Evidence that bears on the defeater
        ↓
DefeaterResult
trust = DEFEATER_INFERENCE
        ↓
Belief revision / hypothesis retirement
        ↓
RunConclusion
```

And then mechanically demonstrate:

```text
INVOKED
→ DefeaterResult PRODUCED
→ REFERENCED
→ DECISION_RELEVANT
```

while:

```text
NO_DEFEATER

Defeater calls             = 0
DefeaterResult             = 0
DEFEATER_INFERENCE path    = 0
```

Critically, **the Defeater must never convert TARGET_CONTROLLED text into an instruction**.

It interprets contradictions.

It does not acquire authority from them.

---

# Final SENTINEL directive

### Freeze now

**`STAGE_2_5D_D4_LLM_CAUSAL_FROZEN`**

### Record limitations

* behavioral result: `VALID_ZERO_BEHAVIORAL_DELTA` between FULL and NO_LLM;
* all four SIs were `UNCLEAR`/`INCONCLUSIVE` or low-confidence;
* definitive interpretation-driven confidence reduction remains unproven;
* SCRIPTED diagnostic was invalid due to infrastructure failure;
* two known Arena baseline test failures remain;
* `FALSIFICATION_FANOUT_HIGH` recorded but not optimized;
* Arena version-control weakness must be resolved before broader validation.

### Authorized next action

**Write the D-5 Defeater causal-integration specification only.**

No implementation yet.

The specification should tell FORGE exactly **what information enters the Defeater, what typed object comes out, what trust level it receives, who consumes it, what the NO_DEFEATER path retains, how contradiction/target-controlled text is contained, and what exact three-run experiment proves causal integration.**

Once that specification survives review, D-5 implementation can begin. 

---

*End of D-4 freeze record.*
