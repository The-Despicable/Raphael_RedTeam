# D-5 Specification — Defeater / Counterfactual Reasoning Causal Integration

**Status:** `D5_SPEC_V2_APPROVED` — Implementation authorized (SENTINEL 2026-07-26)
**Date:** 2026-07-26
**Supersedes:** Nothing. D-5 builds on D-0 through D-4 frozen substrate.

---

## 1. Central Question

**What evidence would cause Raphael to stop believing its current hypothesis or change its intended decision?**

The Defeater is **not** another hypothesis generator, planner, or LLM cognition module. It answers a narrower question: **"What would make hypothesis H unreliable?"** — and then seeks an observation that can test that question.

---

## 2. Causal Chain

```
Hypothesis H (existing, from HypothesisManager)
    │
    ▼
Defeater D constructed for H
    │  ┌─────────────────────────────────────┐
    │  │ "Under what conditions would H lose │
    │  │  support?"                           │
    │  └─────────────────────────────────────┘
    │
    ▼
DiscriminatingObservation / Action proposed
    │  (an executable action whose result bears on D)
    │
    ▼
CapabilityBroker → authorize
    │
    ▼
ExecutionEngine → execute
    │
    ▼
Observation → Evidence (added to EvidenceGraph)
    │
    ▼
Defeater evaluation
    │
    ├── NOT_TRIGGERED → Discriminating evidence contradicts the defeating condition. H survives.
    ├── TRIGGERED   → Defeating condition observed. H loses confidence/support.
    ├── INCONCLUSIVE → Evidence cannot determine whether the defeating condition holds.
    └── NOT_TESTABLE → No authorized discriminating test exists.
    │
    ▼
Hypothesis confidence / state transition
    │
    ▼
Planner reconsideration (if triggered, candidate set may change)
    │
    ▼
RunConclusion (claims carry defeater_result_ids)
```

---

## 3. Typed Contracts

### 3.1 DefeaterTrigger (input to Defeater construction)

```python
@dataclass(frozen=True)
class DefeaterTrigger:
    """The condition that would make a hypothesis unreliable.

    This is NOT a hypothesis itself. It is a reliability condition
    expressed as a structured predicate: "If X is observed, H is unreliable."

    A DefeaterTrigger is a PROPOSAL, never an authorization.
    The suggested action MUST pass through the CapabilityBroker
    and may be rejected if the broker denies it.
    """
    defeater_id: str  # "df_<12hex>"
    hypothesis_id: str  # The hypothesis this defeater applies to
    condition_description: str  # Human-readable: "What would make H unreliable"
    # The specific observation predicate that would trigger this defeater
    target_predicate: Optional[ConclusionPredicate]
    target_entity: str  # entity whose observation would trigger this
    # How confident we are that this condition would actually invalidate H
    relevance_confidence: float  # [0.0, 1.0]
    # How to test it (what kind of action would produce relevant evidence)
    suggested_action_type: str  # e.g., "direct_probe", "http_get", "scan"
    suggested_target: str  # target entity for the discriminating action

    # Provenance (externally assigned)
    generated_at: float = field(default_factory=time.time)
    generated_by: str = "defeater_generator"  # or "llm_defeater" if LLM-augmented
    source_evidence_ids: tuple[str, ...] = ()
    source_hypothesis_id: str = ""
```

### 3.2 DefeaterResult (output of Defeater evaluation)

```python
class DefeaterOutcome(str, Enum):
    NOT_TRIGGERED = "not_triggered"  # Discriminating evidence contradicts the defeating condition. H survives.
    TRIGGERED = "triggered"          # Defeating condition observed. H loses confidence/support.
    INCONCLUSIVE = "inconclusive"    # Evidence cannot determine whether the defeating condition holds.
    NOT_TESTABLE = "not_testable"    # No authorized discriminating test exists.

@dataclass(frozen=True)
class DefeaterResult:
    """The causal intermediate between evidence collection and belief revision.

    Causal chain:
      DefeaterTrigger → DiscriminatingAction → Observation
        → Evidence → DefeaterResult → Hypothesis change → Planner change
    """
    result_id: str  # "dr_<12hex>"
    defeater_id: str
    hypothesis_id: str
    outcome: DefeaterOutcome

    # Evidence that triggered or supported
    triggering_evidence_ids: tuple[str, ...] = ()
    supporting_evidence_ids: tuple[str, ...] = ()

    # Action that produced the evidence
    discriminating_action_id: str = ""
    discriminating_observation_ids: tuple[str, ...] = ()

    # Confidence/relevance update
    prior_hypothesis_confidence: Optional[float] = None
    posterior_hypothesis_confidence: Optional[float] = None
    defeater_relevance_updated: Optional[float] = None

    # Rationale
    reason_codes: tuple[str, ...] = ()

    # Traceability
    generated_at: float = field(default_factory=time.time)
    plan_decision_id: str = ""  # trace back to Planner decision that scheduled the action
```

### 3.3 Provenance addition to ConclusionClaim

Add to `ConclusionProvenance`:
```python
defeater_result_ids: tuple[str, ...] = ()  # D-5: DefeaterResult IDs
```

Add to `DerivationType`:
```python
DEFEATER_TEST = "defeater_test"
```

---

## 4. Causal Gates (D-5 specific)

| Gate | Definition | Evidence |
|---|---|---|---|
| **INVOKED** | `DefeaterGenerator` is called for a specific hypothesis | Trace: `defeater_invocation` for hypothesis H |
| **PRODUCED** | `DefeaterTrigger` object is created | Trace: `produced_defeater_trigger` with trigger ID |
| **REFERENCED** | The trigger informs candidate generation (discriminating action proposed) | Trace: `referenced_defeater_trigger` — candidate records `defeater_trigger_id` |
| **EVALUATED** | `DefeaterResult` is produced from evidence | Trace: `defeater_result` with outcome (`NOT_TRIGGERED`, `TRIGGERED`, `INCONCLUSIVE`, `NOT_TESTABLE`) |
| **BELIEF_UPDATED** | Hypothesis confidence/state changed as a direct consequence of the DefeaterResult | Trace: Hypothesis transition recorded with `defeater_result_id`. Confidence delta or state change observable. |
| **DECISION_RELEVANT** | Subsequent `PlanDecision` references the defeater-induced belief change | Trace: Planner rationale includes `defeater_triggered` (if TRIGGERED) or `defeater_survived` (if NOT_TRIGGERED). Decision artifact references `defeater_result_id`. |
| **CONCLUSION** | ConclusionClaim carries `defeater_result_ids` in provenance | Trace: claim provenance includes `dr_*` ID |

**Key rules:**
- `INCONCLUSIVE` may satisfy EVALUATED (execution/result-production evidence) but **cannot by itself satisfy BELIEF_UPDATED or DECISION_RELEVANT**. A result of `INCONCLUSIVE` with no belief transition does not establish DF-02 or DF-03.
- `TRIGGERED` requires **both** BELIEF_UPDATED (observable hypothesis transition) **and** DECISION_RELEVANT (subsequent Planner reconsideration referencing the transition).
- `NOT_TRIGGERED` satisfies BELIEF_UPDATED if confidence increases or the hypothesis is reaffirmed, and DECISION_RELEVANT if the Planner references the reaffirmation.

**Note:** D-5 uses seven gates — extending the D-4 model with EVALUATED and BELIEF_UPDATED. The Defeater does not pass through an LLM interpretation stage, so D-4's COGNITIVELY_CONSUMED is omitted. The full chain is:

`INVOKED → PRODUCED → REFERENCED → EVALUATED → BELIEF_UPDATED → DECISION_RELEVANT → CONCLUSION`

---

## 5. NO_DEFEATER Ablation

The `NO_DEFEATER` ablation must achieve zero across all seven gates:

```
INVOKED    = 0  (no DefeaterGenerator calls)
PRODUCED   = 0  (no DefeaterTrigger objects)
REFERENCED = 0  (no defeater-derived candidates)
EVALUATED  = 0  (no DefeaterResult objects)
BELIEF_UPDATED = 0  (no defeater-driven belief changes)
DECISION_RELEVANT = 0  (no defeater rationale in Planner)
CONCLUSION = 0  (no defeater_result_ids in ConclusionClaim)
```

while retaining:
- HypothesisManager (unchanged)
- Planner (unchanged)
- Candidate generation (unchanged)
- All deterministic action execution

**Structural implementation:** The `NO_DEFEATER` config simply skips the `defeater_generation` and `defeater_evaluation` steps in the cognitive loop. The rest of Raphael operates identically.

### 5.1 Candidate-set isolation (critical contract)

The base candidate set must be identical between FULL and NO_DEFEATER:

```
BaseCandidates(FULL) == BaseCandidates(NO_DEFEATER)
```

FULL may subsequently **augment** that base set with explicitly defeater-derived discriminating actions. NO_DEFEATER receives the identical base candidate set and simply does not receive the defeater augmentation.

This mirrors the isolation established in D-2 (Planner isolation) and ensures that any behavioral difference can be causally attributed to the Defeater path rather than differences in candidate availability.

**Enforcement:** The candidate-generation function runs once, producing the base set. If `defeater_enabled`, additional defeater-derived candidates are appended. The base set is never modified — only extended. Traces must distinguish base candidates from defeater-derived candidates (e.g., via a `derived_from_defeater_id` field).

---

## 5.5 Belief-Update Policy (preregistered, not tunable)

### 5.5.1 Mechanism
D-5 **must reuse the existing frozen belief-update mechanism** from D-3 (`HypothesisManager.update_confidence()` and `HypothesisManager.falsify()`). No new confidence-calculation or hypothesis-transition algorithm may be introduced for D-5.

If the existing mechanism cannot represent the belief change required by a DefeaterResult (e.g., it lacks a `defeater_result_id` field), a minimal extension is permitted **only** to add the provenance reference, not to alter the transition logic.

### 5.5.2 Transition policy (preregistered)
For a `TRIGGERED` outcome, the following deterministic policy is preregistered:

| Prior state | Prior confidence (example) | Posterior confidence | Posterior state |
|---|---|---|---|
| POSTULATED | ≥ 0.5 | prior × 0.5 | DOUBTFUL |
| POSTULATED | < 0.5 | prior × 0.3 | ABANDONED |
| DOUBTFUL | any | prior × 0.3 | ABANDONED |
| ABANDONED | any | unchanged | ABANDONED |

For a `NOT_TRIGGERED` outcome:

| Prior state | Prior confidence (example) | Posterior confidence | Posterior state |
|---|---|---|---|
| POSTULATED | any | min(1.0, prior × 1.2) | POSTULATED |
| DOUBTFUL | ≥ 0.3 | prior × 1.2 | POSTULATED |
| DOUBTFUL | < 0.3 | unchanged | DOUBTFUL |
| ABANDONED | any | unchanged | ABANDONED |

For an `INCONCLUSIVE` outcome: **No belief change.** Confidence and state remain unchanged.

### 5.5.3 No post-result tuning
The above transition rules must be written into the implementation **before** any diagnostic execution. Post-hoc modification based on Arena score, evaluator output, or behavioral observation is prohibited.

**Enforcement:** The implementation must contain the transition table as a literal constant (not loaded from a config file that could be silently changed between runs). The diagnostic report must state the exact transition rule applied for each DefeaterResult.

---

## 6. Three Prohibited Shortcuts (must be enforced by spec)

### ❌ Shortcut 1: Deriving defeaters from evaluator truth
The Defeater must not receive or derive information from the evaluator's ground truth (`scenario.evaluator_truth`). Nor may it access any success condition, gold answer, or expected outcome.

**Structural invariant (auditable by inspection):**

> `DefeaterGenerator` and `DefeaterEvaluator` MUST NOT import, reference, receive, close over, or indirectly query:
> - `evaluator_truth`
> - `expected_outcome`
> - `EvaluationResult`
> - scoring state or score thresholds
> - architecture-specific evaluator output
> - any field of `ArenaScenario` beyond `scenario_id` (for tracing only)

**Enforcement at API level:** The `DefeaterGenerator` constructor and `generate()` method receive only the `Hypothesis` and its supporting `Evidence`. Neither `ArenaScenario`, `EvaluationResult`, nor any success metric is passed to or accessible from the Defeater module. If a defeater happens to match a ground-truth condition (e.g., "if port 22 is closed"), that is acceptable coincidence — but the generator must not use the truth to construct the trigger.

**Code review check:** Before D-5 implementation is merged, a reviewer must confirm that no file in the defeater module imports from `arena.runner`, `arena.evaluator`, or any test/validation namespace containing expected outcomes.

### ❌ Shortcut 2: Encoding the correct answer
A defeater must not be so specifically defined that it directly encodes the final answer. Example of what is **prohibited**:

> Hypothesis: "10.0.40.10 is controlled by adversary"
> Defeater: "If we observe that 10.0.40.10:22 serves SSH with version OpenSSH_8.9p1, then H is unreliable"

This is too specific — it encodes a precise version expectation that happens to match the truth. The defeater should instead express a **generic reliability condition**, e.g.:

> "If the service on 10.0.40.10:22 does not match the behavior expected of an adversary-controlled host"

The `condition_description` and `target_predicate` should be at the level of **epistemic reliability**, not **factual specificity**.

**Enforcement:** Review whether the defeater could have been written without knowing the ground truth. If removing the ground truth would change the defeater's trigger condition to something unreasonably broad or meaningless, the defeater is likely encoding the answer.

### ❌ Broker isolation: Trigger is proposal, never authorization
The `suggested_action_type` and `suggested_target` fields inside `DefeaterTrigger` are **proposals**, not commands. Every discriminating action derived from a DefeaterTrigger must pass through the existing `CapabilityBroker` — the same broker used for all other candidate actions.

**The Defeater cannot:**
- Expand the set of allowed action types.
- Grant access to targets that the broker would otherwise deny.
- Bypass or override any existing Broker policy.
- Create authorized actions for capabilities that do not exist.

**Enforcement:** The candidate-generation path for defeater-derived discriminating actions calls the same `CapabilityBroker.authorize()` method used for every other candidate. There is no special bypass, no elevated trust level, and no implicit authorization. If the broker denies the action, it is recorded as `NOT_TESTABLE` in the DefeaterResult (the discriminating test could not be executed due to policy constraints).

### ❌ Shortcut 3: Counting creation as integration
Instantiating a `DefeaterTrigger` object is **not** causal integration. The causal chain must be complete:

**For TRIGGERED:** All three of:
1. **BELIEF_UPDATED** — hypothesis confidence decreases OR hypothesis state changes (e.g., `POSTULATED → DOUBTFUL` or `ABANDONED`), linked by `defeater_result_id`.
2. **DECISION_RELEVANT** — the subsequent `PlanDecision` references the defeater-induced change (rationale includes `defeater_triggered`).
3. **CONCLUSION** — `ConclusionClaim` carries the `defeater_result_id` in provenance.

**For NOT_TRIGGERED:** All three analogous conditions apply: BELIEF_UPDATED (confidence may increase or hypothesis reaffirmed), DECISION_RELEVANT (rationale includes `defeater_survived`), CONCLUSION.

**For INCONCLUSIVE:** EVALUATED is satisfied; BELIEF_UPDATED and DECISION_RELEVANT are **not** established by this outcome alone.

**Enforcement:** The diagnostic must show:
- A concrete before/after difference in hypothesis state (BELIEF_UPDATED).
- A Planner rationale code referencing the defeater result (DECISION_RELEVANT).
- A ConclusionClaim carrying `defeater_result_id` (CONCLUSION).

If all three are identical with and without the Defeater, causal integration is not demonstrated.

---

## 7. Diagnostic Experiment

### 7.1 Target scenario
Use the existing `contradiction` template on DEV seed 0 (same as D-4 diagnostic). The contradiction template produces conflicting evidence that should be resolvable by a discriminating action — making it suitable for Defeater testing.

If the contradiction template proves insufficient to trigger a Defeater, a dedicated `defeater` template may be created **only after** the failure is diagnosed, and only with SENTINEL approval.

### 7.2 Three architectures

| Architecture | Defeater | Hypothesis | Planner | LLM | Expected |
|---|---|---|---|---|---|
| `FULL_RAPHAEL` | ✅ | ✅ | ✅ | ✅ | Defeater triggers, results produced, hypothesis changes occur |
| `NO_DEFEATER` | ❌ | ✅ | ✅ | ✅ | No defeater artifacts, otherwise identical cognition |
| `SCRIPTED_BASELINE` | ❌ | ❌ | ❌ | ❌ | Direct observation only |

### 7.3 Success criteria

**Required:**
1. `FULL_RAPHAEL` produces at least one `DefeaterTrigger` for a hypothesis (INVOKED + PRODUCED).
2. At least one `DefeaterResult` has outcome `TRIGGERED` or `NOT_TRIGGERED` (not solely `INCONCLUSIVE` or `NOT_TESTABLE`).
3. The `TRIGGERED` or `NOT_TRIGGERED` result is causally linked to a hypothesis confidence or state change (BELIEF_UPDATED).
4. A subsequent `PlanDecision` references the defeater-induced belief change via rationale code `defeater_triggered` or `defeater_survived` (DECISION_RELEVANT).
5. `NO_DEFEATER` produces zero defeater artifacts across all seven gates.
6. `SCRIPTED_BASELINE` runs without crashing (addresses the pre-existing `_conclusion` INFRA_FAILURE if possible, but this is NOT a D-5 requirement).

**Note on INCONCLUSIVE:** An all-INCONCLUSIVE diagnostic is not a D-5 failure if the mechanism correctly ran and produced no definitive evidence. However, such a result does NOT satisfy DF-02 or DF-03, and D-5 freeze would require a preregistered explanation of why no triggerable defeating condition existed on the chosen scenario.

**Not required:**
- Behavioral delta between FULL and NO_DEFEATER (zero delta is acceptable).
- Any particular score threshold on any architecture.

### 7.4 Causal trace ID chain (target)

```
Hypothesis H
    │ hypothesis_id = "hyp_abcd1234"
    ▼
DefeaterTrigger dt_1
    │ defeater_id = "df_0001"
    │ hypothesis_id = "hyp_abcd1234"
    ▼                                              ─── INVOKED
PlanDecision PD_8
    │ rationale includes "defeater_driven"
    │ selected action is the discriminating action
    ▼                                              ─── PRODUCED / REFERENCED
Observation / Evidence E44
    ▼                                              ─── EVALUATED
DefeaterResult dr_1
    │ outcome = TRIGGERED (or NOT_TRIGGERED)
    │ hypothesis_id = "hyp_abcd1234"
    ▼                                              ─── BELIEF_UPDATED
Hypothesis H updated
    │ confidence: 0.8 → 0.3  (if TRIGGERED)
    │ state: POSTULATED → DOUBTFUL  (if TRIGGERED)
    │ defeater_result_id = "dr_1"
    ▼                                              ─── DECISION_RELEVANT
PlanDecision PD_9 (subsequent)
    │ rationale includes "defeater_triggered"
    │ source = DR7/H8
    │ different candidate than PD_8 (behavioral delta NOT required)
    ▼                                              ─── CONCLUSION
ConclusionClaim C_claim
    │ provenance.defeater_result_ids = ("dr_1",)
```

---

## 8. Implementation Outline (for reference only — NOT to be executed until spec is reviewed)

**Note:** The following is an architectural sketch to make the spec concrete. No code will be written until SENTINEL reviews and approves.

### 8.1 New files
- `arena/defeater.py` — `DefeaterTrigger`, `DefeaterResult`, `DefeaterOutcome`, `DefeaterGenerator`, `DefeaterEvaluator`
- `arena/defeater_adapters.py` — adapter from DefeaterResult to ConclusionClaim

### 8.2 Modified files
- `arena/conclusion.py` — add `defeater_result_ids` to `ConclusionProvenance`, add `DEFEATER_TEST` to `DerivationType`
- `arena/conclusion_adapters.py` — add defeater adapter path
- `arena/ablation.py` — add `NO_DEFEATER` to `ABLATION_PRESETS`
- `arena/ablation_runner.py` — add defeater invocation to cognitive loop
- `orchestrator/brain/hypothesis.py` — add `defeater_result_ids` field to `Hypothesis` (optional, for traceability)

### 8.3 NO_DEFEATER guard
```python
# In the cognitive loop:
if config.defeater_enabled:
    trigger = defeater_generator.generate(hypothesis)
    if trigger:
        # Add discriminating action to candidate set
        candidates.append(trigger.to_action_candidate())
```

---

## 9. Acceptance Criteria for D-5 Freeze

The freeze review will verify:

1. **Causal chain completeness:** All seven gates (INVOKED → PRODUCED → REFERENCED → EVALUATED → BELIEF_UPDATED → DECISION_RELEVANT → CONCLUSION) are demonstrated at the ID level.
2. **NO_DEFEATER isolation:** Zero defeater artifacts across all cognitive components.
3. **No shortcut violations:** The specification and implementation do not violate the three prohibited shortcuts (no evaluator truth, no encoded answers, no counting creation as integration).
4. **Regression integrity:** The 25/27 baseline (or better) is maintained. New failures must be explicitly declared as D-5 infrastructure or design gaps.
5. **Claim discipline:** Behavioral improvement claims remain `NOT ESTABLISHED` unless separately proven.

---

## 10. Claim Ledger (target for D-5 freeze)

| Claim | Target Status | Meaning |
|---|---|---|
| DF-01 | `SUPPORTED` | Defeater triggers generated (INVOKED + PRODUCED) |
| DF-02 | `SUPPORTED` | Evidenced DefeaterResult produced with outcome TRIGGERED or NOT_TRIGGERED (EVALUATED) |
| DF-03 | `SUPPORTED` | DefeaterResult causes observable hypothesis confidence/state change (BELIEF_UPDATED) |
| DF-04 | `SUPPORTED` | Subsequent PlanDecision references the defeater-induced change (DECISION_RELEVANT) |
| DF-05 | `SUPPORTED` | ConclusionClaim carries defeater_result_ids in provenance (CONCLUSION) |
| DF-06 | `SUPPORTED` | NO_DEFEATER removes all defeater artifacts across all seven gates |
| DF-07 | `NOT ESTABLISHED` | Behavioral improvement from Defeater reasoning |
| DF-08 | `NOT ESTABLISHED` | Generalization to unseen scenarios |

**Note on DF-02 and INCONCLUSIVE:** A DefeaterResult with outcome `INCONCLUSIVE` satisfies DF-01 (trigger generation) and partially satisfies DF-02 (result produced), but does **not** satisfy DF-03, DF-04, or DF-05 (no belief update, no planner consequence, no conclusion provenance). A diagnostic with only INCONCLUSIVE results cannot achieve D-5 freeze.

---

*End of D-5 specification draft. Ready for SENTINEL review.*
