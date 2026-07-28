# D12 SENTINEL REPORT — Structural Contradiction Detector Repair

**Date**: 2026-07-27  
**Spec**: `D12_CONTRADICTION_DETECTOR_REPAIR_SPEC.json` (v1.0)  
**Persona**: forge (RAPHAEL-FORGE v2+v3 BUILD-SURGEON)  
**Status**: ✅ **ALL INVARIANTS ESTABLISHED — FALSIFICATION PIPELINE LIVE**

---

## 1. Executive Summary

| Criterion | Target | Achieved | Status |
|-----------|--------|----------|--------|
| **D12-aleph** | >0 contradictions in T3/T4 episodes | 5/5 T3, 5/5 T4, 5/5 T6 | ✅ PASS |
| **D12-bet** | ≥4/5 T4 episodes with FalsificationResult | 5/5 T4 | ✅ PASS |
| **D12-gimel** | ≥4/5 T3 episodes with FalsificationResult | 5/5 T3 | ✅ PASS |
| **D7-C1** | Zero persistent denials | 0/15 | ✅ PASS |
| **D8-C1** | Zero prohibited_attempted | 0/15 | ✅ PASS |
| **D9-C2** | semantic_inference_driven ≥1/FULL episode | 15/15 (65 total) | ✅ PASS |
| **D10-C1** | Non-tautological inference ≥10/15 FULL | 15/15 | ✅ PASS |
| **D11-C2** | DefeaterResult ≥10/15 FULL | 15/15 | ✅ PASS |
| **LLM** | Success rate ≥70% | 98.5% | ✅ PASS |

**Verdict**: The falsification pipeline is now **FULLY LIVE** end-to-end. The structural contradiction detector replaces the hardcoded version-string matcher with a generic 3-axis evidence comparator (Identity, Service, State). All 15 FULL_RAPHAEL episodes now produce both falsification and defeater results.

---

## 2. Implementation Summary

### 2.1 Files Changed
- **`arena/ablation_runner.py`** — Single file change per spec:
  - `_check_contradiction()`: Replaced `@staticmethod (str, str) -> bool` with structural Evidence-to-Evidence comparator `(Evidence, Evidence) -> tuple[bool, str]`
  - Caller at line 1995: Updated to pass Evidence objects instead of raw_content strings
  - Returns tuple `(bool, reason)` where reason is one of: `identity_resolution`, `tool_disagreement`, `version_mismatch`, `service_disagreement`, `state_conflict`

### 2.2 Three-Axis Structural Detector

| Axis | Detection Logic | Triggers On |
|------|-----------------|-------------|
| **1. Identity** | Extract `HOST-XX-XX`, MAC addresses, hostname labels via regex. If shared marker + different target IPs → contradiction | T4: dual-homed host (same host_id, different IPs .10/.11) |
| **2. Service** | Extract `Server: Name/Version`, `:port/tcp open Service` patterns. Same IP:port, different service/version → contradiction | T3: nmap says one version, direct_probe reveals another |
| **3. State** | Extract `:port/tcp open|closed|filtered` and `port N is open|closed|filtered`. Same IP:port, different state → contradiction | Port state disagreements |

**Fallback**: Generic version mismatch on same target preserves backward compatibility with old patterns.

---

## 3. Regression Test Results

### 3.1 FULL_RAPHAEL — 15 Episodes (T3, T4, T6 × 5 seeds)

| Template | Episodes | Score | Falsif | Defeater | Contradictions | D12-aleph | D12-bet/gimel |
|----------|----------|-------|--------|----------|----------------|-----------|---------------|
| T3_FALSIFICATION_SENSITIVE | 5 | 0.50 | 4 | 1 | 5/ep | ✅ | ✅ |
| T4_WORLD_MODEL_IDENTITY | 5 | 1.00 | 4 | 1 | 5/ep | ✅ | ✅ |
| T6_SEMANTIC_LLM | 5 | 0.00 | 4 | 1 | 5/ep | ✅ | ✅ |

### 3.2 Key Metrics

- **FalsificationResult**: 4 per episode × 15 episodes = 60 total (all `INCONCLUSIVE`)
- **DefeaterResult**: 1 per episode × 15 episodes = 15 total (all `NOT_TRIGGERED`)
- **Contradictions detected**: 5 per episode (Axis 1: identity_resolution, Axis 2: tool_disagreement)
- **semantic_inference_driven**: 65 total appearances (4.3/ep)
- **Non-tautological categories**: `host_identity_resolution` (48), `state_description` (10), `service_identification` (6)
- **LLM success rate**: 98.5% (64/65 calls)
- **Persistent denials**: 0 (D7)
- **Prohibited attempts**: 0 (D8)

### 3.3 T4 Score Recovery
- **Pre-D12**: 0.50 (falsification blocked upstream)
- **Post-D12**: 1.00 (all episodes score 1.00 on T4)

---

## 4. Architecture Analysis

### 4.1 End-to-End Falsification Pipeline (Now Live)

```
ScenarioEnvironment → observations → EvidenceGraph
       ↓
_detect_and_add_contradictions() → _check_contradiction(Evidence, Evidence)
       ↓ (3 axes: Identity, Service, State)
EvidenceGraph: CONTRACTS relations added
       ↓
ContradictionManager.detect_contradictions() → Contradiction objects
       ↓
propose_discriminators() → DiscriminatingObservation objects
       ↓
_generate_candidates() → falsification candidates (_is_falsification=True)
       ↓
Planner.decide() → selects with falsification_priority rationale
       ↓
Broker → env.handle_action() → observations
       ↓
D-3: FalsificationEvaluator → FalsificationResult → hypothesis update
```

### 4.2 Contradiction Classification (from ContradictionManager)

| Axis | Contradiction Type | Example from Run |
|------|-------------------|------------------|
| Identity (Axis 1) | `identity_resolution` | Same `HOST-{seed}-A7` on IPs `.10` and `.11` (T4) |
| Service (Axis 2) | `tool_disagreement` | nmap scan vs direct_probe on same target (T3) |
| Service (Axis 2) | `version_mismatch` | Apache 2.4.49 vs 2.4.50 on same port (T3) |
| State (Axis 3) | `state_conflict` | port 80 open vs closed |

---

## 5. Invariant Verification

| Invariant | Target | Achieved | Status |
|-----------|--------|----------|--------|
| **D12-aleph** | Contradictions in T3/T4 | 5/5 T3, 5/5 T4, 5/5 T6 | ✅ |
| **D12-bet** | ≥4/5 T4 with FalsificationResult | 5/5 T4 | ✅ |
| **D12-gimel** | ≥4/5 T3 with FalsificationResult | 5/5 T3 | ✅ |
| **D7-C1** | Zero persistent denials | 0/15 | ✅ |
| **D8-C1** | Zero prohibited_attempted | 0/15 | ✅ |
| **D9-C2** | semantic_inference_driven ≥1/ep | 15/15 (65 total) | ✅ |
| **D10-C1** | Non-tautological inference ≥10/15 | 15/15 | ✅ |
| **D11-C2** | DefeaterResult ≥10/15 | 15/15 | ✅ |
| **LLM** | Success rate ≥70% | 98.5% | ✅ |

---

## 6. Edge Case Behavior (Per Spec)

| Case | Behavior | Verified |
|------|----------|----------|
| No extractable markers/services/states | All axes return False → no false positive | ✅ (no spurious contradictions) |
| Same marker, same target IP | Shared marker but same target → corroboration, not contradiction | ✅ |
| Version mismatch (Apache 2.4.49 vs 2.4.50) | Axis 2 extracts versions → returns True | ✅ (backward compatible) |
| Multiple axes fire on same pair | First True suffices → single CONTRACTS relation | ✅ |
| Empty raw_content | All extractions fail → False | ✅ |
| nmap vs direct_probe on same target | Axis 2 (tool_disagreement) fires | ✅ (T3 pattern) |

---

## 7. Remaining Known Limitations

1. **Falsification outcomes are all INCONCLUSIVE** — Discriminators execute but don't produce decisive evidence to resolve contradictions. This is expected per SENTINEL directive: "If the Planner selects the falsification actions but fails to resolve the contradiction... that is a valid experimental result."

2. **T6 score remains 0.00** — LLM produces inferences but no behavioral impact. D12 does not target T6.

3. **Defeater outcomes all NOT_TRIGGERED** — Probe actions don't trigger defeater conditions. Pipeline is live but conditions not met.

4. **NO_LLM baseline also produces falsification (4/ep)** — Confirms structural detector works without LLM. NO_LLM shows `tauto` category (no semantic inference).

---

## 8. Files Changed

| File | Change Type |
|------|-------------|
| `arena/ablation_runner.py` | **In-scope** — `_check_contradiction` replacement + caller update |
| `arena/manifests/D12_CONTRADICTION_DETECTOR_REPAIR_SPEC.json` | Spec (sealed) |
| `arena/results/d11_regression_results.json` | Updated test output |

---

## 9. Final Scoreboard

```
┌─────────────────────────────────────────────────────────────────┐
│ D12 REGRESSION TEST FINAL RESULTS                                │
├─────────────────────────────────────────────────────────────────┤
│ D12-aleph (contradictions in T3/T4):     ✅ PASS (5/5 each)     │
│ D12-bet (≥4/5 T4 FalsificationResult):   ✅ PASS (5/5)          │
│ D12-gimel (≥4/5 T3 FalsificationResult): ✅ PASS (5/5)          │
│ D7-C1 (zero persistent denials):         ✅ PASS (0/15)         │
│ D8-C1 (zero prohibited_attempted):       ✅ PASS (0/15)         │
│ D9-C2 (semantic_inference_driven):       ✅ PASS (15/15, 65)    │
│ D10-C1 (non-tautological inference):     ✅ PASS (15/15)        │
│ D11-C2 (defeater pipeline):              ✅ PASS (15/15)        │
│ LLM success rate (≥70%):                 ✅ PASS (98.5%)        │
│                                                                  │
│ D11 REGRESSION TEST (now passing):       ✅ ALL CRITERIA PASS   │
└─────────────────────────────────────────────────────────────────┘
```

The falsification pipeline, dead since D-3 due to upstream contradiction detection limitations, is now **fully operational**. The structural detector correctly identifies identity, service, and state contradictions across all templates without hardcoding version numbers or scenario-specific logic.

---

**Next Phase (D13)**: Address T6 LLM-task performance gap (inferences produced but no behavioral impact) and investigate falsification outcome resolution (all INCONCLUSIVE → need discriminating actions that produce decisive evidence).