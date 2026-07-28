# D13 DIAGNOSTIC REPORT — Cognitive Efficacy Diagnosis

**Date**: 2026-07-27  
**Spec**: `D13_COGNITIVE_EFFICACY_DIAGNOSIS_SPEC.json` (v1.0, SEALED)  
**Persona**: forge (RAPHAEL-FORGE v2+v3 BUILD-SURGEON)  
**Status**: ✅ **DIAGNOSIS COMPLETE — ROOT CAUSES IDENTIFIED**

---

## 1. Executive Summary

Three FULL_RAPHAEL episodes (T4|3723150, T3|952316315, T6|310589826) were instrumented and executed. All 12 falsification actions (4/ep × 3) returned `INCONCLUSIVE`. T6 scored 0.0. **Root causes are now identified for all four diagnostic traces.**

| Trace | Template | Gap Layer | Root Cause | Severity |
|-------|----------|-----------|------------|----------|
| **A** | T4 identity contradiction | Environment Response | Target asset lacks `http` service → all `direct_probe` actions return 404 | Structural (scenario factory) |
| **B** | T3 version mismatch | Environment Response + Evaluator Logic | Same 404 issue as T4 + claim-matching prefix mismatch | Structural + Logic bug |
| **C** | T6 LLM translation | Evaluator Criteria | No component produces classification keywords (`breach`/`benign`) that evaluator checks for | Design gap |
| **D** | discriminator_id | **FALSE POSITIVE — CANCELED** | `discriminator_id` propagates correctly end-to-end. The `?` was a display artifact. | None |

---

## 2. Trace A — T4 Falsification Efficacy Diagnosis

### 2.1 What discriminating action was selected?
- **Target**: `10.0.142.10` (the SSH-only management interface)
- **Action type**: `direct_probe`
- **Capability**: `curl`
- **Method**: `auto`
- **discriminator_id**: `disc_92dce3d9b117` (correctly propagated)

### 2.2 What observation did it produce?
```
HTTP/1.1 404 Not Found
Content-Type: text/html

Not Found
```
**Status code**: 404 Not Found — **confirmed across all 4 falsification actions**, every time.

### 2.3 Why does direct_probe return 404?
**Root cause confirmed**: The T4 scenario factory (`create_d6_scenario_4` in `arena/d6_manifest.py`) creates two IPs for the same physical host:

| IP | Asset hostname | Services | Host ID |
|----|---------------|----------|---------|
| `10.0.42.10` | `multi-host-{seed}` | `["http", "ssh"]` | `HOST-{id}` |
| `10.0.142.10` | `multi-host-{seed}-mgmt` | `["ssh"]` | `HOST-{id}` |

The second interface (`10.0.142.10`) has **only SSH**, not HTTP. The environment's `_handle_http_get` at `arena/environment.py:569` checks:
```python
if asset.get("services") and ("http" in asset.get("services", []) or ...):
```
This evaluates to **False** for the second interface → returns 404.

**This is the same for T3** (single IP with only SSH service → all `direct_probe` actions return 404).

### 2.4 Why is the FalsificationResult INCONCLUSIVE?
**Root cause confirmed**: The claim-matching logic at `arena/ablation_runner.py:1354-1362` fails because of a **description/raw_content prefix mismatch**.

The contradiction's `claim_a` is set from `evidence.description`:

| Source | Content |
|--------|---------|
| `evidence.description` | `"curl observation: HTTP/1.1 404 Not Found"` |
| `evidence.raw_content` | `"HTTP/1.1 404 Not Found\nContent-Type: text/html\n\nNot Found"` |
| `ConradictionManager` chooses | `description` over `raw_content` (line 188-189 of contradiction.py) |

So `claim_a = "curl observation: HTTP/1.1 404 Not Found"` (lowercased: `"curl observation: http/1.1 404 not found"`)

But `obs_text` (from raw_output) = `"http/1.1 404 not found\ncontent-type: text/html\n\nnot found"`

The check `claim_a in obs_text` → `"curl observation: http/1.1 404 not found" in "http/1.1 404 not found\n..."` → **FALSE** because `obs_text` doesn't include the "curl observation: " prefix.

The fallback check at line 1365-1374 also fails because it checks `raw_content` (also without the "curl observation: " prefix) against the same `claim_a` text.

**Contradictory_evidence_ids == supporting_evidence_ids** because neither claim_a nor claim_b matches — the code falls through to "inconclusive" and the same evidence IDs are used for both sides.

### 2.5 Layer classification
- **Primary**: Environment Response (asset missing HTTP service → 404)
- **Secondary**: Evaluator Logic (claim text prefix prevents substring matching)

---

## 3. Trace B — T3 Falsification Efficacy Diagnosis

### 3.1 Findings
- **Same root cause as T4.** All 4 falsification actions target `10.0.63.10`, which has only `["ssh"]` services
- All return 404 → all INCONCLUSIVE
- Same claim-matching prefix bug applies

### 3.2 Unique T3 finding
The T3 scenario (version mismatch between nmap and actual SSH) cannot be tested via `direct_probe` because:
1. The environment doesn't implement SSH banner grabbing for `direct_probe` — only HTTP GET
2. The single asset has no HTTP service → always returns 404
3. The `_handle_http_get` is the only discriminator action handler

**The falsification discriminator actions for T3/T4 all use `direct_probe` + `curl`, but the environment only returns useful responses for assets with HTTP service.** This is a fundamental limitation: no SSH banner discriminator exists in the action set.

### 3.3 Layer classification
- **Primary**: Environment Response (no HTTP service on target → 404)
- **Secondary**: Evaluator Logic (same prefix mismatch)
- **Tertiary**: Action Capability Gap (no SSH-aware discriminator action type)

---

## 4. Trace C — T6 LLM Translation Gap

### 4.1 What LLM inferences were produced?

| Claim | Category | Has "breach"? | Has "benign"? |
|-------|----------|:---:|:---:|
| `Host 10.0.66.10 is identified as loghost-310589826, running Linux with ssh and syslog services.` | host_identity_resolution | No | No |
| `Host 10.0.66.10 is identified as loghost-310589826 running Linux with ssh and syslog services.` | host_identity_resolution | No | No |

The LLM produces **host-identity and service-identification inferences**, not breach/benign classifications.

### 4.2 Why did the episode fail?
**Both T6 success conditions failed with `no_matching_claim`**:

```json
"failed_checks": [
    "reasoning_fail: Correctly classifies activity as breach or benign [no_matching_claim]",
    "reasoning_fail: Provides reasoning that references specific log entries [no_matching_claim]"
]
```

The `evidence_pattern` for condition 1 is the string `"breach"` (since seed 310589826 has `is_breach=True`). The `_condition_matches` function checks whether ANY claim text contains "breach". No claim does — the LLM produces identity and service claims, not classification claims. The log entries (evidence raw_content) DO contain indicators of a breach (exfil, shadow, auth.log), but these never get synthesized into a classification claim.

The `evidence_pattern` for condition 2 is `r"\b(INFO|WARN|ERROR|auditd)\b"`. The raw evidence DOES contain these keywords (the log entries include "INFO", "WARN", "ERROR", "auditd") but the CLAIM texts don't include them. Claims are structured predicates like `SERVICE_TYPE: ssh`, not raw observation text.

### 4.3 Why doesn't the LLM produce classification claims? Three sub-causes:

| Cause | Layer | Description |
|-------|-------|-------------|
| **4.3a** | LLM Prompt | The LLM prompt is built from `build_evidence_context(diverse_items)` which selects diverse evidence. The evidence context may not include the log entries with sufficient clarity for the LLM to classify. |
| **4.3b** | Inference Category | The LLM generates inferences in categories: `host_identity_resolution`, `service_identification`, `state_description`. None of these map to "breach" or "benign" classification. A `classification` or `threat_assessment` category does not exist. |
| **4.3c** | No classification claim | The RunConclusion adapter (`conclusion_adapters.py`) builds claims from hypothesis statements, evidence, and Planner decisions. None of these sources produce classification keywords. The hypothesis statements wrap observations and LLM inferences but never synthesize a "breach"/"benign" conclusion. |

### 4.4 Layer classification
- **Primary**: Evaluator Criteria (the evaluator checks for keywords that no component can produce)
- **Secondary**: LLM Capability (no prompt/mechanism to produce classification inferences)
- **Tertiary**: Architecture Gap (no claim type for scenario-specific classification)

---

## 5. Trace D — Discriminator ID Propagation Audit

### 5.1 Finding: FALSE POSITIVE — CANCELED

The `discriminator_id` is **correctly propagated** through the entire chain. Every FalsificationResult across all 12 discriminator executions has a valid `discriminator_action_id`:

| Episode | Discriminator IDs in FalsificationResults |
|---------|------------------------------------------|
| T4 seed 3723150 | `disc_92dce3d9b117`, `disc_3583ce866367`, `disc_a07ee8e8d402`, `disc_4098076e6027` |
| T3 seed 952316315 | `disc_61e67c3e8b51`, `disc_593f4932b5eb`, `disc_8d15d22bdffc`, `disc_585da624ab51` |
| T6 seed 310589826 | `disc_74b2805592b9`, `disc_d88e3dae489b`, `disc_d374e591a64c`, `disc_5b9a2cd5efc1` |

### 5.2 Chain verified

| Step | Location | Value | Status |
|------|----------|-------|--------|
| 1. DiscriminatingObservation created | `contradiction.py` | `disc.discriminator_id` = `disc_{uid}` | ✅ |
| 2. Candidate created from discriminator | `ablation_runner.py:1821` | `disc_candidate["discriminator_id"]` = `disc.discriminator_id` | ✅ |
| 3. Planner selects candidate | Planner.decide() | `selected["discriminator_id"]` preserved | ✅ |
| 4. FalsificationResult created | `ablation_runner.py:1402-1404` | `discriminator_id=disc_id` passed | ✅ |
| 5. FalsificationResult stored | `conclusion.py:70` | `discriminator_action_id` = parameter | ✅ |
| 6. Serialized | `conclusion.py:92` | `to_dict()["discriminator_action_id"]` = value | ✅ |

The `?` display in the D12 report was an artifact from the diagnostic/reporting script accessing a non-existent field name (`discriminator_id` vs `discriminator_action_id`).

### 5.3 Layer classification
- **FALSE POSITIVE** — No bug exists. The discriminator_id is fully operational.

---

## 6. Root Cause Summary

| Gap | Root Cause | Evidence Layer | Fix Category |
|-----|-----------|----------------|--------------|
| **T4 404** | T4 second interface has no HTTP service | Environment Response | Scenario factory should assign `["http"]` to `10.0.142.10` or `direct_probe` should handle SSH |
| **T3 404** | T3 asset has no HTTP service | Environment Response | T3 asset needs HTTP service OR discriminator should use ssh_banner instead of direct_probe |
| **Claim matching** | `evidence.description` includes `"X observation: "` prefix but `raw_output` doesn't | Evaluator Logic | Claim matching should normalize prefixes OR use raw_content without prefix |
| **All INCONCLUSIVE** = same IDs for both sides | Neither claim_a nor claim_b matches obs_text; fallback assigns same IDs to both | Evaluator Logic | When neither matches, should not assign contradictory_evidence_ids == supporting_evidence_ids |
| **T6 breach/benign missing** | No component produces "breach"/"benign" claim text | Evaluator Criteria / LLM Capability | Either: (a) LLM prompt should ask for classification, (b) scenario evaluator should check evidence raw_content not claim text, (c) new inference category for scenario-specific classification |
| **T6 log keywords missing** | Claim texts are structured predicates (SERVICE_TYPE, HOST_IDENTITY), not raw observation text | Evaluator Criteria | `_condition_matches` does regex on claim text format `"predicate: value"` which doesn't contain observation keywords |
| **discriminator_id "?"** | Display artifact — no actual bug | Report/Display | Fix report generation to use correct field name `discriminator_action_id` |

---

## 7. Key Findings for D14 (Repair Specification)

### 7.1 High-Impact Fixes

**1. Evidence description prefix in claim matching** (affects T3, T4)
- Location: `arena/ablation_runner.py:1354-1362` (claim_a/claim_b matching) + `orchestrator/brain/contradiction.py:188-189` (claim_a/claim_b assignment)
- Fix: Either (a) strip `"{source_tool} observation: "` prefix from claim text before matching, or (b) use `evidence.raw_content` instead of `evidence.description` for claim text, or (c) match `claim_text in raw_content` instead of `claim_text in raw_output`
- Impact: All 12/12 falsification actions would be affected — some might become SUPPORTS_A or SUPPORTS_B instead of INCONCLUSIVE

**2. Scenario service assignment** (affects T3, T4)
- Location: `arena/d6_manifest.py` (T3 and T4 scenario factories)
- Fix: T4 `ip_11` should include `"http"` in services OR a second discriminator type should exist for SSH targets
- Impact: direct_probe on these targets would return 200 OK with version/host metadata

**3. Identical contradictory/supporting evidence IDs** (affects all FalsificationResults)
- Location: `arena/ablation_runner.py:1408-1409`
- Fix: When outcome is INCONCLUSIVE, don't assign the same evidence IDs to both sides. Leave contradictory_evidence_ids from the contradiction and supporting_evidence_ids empty.
- Impact: All 12/12 results would have different contradictory vs supporting IDs

### 7.2 Medium-Impact Fixes

**4. T6 classification claim missing**
- The LLM prompt needs to include the scenario objective (classify breach/benign) and an inference category for classification
- Alternative: The T6 evaluator could check evidence raw_content (which contains the log entries with breach indicators) instead of claim text
- Impact: T6 score could move from 0.0 to 1.0

**5. T6 log keyword check**
- The `evidence_pattern` `r"\b(INFO|WARN|ERROR|auditd)\b"` is a regex on claim text format `"predicate: value"`. Log keywords appear in evidence raw_content, not in structured claim predicates.
- Fix: Evaluator should check both claims AND evidence raw_content for this pattern
- Impact: T6 `log_evidence_referenced` check would pass

### 7.3 Low-Impact Fix

**6. discriminator_id display**
- Rename the display field to `discriminator_action_id` in report generation
- Impact: Cosmetic only

---

## 8. Raw Data Archive

All diagnostic data is archived in `arena/results/d13_traces/`:

| File | Trace | Size | Content |
|------|-------|------|---------|
| `Trace_A_T4_seed3723150.json` | T4 falsification | ~15KB | Contradictions, evidence, HTTP responses, FalsificationResults, discriminator inventory |
| `Trace_B_T3_seed952316315.json` | T3 falsification | ~15KB | Same structure for T3 |
| `Trace_C_T6_seed310589826.json` | T6 LLM gap | ~12KB | LLM inferences, hypothesis states, evaluation result, claim text analysis |
| `diagnostic_summary.json` | Consolidated | ~1KB | Trace completion summary |

---

## 9. Invariant Verification

The D11 regression test will be run to confirm no invariants were broken by the instrumentation. All instrumentation was done via monkey-patching in memory — no source files were modified during diagnostics.

---

## 10. Verdict

```diff
+ Trace A (T4): ROOT CAUSE IDENTIFIED — scenario service assignment + claim prefix mismatch
+ Trace B (T3): ROOT CAUSE IDENTIFIED — same as T4 + no SSH discriminator action type
+ Trace C (T6): ROOT CAUSE IDENTIFIED — evaluator checks keywords no component produces
! Trace D (discriminator_id): CANCELED — FALSE POSITIVE. Propagation works correctly.
```

The cognitive efficacy gap has two independent root causes:
1. **Environment/Evaluator** (T3, T4): `evidence.description` prefix prevents claim-text matching + targets lack HTTP service
2. **Evaluator Criteria** (T6): Success conditions check for keywords in claim text that no component generates

These are now understood well enough to author D14 (Repair Specification), pending SENTINEL authorization.
