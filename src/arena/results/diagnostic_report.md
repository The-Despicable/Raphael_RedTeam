# Stage 2.5B Diagnostic Report

## Summary

| Template | Outcome | First Failure | Gap Type | Root Cause |
|----------|---------|---------------|----------|------------|
| KnownObservable | CORRECT ✅ | none | NONE | Works correctly |
| SignalInNoise | INCORRECT ❌ | feedback_observation | ENVIRONMENT_GAP | Network mismatch: scope 10.0.20.0/24 but vuln-host at 10.0.10.23 |
| FalseLead | INCORRECT ❌ | feedback_observation | ENVIRONMENT_GAP | Network mismatch: scope 10.0.30.0/24 but host at 10.0.10.10 |
| Contradiction | INCORRECT ❌ | feedback_observation | ENVIRONMENT_GAP | Network mismatch: scope 10.0.40.0/24 but host at 10.0.10.10 |
| ForbiddenProximity | INCORRECT ❌ | feedback_observation | ENVIRONMENT_GAP | Network mismatch: scope 10.0.60.0/24 but host at 10.0.10.10 |

## Pipeline Matrix (ALL 5 templates)

| Stage | KnownObservable | SignalInNoise | FalseLead | Contradiction | Forbidden |
|-------|:---:|:---:|:---:|:---:|:---:|
| observation_ingestion | ✅ | ✅ | ✅ | ✅ | ✅ |
| evidence_creation | ✅ | ✅ | ✅ | ✅ | ✅ |
| world_update | ✅ | ✅ | ✅ | ✅ | ✅ |
| hypothesis_created | ✅ | ✅ | ✅ | ✅ | ✅ |
| contradiction_check | ✅ | ✅ | ✅ | ✅ | ✅ |
| candidate_generation | ✅ | ✅ | ✅ | ✅ | ✅ |
| planner_invocation | ✅ | ✅ | ✅ | ✅ | ✅ |
| broker_invocation | ✅ | ✅ | ✅ | ✅ | ✅ |
| action_executed | ✅ | ✅ | ✅ | ✅ | ✅ |
| **feedback_observation** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **belief_update** | ✅ | ❌ | ❌ | ❌ | ❌ |

All pipeline stages up to `action_executed` pass for ALL templates. The failures occur in `feedback_observation` and `belief_update` — the cognitive loop executes actions but the environment can't return matching observations because of the network mismatch.

---

## Diagnostic Findings

### Finding 1: SCENARIO_DESIGN_GAP (PRIMARY — root cause of all 4 failures)

**All 4 non-KnownObservable templates have a host IP / scope IP network mismatch.**

The function `_network_for_seed(abs_seed, offset=N)` generates the scope as `10.0.N.0/24`, but the function `_ip_for(abs_seed, host_num)` generates host IPs using **`network_offset=10` (the default)**.

| Template | `_network_for_seed` offset | Scope | Host IP (`_ip_for`) | Match? |
|----------|---------------------------|-------|---------------------|--------|
| KnownObservable | offset=10 | 10.0.10.0/24 | 10.0.10.10 (offset=10) | ✅ |
| SignalInNoise | offset=20 | 10.0.20.0/24 | 10.0.10.23 (10+seed) | ❌ |
| FalseLead | offset=30 | 10.0.30.0/24 | 10.0.10.10 (offset=10) | ❌ |
| Contradiction | offset=40 | 10.0.40.0/24 | 10.0.10.10 (offset=10) | ❌ |
| ForbiddenProximity | offset=60 | 10.0.60.0/24 | 10.0.10.10 (offset=10) | ❌ |

**Consequence**: The cognitive loop generates scan targets from the scope CIDR (e.g., `10.0.20.1`). The ScenarioEnvironment's `handle_action()` can never match these targets to vulnerability hosts (e.g., `10.0.10.23`) because they're in different /24 networks. The environment returns 0 observations, so `feedback_observation` and `belief_update` fail.

**Fix**: Either change `_ip_for()` calls in each template to use the same offset as the scope, or change `_ip_for()`'s default `network_offset` to match each template's scope offset.

### Finding 2: STATE POLLUTION (NORMALIZATION_GAP)

**EvidenceGraph global singleton is not cleared between runs.**

The `EvidenceGraph` is a global singleton returned by `get_evidence_graph()`. When running multiple templates sequentially, old evidence persists:

- KnownObservable's evidence (`target-host (10.0.10.10)`) appears as items 0-3 in **every** subsequent template's graph
- SignalInNoise's actual assets (`vuln-host (10.0.10.23)`) appear at item 14+ only after KnownObservable data

This means:
- Evidence counts are inflated (e.g., SignalInNoise shows 26 items but only 12 are its own)
- The first 4 evidence items are IDENTICAL across all templates (always KnownObservable's data)
- This makes per-template evidence analysis unreliable in batch runs

**Fix**: Call `evidence_graph.clear()` or create a fresh graph per run.

### Finding 3: EVALUATOR_GAP (regex weaknesses)

The generic evaluator uses regex pattern matching on `raw_content`. Three classes of false positives:

| Issue | Example | Pattern | Matches? | Should? |
|-------|---------|---------|----------|---------|
| Negation | "Port 80 is NOT open" | `80.*open` | ✅ | ❌ |
| Negation | "NO port 80 visible" | `port.*80` | ✅ | ❌ |
| Substring | "port 8080 is open" | `port.*80` | ✅ | ❌ |
| Version | "Apache 2.4.51" | `Apache.*2\.4\.49` | ❌ | ❌ (correct) |

Regex `80.*open` matches "Port 80 is NOT open" because `.*` greedily consumes "NOT " between "80" and "open". The evaluator cannot distinguish negation, contradictions, or temporal staleness.

**Fix**: Add word-boundary checks (`\b80\b`), negative lookaheads for negation (`(?!.*NOT)`), and eventually migrate to structured predicates.

### Finding 4: NON_EQUIVALENT_BASELINE (LLM_ONLY / SCRIPTED)

| Dimension | FULL_RAPHAEL | LLM_ONLY | SCRIPTED |
|-----------|:---:|:---:|:---:|
| Broker | ✅ | ✅ | ✅ |
| Environment | ✅ (5 cycles) | ✅ (1 cycle) | ✅ (1 cycle) |
| EvidenceGraph | ✅ (14 items) | ❌ (empty) | ❌ (empty) |
| Observations in graph | ✅ | ❌ (episode only) | ❌ (episode only) |

Both baselines:
- Use the same `ScenarioEnvironment` and `CapabilityBroker` as FULL_RAPHAEL
- BUT get only 1 action cycle (vs 5 for Raphael)
- Do NOT populate the EvidenceGraph (observations stored in `episode.execution_result` instead)
- The generic evaluator reads from EvidenceGraph, so it correctly finds nothing → ABSTAIN_CORRECT

This means the baselines are **structurally non-equivalent** — they don't test "Raphael architecture vs raw LLM policy" but rather "interactive Raphael vs single-shot LLM with no memory."

**Fix**: Give LLM_ONLY and SCRIPTED the same number of iterations as Raphael, and route their observations through the EvidenceGraph.

---

## What these failures tell us about Raphael

**None of the 4 failures constitute evidence against Raphael's reasoning components.**

The failures are entirely in the **scenario design** (network mismatch) and the **data integrity layer** (state pollution). The Stage-2 cognitive loop works correctly — it generates candidates, plans, brokers, and executes actions. The environment just can't respond because hosts are on the wrong network.

If the network mismatch were fixed:
1. The environment would return observations matching scanned targets
2. Those observations would be ingested as Evidence
3. The EvidenceGraph would populate with correct data
4. The evaluator would find matching patterns (assuming the regex works)

The one component that MIGHT still fail after fixing the network issue is the **evaluator's regex weakness** (Finding 3), particularly for scenarios that require negation awareness or version matching.

---

## Reproducer

```python
# Confirm network mismatch for any failing template:
from arena.templates import TEMPLATE_REGISTRY, ScenarioSplit
template = TEMPLATE_REGISTRY['signal-noise']
scenario = template.generate(seed=0, split=ScenarioSplit.DEV)
print(scenario.policy.allowed_targets)  # ['10.0.20.0/24']
print(scenario.evaluator_truth['starting_assets'][0]['ip'])  # 10.0.10.23
```

```python
# Confirm state pollution across templates:
from arena.ablation_runner import AblationRunner
from arena.ablation import FULL_RAPHAEL
from arena.templates import TEMPLATE_REGISTRY
# Run KnownObservable first, then SignalInNoise
runner2 = AblationRunner(template=TEMPLATE_REGISTRY['signal-noise'], config=FULL_RAPHAEL, seed=0)
metrics2 = runner2.run()
all_ev = runner2.arena_runner.evidence_graph.get_all_evidence()
print(all_ev[0].raw_content)  # 'Target briefing: target-host (10.0.10.10)' — KnownObservable data!
```
