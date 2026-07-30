# Threats to Validity — RAPHAEL v2.0 RBS-v1 Campaign

**Last updated:** 2026-07-30  
**Mandated by:** SENTINEL GLM-5.2 (External Statistical Review Directive)

---

## 1. Small Sample Sizes (PARTIALLY ADDRESSED)

**Status:** N=10 per configuration completed across 7 templates × 2 configs = 140 runs.

**Residual threat:** N=10 provides basic variance estimates but is insufficient for rigorous bootstrapping or effect-size inference with 95% confidence intervals narrower than ±0.15. A minimum of N=30 per configuration (630 total runs) would be required for publication-grade statistical power.

**Mitigation:** Mean, standard deviation, min, and max reported for all metrics. Variance patterns are consistent across templates:
- NO_LLM shows **zero variance** (std=0.0) across all templates — fully deterministic.
- FULL_RAPHAEL shows non-zero variance only on templates where the LLM influences outcomes (T1, T3, T7).

---

## 2. Benchmark Overfitting / Scenario Determinism

**Status:** CONFIRMED for T4 and T6.

**Evidence:** Both FULL_RAPHAEL and NO_LLM score **1.000 ± 0.000** on:
- **T4_WORLD_MODEL_IDENTITY**: The benchmark is too easy — the identity resolution task is solved by scripted recon actions alone. The LLM's cognitive modeling capability is not exercised.
- **T6_SEMANTIC_LLM**: The benchmark is too easy — semantic inference tasks are solved by pattern matching in the deterministic template logic. The LLM's semantic reasoning is not needed.

**Impact:** Two of seven benchmarks (29%) fail to discriminate between architectures. This inflates the "equivalence" observation and underestimates the true architecture value.

**Recommended action:** Design harder variants of T4 and T6 where NO_LLM scores < 0.5, ensuring the benchmark can actually measure LLM contribution.

---

## 3. Benchmark Floor Effects

**Status:** CONFIRMED for T2 and T5.

**Evidence:** Both FULL_RAPHAEL and NO_LLM score **0.000 ± 0.000** on:
- **T2_HYPOTHESIS_SENSITIVE**: Neither architecture can generate valid hypotheses for this task. The scenario may require domain knowledge not available in either configuration.
- **T5_PLANNING_COST**: Neither architecture can solve the planning optimization task. The scenario's cost function may be misaligned with the action space.

**Impact:** Two of seven benchmarks (29%) are too hard for any configuration. These templates contribute zero discriminatory power.

**Recommended action:** Analyze action traces to determine why the planner fails on these templates. Consider recalibrating scenario difficulty or adding intermediate scaffolding.

---

## 4. Component Underutilization (LLM Non-Engagement)

**Status:** INVESTIGATED.

**Evidence:** Across all 140 N=10 runs, the patterns show:
- On templates where FULL > NO_LLM (T1, T3, T7), FULL shows **non-zero variance** (std ≈ 0.15-0.24), indicating the LLM is being queried and its stochastic outputs drive variance.
- On templates where FULL = NO_LLM (T2, T4, T5, T6), FULL shows **zero variance** (std = 0.0), identical to NO_LLM's behavior. This suggests either:
  - (a) The LLM is queried but produces answers consistent with the deterministic default, OR
  - (b) The planner selects default/recon actions without querying the LLM

**Tracing required:** Deeper instrumentation is needed to count actual LLM invocations per episode. Current metrics only capture action-level outcomes, not internal decision paths.

**Recommended action:** Add `llm_query_count` and `planner_fallback_count` metrics to the ablation runner for future campaigns.

---

## 5. Single Provider Dependency

**Status:** OPEN.

**All N=10 data was collected using a single LLM provider:** `nemotron-3-ultra:cloud` via Ollama.

**Threat:** Results may not generalize to other LLM providers (NVIDIA NIM, GPT-4, Claude, etc.). Different providers have different failure modes, latency profiles, and output distributions that could interact with the RAPHAEL architecture.

**Mitigation (future):** Cross-provider replication on a subset of templates (T1, T3, T7) with at least 3 different LLM providers.

---

## 6. Seed Selection Bias

**Status:** OPEN.

**Seeds used:** 42, 1042-1050 (10 total)

**Threat:** These seeds were chosen arbitrarily and may not be representative of the full seed space. The template generators may produce easier or harder scenarios for specific seed ranges.

**Mitigation (future):** Use systematic seed sampling (e.g., every 100th seed from 0-10000) and report seed-to-seed variance distributions.

---

## 7. No Repeatability Measurement Across Full Pipeline

**Status:** ADDRESSED for D6 templates. NOT ADDRESSED for live-target execution.

**Experiment 0** measured repeatability on the D6 T1 template only:
- Same seed (n=10): score=1.0±0.0, actions=72.0±2.0 — **deterministic scoring**
- Different seeds (n=10): score=1.0±0.0, actions=70.8±1.6
- DVWA Docker container is provisioned but the full live-target autonomous pipeline was not executed.

**Threat:** The D6 benchmark engine is deterministic. The Raphael autonomous pipeline against live targets (nmap scanning, credential spraying, etc.) may have fundamentally different variance characteristics.

---

## Summary of Threat Severity

| Threat | Severity | Addressed? | Action Required |
|--------|----------|-----------|-----------------|
| Small sample size | MEDIUM | PARTIALLY | Expand to N=30+ |
| Benchmark ceiling (T4, T6) | HIGH | NO | Redesign scenarios |
| Benchmark floor (T2, T5) | HIGH | NO | Redesign scenarios |
| LLM non-engagement | MEDIUM | NO | Add invocation metrics |
| Single provider | MEDIUM | NO | Cross-provider test |
| Seed bias | LOW | NO | Systematic sampling |
| Live-target variance | LOW | PARTIALLY | DVWA container ready |
