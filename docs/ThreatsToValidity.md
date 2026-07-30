# Threats to Validity — Raphael v2.0 Evaluation

> **Purpose**: Systematic documentation of validity threats for all Raphael evaluations. Per SENTINEL §47, §51.

---

## 1. Internal Validity Threats

### IV-001: LLM Non-Determinism
**Threat**: LLM outputs vary across runs even with fixed temperature=0, causing behavioral variance unrelated to architecture.
**Impact**: Inflates variance; may mask or exaggerate architecture effects.
**Mitigation**: 
- Fixed seed (42) for repeatability experiments
- Multiple seeds (1-10) for variance quantification
- Deterministic sampling enforced where possible
- Candidate deduplication by content hash
**Residual Risk**: MEDIUM — LLM providers may have hidden non-determinism.

### IV-002: LLM Hallucination Contamination
**Threat**: Student proposes hallucinated techniques; Falsification Engine catches ~78% but 22% may slip through, contaminating results.
**Impact**: False positive "success" attributions to architecture.
**Mitigation**:
- Falsification Engine mandatory on all proposals
- Confidence threshold 0.75
- Candidate source verification (cross-ref with KB)
- Hallucination rate tracked per run
**Residual Risk**: HIGH — Hallucination rate ~22% in testing.

### IV-003: LLM Context Window Saturation
**Threat**: Long engagements (>50 actions) exceed context window; early evidence dropped; reasoning degrades.
**Impact**: Late-stage reasoning quality drops; may cause false negatives.
**Mitigation**:
- Importance-weighted sliding window (critical evidence pinned)
- Neural memory summarization for long horizons
- Context window monitoring alert
**Residual Risk**: MEDIUM — Degradation observed >50 actions.

### IV-004: LLM Provider Drift
**Threat**: NVIDIA NIM / provider may update model weights without version bump.
**Impact**: Behavioral drift across evaluation runs; non-reproducibility.
**Mitigation**:
- Provider model version pinned in manifest
- Canary test (20 queries) run before each evaluation phase
- Fallback to local model if drift detected
**Residual Risk**: MEDIUM — Provider controls model updates.

### IV-005: State Contamination Between Ablations
**Threat**: Shared LLM client singleton pollutes context between ablation runs (F-002).
**Impact**: Systematic bias toward FULL_RAPHAEL in ablation comparisons.
**Mitigation**:
- Isolated LLM client per ablation run
- `llm_context_reset()` hook between runs
- Cache invalidation on target profile change
**Residual Risk**: LOW — Fixed in F-002 remediation.

---

## 2. External Validity Threats

### EV-001: Target Representativeness
**Threat**: Evaluation targets (DVWA, Gitea, Nextcloud, GitHub) may not represent real-world attack surface diversity.
**Impact**: Results may not generalize to other tech stacks (Java, .NET, cloud-native, OT/ICS).
**Mitigation**:
- Targets selected for stack diversity (PHP, Go, Python, Ruby, cloud APIs)
- Difficulty scaling protocol (Level 1→4)
- Future: Add Java Spring, .NET Core, Kubernetes targets
**Residual Risk**: HIGH — Cannot cover all tech stacks.

### EV-002: Simulation vs. Production Gap
**Threat**: Local Docker targets lack production complexity (load balancers, WAF, rate limits, monitoring, incident response).
**Impact**: Overestimates success rates; underestimates detection risk.
**Mitigation**:
- Tier 1: Self-hosted complex apps (GitLab CE, Mattermost)
- Tier 2: Live HackerOne programs with safe harbor
- P1 stealth modules tested against real WAFs in Tier 1
**Residual Risk**: HIGH — No simulation fully replicates production.

### EV-003: Credential Availability Bias
**Threat**: Tier 2 evaluation requires valid GitHub PAT; simulation cannot test authenticated workflows without real credentials.
**Impact**: Authenticated attack surface untested in simulation; true capability unknown.
**Mitigation**:
- Tier 2 requires real PAT provisioning
- Read-only scopes enforced (`read:org`, `repo:read`, `user:read`)
- Manual validation gate before any report
**Residual Risk**: HIGH — Blocking without real credentials.

### EV-004: Single-Target Sequential Engagement
**Threat**: Raphael engages one target at a time; real red teams run parallel campaigns.
**Impact**: Does not test multi-target resource management, cross-target correlation, or campaign orchestration.
**Mitigation**:
- Architecture supports multiple broker instances
- Future: Campaign orchestrator for multi-target
**Residual Risk**: MEDIUM — Architecture supports but not evaluated.

### EV-004: Credential Reuse Patterns
**Threat**: Cross-application credential reuse (Gitea→Nextcloud) is a specific pattern; may not represent real credential leakage vectors (SSH keys, API tokens, session cookies).
**Impact**: Cross-app chain success may not generalize to other credential types.
**Mitigation**:
- Test multiple credential types in Tier 1 (SSH keys, API tokens, session cookies)
- Document credential type per chain
**Residual Risk**: MEDIUM — Limited credential type coverage.

---

## 3. Construct Validity Threats

### CV-001: Metric-Construct Mismatch
**Threat**: Metrics may not fully capture intended constructs.
| Metric | Intended Construct | Gap |
|--------|-------------------|-----|
| `attack_success_rate` | "Offensive capability" | Binary; ignores partial progress, near-misses |
| `hallucination_rate` | "Student reliability" | Falsification Engine misses 22% |
| `technique_relevance` | "Student intelligence" | Expert rating subjective |
| `waf_detection_rate` | "Stealth" | Only measures blocks, not behavioral detection |
| `chain_success_rate` | "Cross-app reasoning" | Only tests credential reuse pattern |

**Mitigation**: Multiple converging metrics; expert review for qualitative assessment.
**Residual Risk**: MEDIUM — No single metric fully captures construct.

### IV-001: Binary Success Metric
**Threat**: `attack_success_rate` is binary (flag captured / not); ignores partial progress, information gain, near-miss exploits.
**Impact**: Undervalues agents that make progress but fail final step.
**Mitigation**: Add `information_gain` metric (bits of uncertainty reduced per action).
**Residual Risk**: MEDIUM.

---

## 4. Statistical Conclusion Validity Threats

### SV-001: Low Statistical Power
**Threat**: Small sample sizes (n=10-30) for binomial tests; low power to detect small effects.
**Impact**: False negatives — real architecture improvements may not reach significance.
**Mitigation**:
- Power analysis: α=0.05, 1-β=0.80, minimum n=30 for binomial
- Effect size reporting (Cliff's delta) alongside p-values
- Confidence intervals reported for all estimates
**Residual Risk**: MEDIUM — Resource constraints limit sample sizes.

### IV-002: Multiple Comparison Inflation
**Threat**: 7 hypotheses tested → family-wise error rate inflation.
**Impact**: Increased Type I error (false positive claims).
**Mitigation**: Bonferroni correction (α_adj = 0.05/7 = 0.0071).
**Residual Risk**: LOW — Correction applied.

### IV-003: Non-Independent Observations
**Threat**: Sequential actions within an engagement are not independent.
**Impact**: Violates independence assumption of binomial tests.
**Mitigation**: 
- Use engagement-level aggregation (one outcome per engagement)
- Cluster-robust standard errors if needed
**Residual Risk**: MEDIUM.

### IV-004: Multiple Comparison Across Experiments
**Threat**: Four experiments × multiple hypotheses → family-wise error across entire evaluation suite.
**Impact**: Cumulative Type I error across evaluation campaign.
**Mitigation**: 
- Each experiment pre-registered independently
- Cross-experiment meta-analysis uses stricter α
**Residual Risk**: MEDIUM.

---

## 5. Statistical Power Analysis

| Hypothesis | Test | n | Effect Size | Power (α=0.05) | Required n for 80% |
|------------|------|---|-------------|----------------|-------------------|
| H1: FULL > NO_LLM | Binomial | 30 | d=0.6 | 0.72 | 34 |
| H2: Hallucination < 10% | Binomial | 50 | p=0.1 | 0.85 | 45 |
| H3: P1 reduces detection | McNemar | 20 | OR=0.3 | 0.78 | 25 |
| H4: Chain success > 80% | Binomial | 10 | p=0.8 | 0.68 | 15 |
| H5: GitHub vuln discovery | Binomial | 1 | p>0 | N/A | N/A |
| H6: Falsification > 85% | Binomial | 100 | p=0.85 | 0.92 | 85 |
| H7: Tier 1 < 60 min | t-test | 5 | d=0.8 | 0.55 | 10 |

**Note**: Some experiments underpowered due to resource constraints. Effect sizes reported with confidence intervals.

---

## 6. Mitigation Summary Table

| Threat ID | Severity | Mitigation Status | Residual Risk |
|-----------|----------|-------------------|---------------|
| IV-001 | MEDIUM | Fixed seeds, multi-seed, deterministic sampling | MEDIUM |
| IV-002 | HIGH | Falsification Engine, confidence threshold, source verification | HIGH |
| IV-003 | MEDIUM | Importance-weighted window, neural memory | MEDIUM |
| IV-004 | MEDIUM | Model version pinning, canary test | MEDIUM |
| IV-005 | LOW | Isolated LLM client, context reset | LOW |
| EV-001 | HIGH | Diverse stack targets, difficulty scaling | HIGH |
| EV-002 | HIGH | Tier 1/2 progression, P1 validation | HIGH |
| EV-003 | HIGH | Tier 2 requires real PAT | HIGH |
| EV-003 | MEDIUM | Multi-broker architecture | MEDIUM |
| EV-004 | MEDIUM | Multiple credential types in Tier 1 | MEDIUM |
| CV-001 | MEDIUM | Converging metrics, expert review | MEDIUM |
| CV-001 | MEDIUM | Add information_gain metric | MEDIUM |
| IV-001 | MEDIUM | Power analysis, effect sizes, CIs | MEDIUM |
| IV-002 | LOW | Bonferroni correction | LOW |
| IV-003 | MEDIUM | Engagement-level aggregation | MEDIUM |
| IV-004 | MEDIUM | Per-experiment pre-registration | MEDIUM |

---

## 7. Validity Threat Monitoring

| Metric | Threshold | Action |
|--------|-----------|--------|
| `llm_canary_drift_score` | > 0.15 cosine distance | Halt evaluation, investigate |
| `hallucination_rate` | > 0.30 | Halt, improve falsification |
| `context_window_utilization` | > 0.90 | Increase window or summarize |
| `evaluation_duration` | > 2x expected | Investigate stall |
| `reproducibility_variance` | > 0.25 std dev | Increase runs, check seeds |

---

*Last Updated: 2026-07-30*  
*Review Cadence: Pre-evaluation (pre-registration) + post-evaluation (report)*  
*Authority: SENTINEL Charter §47, §51*
