# INVALIDATED_POST_HOC

This pilot was invalidated after the benchmark integrity repair pass.
The original results should NOT be used for any ablation comparison.

## Identified Integrity Defects (4)

1. **SCENARIO_ADDRESS_GENERATION_DEFECT** (Primary)
   - Host IPs generated in 10.0.10.0/24 but scope was 10.0.20-60.0/24
   - Environment could never match scan targets to hosts
   - Root cause: _ip_for() default network_offset=10 vs template-specific offsets (20,30,40,60)

2. **CROSS_RUN_STATE_CONTAMINATION**
   - EvidenceGraph global singleton never cleared between runs
   - Results varied by execution order
   - Root cause: Module-level get_evidence_graph() reused across ArenaRunner instances

3. **EVALUATOR_NEGATION_DEFECT**
   - 'Port 80 is NOT open' matched regex '80.*open'
   - Substring collision: 'port 8080' matched pattern for 'port 80'
   - Uncertainty words ('might', 'could') not rejected
   - Root cause: REGEX_FALLBACK without negation/substring/staleness guards

4. **BASELINE_INEQUIVALENCE**
   - LLM_ONLY/SCRIPTED received 1 iteration vs Raphael's 5
   - Did not populate EvidenceGraph or use CapabilityBroker
   - Different environment/broker/pipeline than FULL_RAPHAEL

## Repair Applied (Stage 2.5B.1)

All four defects fixed in measurement apparatus:
- Generator invariant: host ∈ scope guaranteed by _make_scope_and_host()
- Cross-run isolation: Fresh EvidenceGraph/WorldModel/HypothesisManager/ContradictionManager per run
- Evaluator hardened: negation guards, substring collision detection, hypothesis-status awareness
- Baselines equivalent: Same iteration budget (5), broker, evidence pipeline, evaluator

## New Pilot Results

The repaired apparatus produces **identical outcomes across all 8 ablation configurations**.
No component provides measurable discrimination on these 5 templates.

Archive created at: arena/results/archive/pilot_20260725_033716_INVALIDATED_POST_HOC
