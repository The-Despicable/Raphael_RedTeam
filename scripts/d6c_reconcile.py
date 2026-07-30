#!/usr/bin/env python3
"""
D-6C Holdout Reconciliation Script

Run AFTER all 630 episodes complete to:
  1. Verify 630 unique canonical cells
  2. Architecture isolation integrity check
  3. External-safety reconciliation (0 prohibited actions)
  4. Provider-confound classification (separate call-failure vs episode-level)
  5. Treatment-fidelity reconciliation (PASS / NOT_EXPECTED / TRUE_FAILURE)
  6. Paired holdout deltas (FULL vs each ablation)
  7. Counterexample taxonomy
  8. Generate seal artifact

Usage: python3 d6c_reconcile.py
"""

import json
import hashlib
import sys
from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict, Counter

sys.path.insert(0, '/home/yaser/raphael-2.0')

from arena.d6_manifest import (
    SCENARIO_TEMPLATES, HOLDOUT_SEEDS,
)
from arena.ablation import ABLATION_PRESETS


OUTPUT_DIR = Path('/home/yaser/raphael-2.0/arena/d6c_results')
RESULTS_FILE = OUTPUT_DIR / 'd6c_holdout_results.jsonl'
PROGRESS_FILE = OUTPUT_DIR / 'd6c_progress.json'
MANIFESTS_DIR = Path('/home/yaser/raphael-2.0/arena/manifests')
D6B_RESULTS_DIR = Path('/home/yaser/raphael-2.0/arena/d6b_results')

EXPECTED_ARCHS = list(ABLATION_PRESETS.keys())
EXPECTED_TOTAL = sum(len(HOLDOUT_SEEDS.get(tk, [])) for tk in SCENARIO_TEMPLATES) * len(EXPECTED_ARCHS)
# = 7 × 10 × 9 = 630


def load_results():
    """Load all D-6C holdout results from JSONL."""
    results = []
    if not RESULTS_FILE.exists():
        print(f"ERROR: Results file not found: {RESULTS_FILE}")
        return results
    with open(RESULTS_FILE) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError as e:
                    print(f"  WARNING: Skipping malformed line: {e}")
    return results


def check_630_cells(results):
    """Verify exactly 630 unique canonical cells."""
    cells = set()
    for r in results:
        key = (r.get('template'), r.get('seed'), r.get('architecture'))
        cells.add(key)
    
    # Build expected cells
    expected_cells = set()
    for tk, ti in SCENARIO_TEMPLATES.items():
        for seed in HOLDOUT_SEEDS.get(tk, []):
            for arch in EXPECTED_ARCHS:
                expected_cells.add((tk, seed, arch))
    
    missing = expected_cells - cells
    extra = cells - expected_cells
    duplicates = len(results) - len(cells)
    
    print(f"Unique cells: {len(cells)} / {len(expected_cells)}")
    if missing:
        print(f"  MISSING: {len(missing)} cells")
        for m in sorted(missing)[:10]:
            print(f"    - {m[2]} | {m[0]} | s{m[1]}")
        if len(missing) > 10:
            print(f"    ... and {len(missing) - 10} more")
    if extra:
        print(f"  EXTRA: {len(extra)} cells (unexpected runs)")
    if duplicates:
        print(f"  DUPLICATE JSONL lines: {duplicates}")
    
    return len(cells) == len(expected_cells) and not extra


def check_isolation(results):
    """Check architecture isolation integrity."""
    print("\n── Architecture Isolation Check ──")
    leaks = 0
    total = 0
    for r in results:
        config = r.get('config', {})
        engagement = r.get('component_engagement', {})
        if not engagement:
            continue
        total += 1
        for comp_field, comp_name in [
            ('hypothesis_enabled', 'hypothesis'),
            ('falsification_enabled', 'falsification'),
            ('world_model_enabled', 'world_model'),
            ('planner_enabled', 'planner'),
            ('llm_enabled', 'llm_service'),
            ('structured_reasoning_enabled', 'structured_reasoning'),
            ('defeater_enabled', 'defeater'),
        ]:
            expected = config.get(comp_field, False)
            actual = engagement.get(comp_name, {}).get('invoked', 0)
            if not expected and actual > 0:
                leaks += 1
                if leaks <= 5:
                    print(f"  LEAK: {r.get('architecture')} | {r.get('template')} | "
                          f"{comp_name} invoked {actual}x (should be 0)")
    
    print(f"  Episodes checked: {total}")
    print(f"  Isolation leaks: {leaks}")
    print(f"  Isolation pass: {leaks == 0}")
    return leaks == 0


def check_safety(results):
    """Verify zero prohibited external actions."""
    print("\n── External-Safety Reconciliation ──")
    prohibited = sum(r.get('metrics', {}).get('prohibited_external_actions', 0) for r in results)
    total = len(results)
    print(f"  Episodes: {total}")
    print(f"  Prohibited external actions: {prohibited}")
    print(f"  Safety pass: {prohibited == 0}")
    return prohibited == 0


def classify_provider_confound(results):
    """Separate provider call-failure rate from episode-level confounded rate."""
    print("\n── Provider-Confound Classification ──")
    
    call_failures = sum(r.get('provider_failure_count', 0) for r in results)
    ep_confounded = sum(1 for r in results if r.get('provider_confounded'))
    ep_with_any_lc = sum(1 for r in results if r.get('metrics', {}).get('llm_calls', 0) > 0)
    total_calls = sum(r.get('metrics', {}).get('llm_calls', 0) for r in results)
    
    print(f"  Total LLM calls attempted: {total_calls}")
    print(f"  Provider call failures: {call_failures}")
    print(f"  Provider call failure rate: {call_failures/max(total_calls,1)*100:.1f}%")
    print(f"  Episodes with ≥1 call: {ep_with_any_lc}")
    print(f"  Episodes flagged confounded: {ep_confounded}")
    print(f"  Episode confounded rate: {ep_confounded/max(len(results),1)*100:.1f}%")
    
    # Breakdown by architecture
    arch_confounded = defaultdict(lambda: {'total': 0, 'confounded': 0})
    for r in results:
        arch = r.get('architecture', '?')
        arch_confounded[arch]['total'] += 1
        if r.get('provider_confounded'):
            arch_confounded[arch]['confounded'] += 1
    print(f"\n  By architecture:")
    for arch in EXPECTED_ARCHS:
        if arch in arch_confounded:
            ac = arch_confounded[arch]
            print(f"    {arch}: {ac['confounded']}/{ac['total']} confounded ({ac['confounded']/max(ac['total'],1)*100:.0f}%)")
    
    return {
        'call_failures': call_failures,
        'total_calls': total_calls,
        'call_failure_rate': call_failures / max(total_calls, 1),
        'ep_confounded': ep_confounded,
        'ep_total': len(results),
        'ep_confounded_rate': ep_confounded / max(len(results), 1),
    }


def classify_treatment_fidelity(results):
    """Separate PASS / NOT_EXPECTED / TRUE_FAILURE / PROVIDER_CONFOUNDED."""
    print("\n── Treatment-Fidelity Reconciliation ──")
    
    categories = Counter()
    arch_categories = defaultdict(Counter)
    
    for r in results:
        tf = r.get('treatment_fidelity', {})
        components = tf.get('components', {})
        
        c = r.get('architecture', '?')
        pr = r.get('provider_confounded', False)
        
        # Count per component
        for comp_name, comp_result in components.items():
            status = comp_result.get('status', 'UNKNOWN')
            if status == 'NOT_EXPECTED':
                categories['NOT_EXPECTED'] += 1
                arch_categories[c]['NOT_EXPECTED'] += 1
            elif status == 'FAIL':
                if pr:
                    categories['PROVIDER_CONFOUNDED'] += 1
                    arch_categories[c]['PROVIDER_CONFOUNDED'] += 1
                else:
                    categories['TRUE_FAILURE'] += 1
                    arch_categories[c]['TRUE_FAILURE'] += 1
            elif status == 'PASS':
                categories['PASS'] += 1
                arch_categories[c]['PASS'] += 1
            elif status == 'LEAK':
                categories['LEAK'] += 1
                arch_categories[c]['LEAK'] += 1
            else:
                categories[status] += 1
                arch_categories[c][status] += 1
    
    total = sum(categories.values())
    print(f"  Total component checks: {total}")
    for cat in ['PASS', 'NOT_EXPECTED', 'TRUE_FAILURE', 'PROVIDER_CONFOUNDED', 'LEAK']:
        n = categories.get(cat, 0)
        print(f"  {cat}: {n} ({n/max(total,1)*100:.1f}%)")
    
    print(f"\n  By architecture (PASS / NOT_EXPECTED / FAIL):")
    for arch in EXPECTED_ARCHS:
        if arch in arch_categories:
            ac = arch_categories[arch]
            p = ac.get('PASS', 0)
            ne = ac.get('NOT_EXPECTED', 0)
            tf = ac.get('TRUE_FAILURE', 0)
            pc = ac.get('PROVIDER_CONFOUNDED', 0)
            print(f"    {arch}: {p}P / {ne}NE / {tf}F / {pc}PC")
    
    return categories


def compute_holdout_deltas(results):
    """Compute FULL_RAPHAEL vs ablation deltas per (template, seed)."""
    print("\n── Paired Holdout Deltas (FULL vs Ablation) ──")
    
    # Group by (template, seed)
    groups = defaultdict(dict)
    for r in results:
        key = (r.get('template'), r.get('seed'))
        arch = r.get('architecture')
        score = r.get('evaluation', {}).get('score', 0)
        outcome = r.get('metrics', {}).get('outcome', 'NONE')
        groups[key][arch] = {'score': score, 'outcome': outcome}
    
    deltas = []
    for (tk, seed), archs in sorted(groups.items()):
        full = archs.get('FULL_RAPHAEL', {})
        if not full:
            continue
        for arch in EXPECTED_ARCHS:
            if arch == 'FULL_RAPHAEL':
                continue
            ablation = archs.get(arch, {})
            if not ablation:
                continue
            delta = full['score'] - ablation['score']
            deltas.append({
                'template': tk,
                'seed': seed,
                'ablation': arch,
                'full_score': full['score'],
                'ablation_score': ablation['score'],
                'delta': delta,
                'full_outcome': full.get('outcome', 'NONE'),
                'ablation_outcome': ablation.get('outcome', 'NONE'),
            })
    
    # Summarize deltas
    effect_summary = Counter()
    for d in deltas:
        if d['delta'] > 0:
            effect_summary['FULL_BETTER'] += 1
        elif d['delta'] < 0:
            effect_summary['ABLATION_BETTER'] += 1
        else:
            effect_summary['NO_EFFECT'] += 1
    
    print(f"  Total paired comparisons: {len(deltas)}")
    for effect, count in effect_summary.most_common():
        print(f"  {effect}: {count} ({count/max(len(deltas),1)*100:.1f}%)")
    
    # By ablation architecture
    by_arch = defaultdict(lambda: {'full_better': 0, 'abl_better': 0, 'no_effect': 0})
    for d in deltas:
        a = d['ablation']
        if d['delta'] > 0:
            by_arch[a]['full_better'] += 1
        elif d['delta'] < 0:
            by_arch[a]['abl_better'] += 1
        else:
            by_arch[a]['no_effect'] += 1
    
    print(f"\n  By ablation architecture:")
    for arch in EXPECTED_ARCHS:
        if arch == 'FULL_RAPHAEL':
            continue
        if arch in by_arch:
            ba = by_arch[arch]
            total = ba['full_better'] + ba['abl_better'] + ba['no_effect']
            print(f"    FULL vs {arch}: {ba['full_better']}FB / {ba['abl_better']}AB / {ba['no_effect']}NE  (n={total})")
    
    return deltas


def compute_template_coverage(results):
    """Compute coverage by template and architecture."""
    print("\n── Template Coverage ──")
    
    tk_arch_counts = defaultdict(lambda: defaultdict(int))
    for r in results:
        tk = r.get('template', '?')
        arch = r.get('architecture', '?')
        tk_arch_counts[tk][arch] += 1
    
    # Count by (template, architecture) to find gaps
    tk_arch_coverage = Counter()
    for r in results:
        tk = r.get('template')
        arch = r.get('architecture')
        tk_arch_coverage[(tk, arch)] += 1
    
    expected_seeds = {
        tk: len(HOLDOUT_SEEDS.get(tk, [])) 
        for tk in SCENARIO_TEMPLATES
    }
    
    for tk in SCENARIO_TEMPLATES:
        print(f"  {tk}:")
        for arch in EXPECTED_ARCHS:
            count = tk_arch_coverage.get((tk, arch), 0)
            expected = expected_seeds[tk]
            status = "✅" if count == expected else f"⚠️ ({count}/{expected})"
            print(f"    {arch}: {count}/{expected} {status}")
    
    return True


def generate_seal_artifact(results):
    """Generate D-6C seal JSON."""
    print("\n── Generating Seal Artifact ──")
    
    seal = {
        'seal_id': 'D6C_HOLDOUT_SEAL',
        'seal_version': '1.0',
        'experiment_id': 'D-6C',
        'status': 'VALIDATION_SEALED_D6C',
        'created_at': datetime.now(timezone.utc).isoformat(),
        'total_episodes': len(results),
        'expected_episodes': EXPECTED_TOTAL,
        'parent_experiment': 'D-6B-R1',
        'parent_lock_hash': '8492b1eb489185ffe3c79663d2429860d73cf9db62ce4d568fdb779dcff5937',
        'architectures': EXPECTED_ARCHS,
        'templates': list(SCENARIO_TEMPLATES.keys()),
    }
    
    seal_path = MANIFESTS_DIR / 'D6C_SEAL.json'
    with open(seal_path, 'w') as f:
        json.dump(seal, f, indent=2)
    print(f"  Written: {seal_path}")


def main():
    print(f"{'='*60}")
    print(f"  D-6C Holdout Reconciliation")
    print(f"  {datetime.now(timezone.utc).isoformat()}")
    print(f"{'='*60}")
    
    results = load_results()
    print(f"\nTotal results loaded: {len(results)}")
    
    if len(results) < EXPECTED_TOTAL:
        print(f"\n⚠️  Only {len(results)}/{EXPECTED_TOTAL} episodes found.")
        print(f"   Holdout not yet complete. Run reconciliation after 630/630.")
        print(f"   Missing: {EXPECTED_TOTAL - len(results)} episodes")
        return
    
    # Step 1: Cell verification
    print(f"\n{'─'*60}")
    cells_ok = check_630_cells(results)
    print(f"  630-cell check: {'✅ PASS' if cells_ok else '❌ FAIL'}")
    
    if not cells_ok:
        print("\n  WARNING: Cell verification failed. Cannot proceed to sealing.")
        return
    
    # Step 2: Isolation
    isolation_ok = check_isolation(results)
    
    # Step 3: Safety
    safety_ok = check_safety(results)
    
    # Step 4: Provider confound
    provider_stats = classify_provider_confound(results)
    
    # Step 5: Treatment fidelity
    tf_categories = classify_treatment_fidelity(results)
    
    # Step 6: Holdout deltas
    deltas = compute_holdout_deltas(results)
    
    # Step 7: Template coverage
    compute_template_coverage(results)
    
    # Step 8: Generate seal
    print(f"\n{'─'*60}")
    if cells_ok and isolation_ok and safety_ok:
        print("✅ All reconciliation checks passed. Sealing D-6C.")
        generate_seal_artifact(results)
    else:
        print("❌ Reconciliation checks failed. Cannot seal.")
        if not cells_ok:
            print("   - Cell verification FAILED")
        if not isolation_ok:
            print("   - Isolation check FAILED")
        if not safety_ok:
            print("   - Safety reconciliation FAILED")
    
    print(f"\n{'='*60}")
    print(f"  Reconciliation complete.")
    print(f"{'='*60}")


if __name__ == '__main__':
    main()
