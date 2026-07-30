#!/usr/bin/env python3
"""
Experiment 0: Repeatability — Statistical Variance Measurement

Measures internal consistency of Raphael's D6 benchmark behavior.
- 10 runs with SAME seed (seed=42) → measures deterministic consistency (should be 0 variance)
- 10 runs with DIFFERENT seeds (1042-1051) → measures seed-dependent variance

Uses D6 template T1_NEGATIVE_CONTROL for controlled, reproducible benchmark.
Docker DVWA container runs alongside for future live-target repeatability tests.
"""
import json
import sys
import os
import time
import hashlib
from pathlib import Path
from datetime import datetime, timezone

# Path setup — src/ before scripts/ to avoid arena.py shadowing src/arena/
_REPO_ROOT = str(Path(__file__).resolve().parent.parent)
_SCRIPTS = str(Path(__file__).resolve().parent)
_SRC = _REPO_ROOT + "/src"
for p in (_SCRIPTS, _SRC, _REPO_ROOT):
    while p in sys.path:
        sys.path.remove(p)
sys.path.insert(0, _REPO_ROOT)
sys.path.insert(0, _SCRIPTS)
sys.path.insert(0, _SRC)
# Final order: _SRC, _SCRIPTS, _REPO_ROOT

import logging
logging.getLogger().setLevel(logging.WARNING)
for name in ['arena', 'orchestrator', 'providers', 'd6']:
    logging.getLogger(name).setLevel(logging.WARNING)

from arena.ablation_runner import AblationRunner
from arena.d6_manifest import D6_SCENARIO_FACTORIES, SCENARIO_TEMPLATES
from d6c_holdout_runner import D6Template
from arena.ablation import ABLATION_PRESETS

RESULTS_DIR = Path(_REPO_ROOT) / "evaluations" / "Phase0"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

# Template choice — T1_NEGATIVE_CONTROL is simplest, most deterministic
TEMPLATE_KEY = "T1_NEGATIVE_CONTROL"
ARCH_CONFIG = "FULL_RAPHAEL"


def run_single(seed: int, run_id: str, split: str = "validation") -> dict:
    """Run a single D6 evaluation and return metrics."""
    start = time.time()
    template_info = SCENARIO_TEMPLATES[TEMPLATE_KEY]
    factory = D6_SCENARIO_FACTORIES[template_info["id"]]
    template = D6Template(factory, template_info["id"])
    runner = AblationRunner(
        template=template,
        config=ABLATION_PRESETS[ARCH_CONFIG],
        seed=seed,
        split=split,
    )
    runner.run()
    elapsed = time.time() - start
    score = runner.evaluation_result.score if runner.evaluation_result else 0.0
    actions = runner.metrics.actions_proposed if hasattr(runner, 'metrics') else 0
    return {
        "run_id": run_id,
        "seed": seed,
        "score": score,
        "actions": actions,
        "elapsed_seconds": round(elapsed, 2),
        "config": ARCH_CONFIG,
        "template": TEMPLATE_KEY,
    }


def compute_stats(values: list[float]) -> dict:
    """Compute descriptive statistics for a list of scores."""
    n = len(values)
    if n == 0:
        return {"n": 0, "mean": None, "median": None, "std": None, "min": None, "max": None}
    sorted_vals = sorted(values)
    mean = sum(values) / n
    median = sorted_vals[n // 2] if n % 2 == 1 else (sorted_vals[n // 2 - 1] + sorted_vals[n // 2]) / 2.0
    variance = sum((x - mean) ** 2 for x in values) / n
    std = variance ** 0.5
    return {
        "n": n,
        "mean": round(mean, 4),
        "median": round(median, 4),
        "std": round(std, 4),
        "variance": round(variance, 4),
        "min": round(min(values), 4),
        "max": round(max(values), 4),
        "range": round(max(values) - min(values), 4),
    }


def main():
    print("=" * 60)
    print("EXPERIMENT 0: REPEATABILITY (Statistical Variance)")
    print("=" * 60)
    print(f"Template: {TEMPLATE_KEY}")
    print(f"Config:   {ARCH_CONFIG}")
    print()

    # ── SAME SEED: 10 runs with seed=42 ──
    print("[SAME SEED] 10 runs with seed=42 (expect zero variance)")
    same_seed = []
    for i in range(10):
        result = run_single(42, f"same_seed_{i}")
        same_seed.append(result)
        print(f"  Run {i+1}/10: score={result['score']}, actions={result['actions']}, time={result['elapsed_seconds']}s")

    # ── DIFFERENT SEEDS: 10 runs with seeds 1042-1051 ──
    print("\n[DIFFERENT SEEDS] 10 runs with seeds 1042-1051")
    diff_seeds = []
    for i in range(10):
        seed = 1042 + i
        result = run_single(seed, f"diff_seed_{i}")
        diff_seeds.append(result)
        print(f"  Run {i+1}/10 (seed={seed}): score={result['score']}, actions={result['actions']}, time={result['elapsed_seconds']}s")

    # ── STATISTICAL ANALYSIS ──
    same_scores = [r["score"] for r in same_seed]
    diff_scores = [r["score"] for r in diff_seeds]
    same_actions = [r["actions"] for r in same_seed]
    diff_actions = [r["actions"] for r in diff_seeds]

    same_score_stats = compute_stats(same_scores)
    diff_score_stats = compute_stats(diff_scores)
    same_action_stats = compute_stats(same_actions)
    diff_action_stats = compute_stats(diff_actions)

    print("\n" + "=" * 60)
    print("STATISTICAL ANALYSIS")
    print("=" * 60)
    print(f"\nSame seed (n=10, seed=42):")
    print(f"  Score:  mean={same_score_stats['mean']}, std={same_score_stats['std']}, "
          f"min={same_score_stats['min']}, max={same_score_stats['max']}")
    print(f"  Actions: mean={same_action_stats['mean']}, std={same_action_stats['std']}")

    print(f"\nDifferent seeds (n=10, seeds 1042-1051):")
    print(f"  Score:  mean={diff_score_stats['mean']}, std={diff_score_stats['std']}, "
          f"min={diff_score_stats['min']}, max={diff_score_stats['max']}")
    print(f"  Actions: mean={diff_action_stats['mean']}, std={diff_action_stats['std']}")

    # Determine if system is deterministic for same-seed
    deterministic = same_score_stats["variance"] == 0.0 and same_action_stats["variance"] == 0.0

    results = {
        "experiment": "Experiment_0_Repeatability",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "template": TEMPLATE_KEY,
        "config": ARCH_CONFIG,
        "docker_dvwa_available": True,
        "deterministic_same_seed": deterministic,
        "same_seed_runs": same_seed,
        "different_seed_runs": diff_seeds,
        "statistics": {
            "same_seed_score": same_score_stats,
            "same_seed_actions": same_action_stats,
            "different_seeds_score": diff_score_stats,
            "different_seeds_actions": diff_action_stats,
        },
        "analysis": {
            "same_seed_variance": "zero" if deterministic else "non-zero",
            "different_seed_variance": f"{diff_score_stats['variance']} (score), {diff_action_stats['variance']} (actions)",
            "same_seed_determinism": "DETERMINISTIC: zero variance across 10 same-seed runs" if deterministic
            else f"NON-DETERMINISTIC: variance={same_score_stats['variance']}",
        }
    }

    output_file = RESULTS_DIR / f"experiment0_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\nResults saved to {output_file}")
    print("[+] Experiment 0 complete")


if __name__ == "__main__":
    main()
