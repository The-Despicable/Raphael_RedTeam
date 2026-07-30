#!/usr/bin/env python3
"""
RBS-v1 Experiment 3: Difficulty Scaling
Evaluates capability curves across Level 1, 2, and 3 targets.
"""
import sys
import json
import os
from pathlib import Path
_REPO_ROOT = str(Path(__file__).resolve().parent.parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from arena.ablation_runner import AblationRunner
from arena.d6_manifest import D6_SCENARIO_FACTORIES, SCENARIO_TEMPLATES
from d6c_holdout_runner import D6Template
from arena.ablation import ABLATION_PRESETS

TARGETS = {
    "Level_1": "T3_FALSIFICATION_SENSITIVE",
    "Level_2": "T4_WORLD_MODEL_IDENTITY",
    "Level_3": "T6_SEMANTIC_LLM"
}
SEED = 952316315
ARCHITECTURE = "FULL_RAPHAEL"

def run_experiment():
    results = {}
    
    for level, template_key in TARGETS.items():
        print(f"[*] Running {ARCHITECTURE} on {level} ({template_key})...")
        template_info = SCENARIO_TEMPLATES[template_key]
        factory = D6_SCENARIO_FACTORIES[template_info["id"]]
        template = D6Template(factory, template_info["id"])
        
        runner = AblationRunner(
            template=template,
            config=ABLATION_PRESETS[ARCHITECTURE],
            seed=SEED,
            split="validation"
        )
        runner.run()
        
        metrics = {
            "score": runner.evaluation_result.score if runner.evaluation_result else 0.0,
            "actions_proposed": runner.metrics.actions_proposed,
            "knowledge_gain": len(runner.world_model.entities) if hasattr(runner, 'world_model') else 0
        }
        results[level] = metrics

    with open("evaluations/difficulty/exp3_results.json", "w") as f:
        json.dump(results, f, indent=4)
    print("[+] Experiment 3 complete. Results saved.")

if __name__ == "__main__":
    os.makedirs("evaluations/difficulty", exist_ok=True)
    run_experiment()
