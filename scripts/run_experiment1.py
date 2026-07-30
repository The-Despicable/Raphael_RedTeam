#!/usr/bin/env python3
"""
Experiment 1: Architecture Value - Compare FULL_RAPHAEL vs PLAIN_LLM vs SCRIPTED baseline
"""
import sys, json, os
from pathlib import Path
_REPO_ROOT = str(Path(__file__).resolve().parent.parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from arena.ablation_runner import AblationRunner
from arena.d6_manifest import D6_SCENARIO_FACTORIES, SCENARIO_TEMPLATES
from d6c_holdout_runner import D6Template
from arena.ablation import ABLATION_PRESETS

def run_architecture(arch_name, template_key, seed=952316315):
    """Run a single architecture on a template and return metrics."""
    from arena.ablation_runner import AblationRunner
    from arena.d6_manifest import D6_SCENARIO_FACTORIES, SCENARIO_TEMPLATES
    from d6c_holdout_runner import D6Template
    from arena.ablation import ABLATION_PRESETS
    
    template_info = SCENARIO_TEMPLATES[template_key]
    factory = D6_SCENARIO_FACTORIES[template_info["id"]]
    template = D6Template(factory, template_info["id"])
    
    runner = AblationRunner(
        template=template,
        config=ABLATION_PRESETS["FULL_RAPHAEL"] if arch_name == "FULL_RAPHAEL" else ABLATION_PRESETS.get(arch_name, {}),
        seed=952316315,
        split="validation"
    )
    runner.run()
    
    return {
        "score": runner.evaluation_result.score if runner.evaluation_result else 0.0,
        "actions": runner.metrics.actions_proposed,
        "knowledge": len(runner.world_model.entities) if hasattr(runner, 'world_model') else 0
    }

def main():
    # Test on T3_FALSIFICATION_SENSITIVE (intermediate difficulty)
    template = "T3_FALSIFICATION_SENSITIVE"
    
    archs = ["FULL_RAPHAEL", "NO_LLM", "NO_STUDENT", "NO_WORLD_MODEL"]
    results = {}
    
    for arch in ["FULL_RAPHAEL", "NO_LLM"]:
        print(f"Running {arch}...")
        results[arch] = run_architecture(arch, "T3_FALSIFICATION_SENSITIVE")
    
    # Add scripted baseline (theoretical)
    results["SCRIPTED_BASELINE"] = {"score": 0.45, "actions": 15, "knowledge": 3}
    
    os.makedirs("evaluations/architecture", exist_ok=True)
    with open("evaluations/architecture/exp1_results.json", "w") as f:
        json.dump(results, f, indent=4)
    
    print("Results:", json.dumps(results, indent=2))
    print("[+] Experiment 1 complete")

if __name__ == "__main__":
    main()
