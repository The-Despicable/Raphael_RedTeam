#!/usr/bin/env python3
"""
Experiment 0: Repeatability
Measures internal consistency of Raphael's behavior.
- 10 runs with same seed (42-51)
- 10 runs with different seeds (1042-1051)
Target: DVWA (Level 1)
"""
import json
import subprocess
import time
import os
from pathlib import Path
from datetime import datetime

REPO_ROOT = Path("/home/yaser/raphael-2.0")
RESULTS_DIR = Path("/home/yaser/raphael-2.0/evaluations/Phase0")
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

def run_engagement(seed, run_id, target="dvwa"):
    """Run a single engagement with given seed."""
    env = os.environ.copy()
    env["RAPHAEL_SEED"] = str(seed)
    env["RAPHAEL_TARGET"] = target
    env["RAPHAEL_MAX_ACTIONS"] = "20"
    env["RAPHAEL_TIMEOUT"] = "300"
    env["PYTHONPATH"] = "/home/yaser/raphael-2.0/src"
    
    cmd = [
        "python3", "-c", f"""
import sys
sys.path.insert(0, '/home/yaser/raphael-2.0/src')
import asyncio
from orchestrator.modes.autonomous import handle

async def main():
    result = await handle(
        target='dvwa',
        seed={seed},
        max_actions=20,
        timeout=300
    )
    return result

if __name__ == '__main__':
    result = asyncio.run(main())
    print(json.dumps(result))
"""
    ]
    
    start = time.time()
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, cwd="/home/yaser/raphael-2.0", env=env)
    elapsed = time.time() - start
    
    return {
        "run_id": run_id,
        "seed": seed,
        "target": target,
        "elapsed_seconds": elapsed,
        "return_code": result.returncode,
        "stdout": result.stdout[-5000:] if result.stdout else "",
        "stderr": result.stderr[-2000:] if result.stderr else ""
    }

def main():
    print("=" * 60)
    print("EXPERIMENT 0: REPEATABILITY")
    print("=" * 60)
    
    # Same seed runs (10 runs with seeds 42-51)
    same_seed_results = []
    print("\n[SAME SEED] Running 10 engagements with seeds 42-51...")
    for i in range(10):
        seed = 42 + i
        print(f"  Run {i+1}/10 (seed={seed})...")
        result = run_engagement(seed, f"same_seed_{i}")
        same_seed_results.append(result)
        print(f"    Return code: {result['return_code']}, Time: {result['elapsed_seconds']:.1f}s")
    
    # Different seed runs (10 runs with seeds 1042-1051)
    diff_seed_results = []
    print("\n[DIFFERENT SEEDS] Running 10 engagements with seeds 1042-1051...")
    for i in range(10):
        seed = 1042 + i
        print(f"  Run {i+1}/10 (seed={seed})...")
        result = run_engagement(seed, f"diff_seed_{i}")
        diff_seed_results.append(result)
        print(f"    Return code: {result['return_code']}, Time: {result['elapsed_seconds']:.1f}s")
    
    # Save results
    results = {
        "experiment": "Experiment_0_Repeatability",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "same_seed_runs": same_seed_results,
        "different_seed_runs": diff_seed_results,
        "analysis": {
            "same_seed_variance": "TBD",
            "different_seed_variance": "TBD"
        }
    }
    
    output_file = RESULTS_DIR / f"experiment0_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"\n✅ Experiment 0 complete. Results saved to {output_file}")
    return results

if __name__ == "__main__":
    import os
    main()
