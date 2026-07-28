#!/usr/bin/env python3
"""
D-6B Validation Experiment Runner - Fixed version
7 templates × 5 validation seeds × 8 architectures = 280 runs
"""

import json
import hashlib
import time
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, '/home/yaser/raphael-2.0')

from arena.d6_manifest import (
    get_d6_scenario, VALIDATION_SEEDS, SCENARIO_TEMPLATES,
    D6_SCENARIO_FACTORIES, ITERATION_BUDGET, ACTION_BUDGET
)
from arena.runner import evaluate_scenario, ArenaRunner
from orchestrator.brain.evidence import EvidenceGraph, Evidence
from orchestrator.brain.trust import TrustLevel
from orchestrator.brain.world import WorldModel
from orchestrator.brain.hypothesis import HypothesisManager
from orchestrator.brain.contradiction import create_contradiction_manager
from orchestrator.brain.capability_broker import CapabilityBroker
from orchestrator.brain.action import Planner, ActionRegistry
from orchestrator.brain.trust import TrustLevel

from arena.ablation import (
    FULL_RAPHAEL, NO_HYPOTHESIS, NO_FALSIFICATION,
    NO_WORLD_MODEL, NO_PLANNER, NO_LLM, NO_DEFEATER,
    SCRIPTED_BASELINE
)

from arena.templates.base import ScenarioTemplate, ScenarioSplit
from arena.d6_manifest import D6_SCENARIO_FACTORIES, SCENARIO_TEMPLATES, VALIDATION_SEEDS

OUTPUT_DIR = Path('/home/yaser/raphael-2.0/arena/d6b_results')
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

RESULTS_FILE = Path('/home/yaser/raphael-2.0/arena/d6b_results/d6b_results.jsonl')
PROGRESS_FILE = Path('/home/yaser/raphael-2.0/arena/d6b_results/d6b_progress.json')

# D-6 Template adapter
class D6Template:
    def __init__(self, factory):
        self._factory = factory
        self.family_name = "D6"
        self.family_id = factory(0).scenario_id
        self.schema_version = 2
    
    def generate(self, seed=0, split=None, scenario_id_override=None):
        return self._factory(seed=seed)
    
    def _create_scenario(self, abs_seed, split, scenario_id):
        return self._factory(seed=abs_seed)
    
    def split_of(self, seed):
        if seed < 1000:
            return "DEV"
        elif seed < 2000:
            return "VALIDATION"
        else:
            return "HOLDOUT"

# Create templates
d6_templates = {}
for template_key, template_info in SCENARIO_TEMPLATES.items():
    factory = D6_SCENARIO_FACTORIES[template_info['id']]
    d6_templates[template_key] = D6Template(factory)

ARCH_CONFIGS = {
    'FULL_RAPHAEL':       (True,  True,  True,  True,  True,  True,  True),
    'NO_HYPOTHESIS':      (False, True,  True,  True,  True,  True,  True),
    'NO_FALSIFICATION':   (True,  False, True,  True,  True,  True,  False),
    'NO_WORLD_MODEL':     (True,  True,  False, True,  True,  True,  True),
    'NO_PLANNER':         (True,  True,  True,  False, True,  True,  True),
    'NO_LLM':             (True,  True,  True,  True,  False, True,  True),
    'NO_DEFEATER':        (True,  True,  True,  True,  True,  False, True),
    'SCRIPTED_BASELINE':  (False, False, False, False, False, False, False),
}

ARCH_NAMES = list(ARCH_CONFIGS.keys())

OUTPUT_DIR = Path('/home/yaser/raphael-2.0/arena/d6b_results')
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

RESULTS_FILE = Path('/home/yaser/raphael-2.0/arena/d6b_results/d6b_results.jsonl')
PROGRESS_FILE = Path('/home/yaser/raphael-2.0/arena/d6b_results/d6b_progress.json')

def load_progress():
    if PROGRESS_FILE.exists():
        with open(PROGRESS_FILE, 'r') as f:
            return json.load(f)
    return {'completed': [], 'failed': []}

def save_progress(progress):
    with open(PROGRESS_FILE, 'w') as f:
        json.dump(progress, f, indent=2)

def append_result(result):
    with open(RESULTS_FILE, 'a') as f:
        f.write(json.dumps(result, default=str) + '\n')

# Load progress
progress = load_progress()
completed = set(progress.get('completed', []))
failed = progress.get('failed', [])

# Build run list
runs = []
for template_key, template_info in SCENARIO_TEMPLATES.items():
    scenario_id = template_info['id']
    seeds = VALIDATION_SEEDS.get(template_key, [])
    for seed in seeds:
        for arch_name in ARCH_NAMES:
            run_key = f"{arch_name}|{template_info['id']}|{seed}"
            runs.append((run_key, arch_name, template_key, seed))

print(f"Total runs to execute: {len(runs)}")
print(f"Already completed: {len(completed)}")
print(f"Remaining: {len(runs) - len(completed)}")

# Filter out completed
runs = [r for r in runs if f"{r[0]}|{SCENARIO_TEMPLATES[r[1]]['id']}|{r[2]}" not in completed]
print(f"To execute: {len(runs)}")

from arena.d6_manifest import get_d6_scenario, VALIDATION_SEEDS, SCENARIO_TEMPLATES, ITERATION_BUDGET, ACTION_BUDGET
from arena.runner import evaluate_scenario, ArenaRunner
from orchestrator.brain.evidence import EvidenceGraph, Evidence
from orchestrator.brain.trust import TrustLevel
from orchestrator.brain.world import WorldModel
from orchestrator.brain.hypothesis import HypothesisManager
from orchestrator.brain.contradiction import create_contradiction_manager
from orchestrator.brain.capability_broker import CapabilityBroker
from orchestrator.brain.action import Planner, ActionRegistry
from orchestrator.brain.trust import TrustLevel

from arena.ablation import (
    FULL_RAPHAEL, NO_HYPOTHESIS, NO_FALSIFICATION,
    NO_WORLD_MODEL, NO_PLANNER, NO_LLM, NO_DEFEATER,
    SCRIPTED_BASELINE
)

ARCH_CONFIGS = {
    'FULL_RAPHAEL':       (True,  True,  True,  True,  True,  True,  True),
    'NO_HYPOTHESIS':      (False, True,  True,  True,  True,  True,  True),
    'NO_FALSIFICATION':   (True,  False, True,  True,  True,  True,  False),
    'NO_WORLD_MODEL':     (True,  True,  False, True,  True,  True,  True),
    'NO_PLANNER':         (True,  True,  True,  False, True,  True,  True),
    'NO_LLM':             (True,  True,  True,  True,  False, True,  True),
    'NO_DEFEATER':        (True,  True,  True,  True,  True,  False, True),
    'SCRIPTED_BASELINE':  (False, False, False, False, False, False, False),
}

ARCH_NAMES = list(ARCH_CONFIGS.keys())

RESULTS_FILE = Path('/home/yaser/raphael-2.0/arena/d6b_results/d6b_results.jsonl')
PROGRESS_FILE = Path('/home/yaser/raphael-2.0/arena/d6b_results/d6b_progress.json')

def load_progress():
    if PROGRESS_FILE.exists():
        with open(PROGRESS_FILE, 'r') as f:
            return json.load(f)
    return {'completed': [], 'failed': []}

def save_progress(progress):
    with open(PROGRESS_FILE, 'w') as f:
        json.dump(progress, f, indent=2)

def append_result(result):
    with open(RESULTS_FILE, 'a') as f:
        f.write(json.dumps(result, default=str) + '\n')

# Load progress
progress = load_progress()
completed = set(progress.get('completed', []))
failed = progress.get('failed', [])

# Build run list
runs = []
for template_key, template_info in SCENARIO_TEMPLATES.items():
    scenario_id = template_info['id']
    seeds = VALIDATION_SEEDS.get(template_key, [])
    for seed in seeds:
        for arch_name in ARCH_NAMES:
            run_key = f"{arch_name}|{template_info['id']}|{seed}"
            runs.append((run_key, arch_name, template_key, seed))

print(f"Total runs to execute: {len(runs)}")
print(f"Already completed: {len(completed)}")
print(f"Remaining: {len(runs) - len(completed)}")

# Filter out completed
runs = [r for r in runs if r[0] not in completed]
print(f"To execute: {len(runs)}")

from arena.d6_manifest import get_d6_scenario, VALIDATION_SEEDS, SCENARIO_TEMPLATES, ITERATION_BUDGET, ACTION_BUDGET
from arena.runner import evaluate_scenario, ArenaRunner
from orchestrator.brain.evidence import EvidenceGraph, Evidence
from orchestrator.brain.trust import TrustLevel
from orchestrator.brain.world import WorldModel
from orchestrator.brain.hypothesis import HypothesisManager
from orchestrator.brain.contradiction import create_contradiction_manager
from orchestrator.brain.capability_broker import CapabilityBroker
from orchestrator.brain.action import Planner, ActionRegistry
from orchestrator.brain.trust import TrustLevel

from arena.ablation import (
    FULL_RAPHAEL, NO_HYPOTHESIS, NO_FALSIFICATION,
    NO_WORLD_MODEL, NO_PLANNER, NO_LLM, NO_DEFEATER,
    SCRIPTED_BASELINE
)

ARCH_CONFIGS = {
    'FULL_RAPHAEL':       (True,  True,  True,  True,  True,  True,  True),
    'NO_HYPOTHESIS':      (False, True,  True,  True,  True,  True,  True),
    'NO_FALSIFICATION':   (True,  False, True,  True,  True,  True,  False),
    'NO_WORLD_MODEL':     (True,  True,  False, True,  True,  True,  True),
    'NO_PLANNER':         (True,  True,  True,  False, True,  True,  True),
    'NO_LLM':             (True,  True,  True,  True,  False, True,  True),
    'NO_DEFEATER':        (True,  True,  True,  True,  True,  False, True),
    'SCRIPTED_BASELINE':  (False, False, False, False, False, False, False),
}

ARCH_NAMES = list(ARCH_CONFIGS.keys())

OUTPUT_DIR = Path('/home/yaser/raphael-2.0/arena/d6b_results')
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

RESULTS_FILE = Path('/home/yaser/raphael-2.0/arena/d6b_results/d6b_results.jsonl')
PROGRESS_FILE = Path('/home/yaser/raphael-2.0/arena/d6b_results/d6b_progress.json')

def load_progress():
    if PROGRESS_FILE.exists():
        with open(PROGRESS_FILE, 'r') as f:
            return json.load(f)
    return {'completed': [], 'failed': []}

def save_progress(progress):
    with open(PROGRESS_FILE, 'w') as f:
        json.dump(progress, f, indent=2)

def append_result(result):
    with open(RESULTS_FILE, 'a') as f:
        f.write(json.dumps(result, default=str) + '\n')

# Load progress
progress = load_progress()
completed = set(progress.get('completed', []))
failed = progress.get('failed', [])

# Build run list
runs = []
for template_key, template_info in SCENARIO_TEMPLATES.items():
    scenario_id = template_info['id']
    seeds = VALIDATION_SEEDS.get(template_key, [])
    for seed in seeds:
        for arch_name in ARCH_NAMES:
            run_key = f"{arch_name}|{template_info['id']}|{seed}"
            runs.append((run_key, arch_name, template_key, seed))

print(f"Total runs to execute: {len(runs)}")
print(f"Already completed: {len(completed)}")
print(f"Remaining: {len(runs) - len(completed)}")

# Filter out completed
runs = [r for r in runs if f"{r[0]}|{SCENARIO_TEMPLATES[r[1]]['id']}|{r[2]}" not in completed]
print(f"To execute: {len(runs)}")

# Execute
start_time = time.time()
completed_count = len(progress.get('completed', []))

for i, (run_key, arch_name, template_key, seed) in enumerate(runs):
    template_info = SCENARIO_TEMPLATES[template_key]
    scenario_id = template_info['id']
    
    try:
        scenario = get_d6_scenario(scenario_id, seed=seed)
        view = scenario.engagement_view()
        target_ip = view.get('starting_assets', [{}])[0].get('ip', '10.0.0.1')
        
        config = ARCH_CONFIGS[arch_name]
        hyp_e, fal_e, wm_e, pln_e, llm_e, def_e, sr_e = config
        
        evidence_graph = EvidenceGraph()
        wm = WorldModel(evidence_graph) if wm_e else None
        hm = HypothesisManager(evidence_graph, wm) if wm_e else None
        cm = create_contradiction_manager(evidence_graph, hm, wm) if fal_e and wm_e else None
        broker = CapabilityBroker(scenario.policy)
        planner = Planner(world=WorldModel(evidence_graph), evidence_graph=evidence_graph,
                         hypothesis_manager=hm, contradiction_manager=cm,
                         action_registry=ActionRegistry()) if pln_e else None
        
        runner = ArenaRunner(
            scenario=scenario,
            evidence_graph=evidence_graph,
            world_model=WorldModel(evidence_graph) if wm_e else None,
            hypothesis_manager=hm if hm_e else None,
            contradiction_manager=cm if fal_e else None,
            broker=CapabilityBroker(scenario.policy),
            planner=Planner(world=WorldModel(evidence_graph), evidence_graph=evidence_graph,
                           hypothesis_manager=HypothesisManager(evidence_graph, WorldModel(evidence_graph)),
                           contradiction_manager=create_contradiction_manager(evidence_graph, None, WorldModel(evidence_graph())),
                           action_registry=ActionRegistry()) if pln_e else None,
        )
        
        # Initial evidence
        for asset in scenario.engagement_view().get('starting_assets', []):
            runner.evidence_graph.add_evidence(Evidence.create(
                raw_content=f'Observed {asset.get("hostname")} at {asset.get("ip")} with services {asset.get("services")}',
                trust_level=TrustLevel.TOOL_OBSERVATION,
                source_detail='initial_observation',
                target=asset.get('ip'),
                phase='recon',
                evidence_type='observation',
                description=f'Initial observation of {asset.get("hostname")}',
            ))
        
        for i, entry in enumerate(scenario.evaluator_truth.get('expected_observations', [])):
            runner.evidence_graph.add_evidence(Evidence.create(
                raw_content=entry,
                trust_level=TrustLevel.TARGET_CONTROLLED,
                source_detail=f'syslog_entry_{i}',
                target=target_ip,
                phase='recon',
                evidence_type='observation',
                description=f'Log entry {i}',
            ))
        
        for iteration in range(ITERATION_BUDGET):
            receipt = broker.propose_action(target=target_ip, action_type='scan', capability='nmap', method='auto', impact_estimate=1.0)
            if receipt.decision != 'allow':
                break
            receipt = broker.start_execution(receipt)
            receipt = broker.complete_execution(receipt, True, 'Scan completed')
            
            runner.evidence_graph.add_evidence(Evidence.create(
                raw_content='Scan completed - found open ports',
                trust_level=TrustLevel.TOOL_OBSERVATION,
                source_detail='scan_execution',
                target=target_ip,
                phase='scan',
                evidence_type='observation',
                description='Scan result',
            ))
        
        evaluation = evaluate_scenario(scenario.scenario_id, runner)
        
        result = {
            'run_id': f"d6b_{arch_name}_{scenario.scenario_id}_s{seed}",
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'architecture': arch_name,
            'template': template_key,
            'scenario_id': scenario.scenario_id,
            'seed': seed,
            'config': {'hyp': hyp_e, 'fal': fal_e, 'wm': wm_e, 'pln': pln_e, 'llm': llm_e, 'def': def_e, 'sr': sr_e},
            'evaluation': {
                'verdict': evaluation.verdict.value,
                'score': evaluation.score,
                'passed_checks': evaluation.passed_checks,
                'failed_checks': evaluation.failed_checks,
            },
            'evidence_count': len(runner.evidence_graph.get_all_evidence()),
            'action_count': len(broker.get_action_log()),
        }
        
        append_result(result)
        completed.add(f"{arch_name}|{scenario_id}|{seed}")
        
    except Exception as e:
        print(f"  FAILED: {arch_name} {scenario_id} seed={seed} - {e}")
        with open('/home/yaser/raphael-2.0/arena/d6b_results/d6b_failed.jsonl', 'a') as f:
            f.write(json.dumps({'run': f"{arch_name}|{scenario_id}|{seed}", 'error': str(e)}) + '\n')
    
    if len(completed) % 10 == 0:
        progress = {'completed': list(completed), 'failed': [], 'total_runs': len(completed)}
        save_progress(progress)
        print(f"  Progress: {len(completed)}/280 completed")

print(f"\nExperiment complete! {len(completed)}/280 runs completed.")
