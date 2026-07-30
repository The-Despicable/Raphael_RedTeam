"""base.py — Abstract base scenario template with dev/validation/holdout split.

Every template extends ScenarioTemplate and implements _create_scenario()
which deterministically produces an ArenaScenario from (seed, split).
"""

import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from arena.runner import ArenaScenario, ArenaRunner, EvaluationResult, EvaluationVerdict


class ScenarioSplit(Enum):
    """Split type for scenario generation — determines seed range and access level."""
    DEV = "dev"           # Seeds 0–999: ground truth inspectable
    VALIDATION = "val"    # Seeds 1000–1999: aggregate only
    HOLDOUT = "holdout"   # Seeds 2000–9999: completely blind


# Ordinal offsets for each split (added to user-provided seed)
SPLIT_OFFSETS = {
    ScenarioSplit.DEV: 0,
    ScenarioSplit.VALIDATION: 1000,
    ScenarioSplit.HOLDOUT: 2000,
}

# Max seed per split (exclusive upper bound)
SPLIT_MAX_SEED = {
    ScenarioSplit.DEV: 1000,
    ScenarioSplit.VALIDATION: 1000,
    ScenarioSplit.HOLDOUT: 8000,  # 2000–9999
}

# Domain seeds (used for hash-based parameter derivation)
DOMAIN_SEED = "raphael-arena-stage2.5-v1"


def resolve_seed(seed: int, split: ScenarioSplit) -> int:
    """Resolve a relative seed + split to an absolute seed.
    
    Parameters:
        seed: Relative seed within the split (0–split_max-1).
        split: Which split to use.
    
    Returns:
        Absolute seed value for deterministic generation.
    
    Raises:
        ValueError: If seed is out of range for the split.
    """
    max_seed = SPLIT_MAX_SEED[split]
    if seed < 0 or seed >= max_seed:
        raise ValueError(
            f"Seed {seed} out of range for split {split.value} "
            f"(0–{max_seed - 1})"
        )
    return SPLIT_OFFSETS[split] + seed


def derive_param(seed: int, param_name: str, param_type: str, 
                 choices: Optional[list] = None,
                 min_val: int = 0, max_val: int = 100) -> object:
    """Deterministically derive a parameter value from a seed.
    
    Uses SHA-256 of (domain_seed, seed, param_name) to produce a
    deterministic but distributed value.
    
    Parameters:
        seed: Absolute seed value.
        param_name: Name of the parameter (used in hash).
        param_type: One of "int", "float", "choice", "bool".
        choices: List of choices for "choice" type.
        min_val: Minimum for "int" type.
        max_val: Maximum for "int" type.
    
    Returns:
        Deterministic parameter value.
    """
    hash_input = f"{DOMAIN_SEED}:{seed}:{param_name}"
    h = hashlib.sha256(hash_input.encode()).hexdigest()
    # Use first 8 hex chars as a uint32
    val = int(h[:8], 16)
    
    if param_type == "int":
        return min_val + (val % (max_val - min_val + 1))
    elif param_type == "float":
        scale = (val % 10000) / 10000.0  # 0.0000–0.9999
        return min_val + scale * (max_val - min_val)
    elif param_type == "choice":
        if not choices:
            raise ValueError("choices required for 'choice' param_type")
        return choices[val % len(choices)]
    elif param_type == "bool":
        return (val % 2) == 0
    else:
        raise ValueError(f"Unknown param_type: {param_type}")


def derive_subseed(seed: int, key: str) -> int:
    """Derive a sub-seed for nested parameter generation."""
    hash_input = f"{DOMAIN_SEED}:{seed}:{key}"
    h = hashlib.sha256(hash_input.encode()).hexdigest()
    return int(h[:8], 16)


@dataclass
class ScenarioTemplate(ABC):
    """Abstract base class for parameterized scenario templates.
    
    Each concrete template represents one family of scenarios (e.g.,
    "Known Observable Condition"). Templates generate deterministic
    ArenaScenarios from a (seed, split) pair.
    
    Design invariants:
    1. Ground truth is defined first, engagement view derived from it.
    2. All generation is deterministic: same (seed, split) → same scenario.
    3. The evaluator_truth is NEVER exposed in engagement_view().
    4. Success conditions, expected observations, and acceptable actions
       are all derived deterministically from parameters.
    """
    
    family_name: str = ""
    """Human-readable family name, e.g., "Known Observable Condition"."""
    
    family_id: str = ""
    """Machine-readable family ID, e.g., "known-observable"."""
    
    schema_version: int = 1
    
    def generate(self, seed: int, split: ScenarioSplit = ScenarioSplit.DEV,
                 scenario_id_override: Optional[str] = None) -> ArenaScenario:
        """Generate a complete ArenaScenario from (seed, split).
        
        Parameters:
            seed: Relative seed within the split (0–split_max-1).
            split: Which split to use.
            scenario_id_override: Optional override for scenario_id.
        
        Returns:
            A fully-formed ArenaScenario with evaluator_truth populated.
        """
        abs_seed = resolve_seed(seed, split)
        scenario_id = scenario_id_override or f"{self.family_id}-s{abs_seed:04d}"
        
        scenario = self._create_scenario(abs_seed, split, scenario_id)
        
        # Validate the scenario
        issues = scenario.validate()
        if issues:
            raise ValueError(
                f"Scenario {scenario_id} validation failed: {'; '.join(issues)}"
            )
        
        return scenario
    
    @abstractmethod
    def _create_scenario(self, abs_seed: int, split: ScenarioSplit,
                         scenario_id: str) -> ArenaScenario:
        """Create the scenario. Must be implemented by subclasses.
        
        Parameters:
            abs_seed: Absolute seed (already resolved with split offset).
            split: Which split this scenario belongs to.
            scenario_id: Unique ID for this scenario.
        
        Returns:
            Populated ArenaScenario.
        """
        ...
    
    def split_of(self, seed: int) -> ScenarioSplit:
        """Determine which split a relative seed belongs to."""
        if seed < 1000:
            return ScenarioSplit.DEV
        elif seed < 2000:
            return ScenarioSplit.VALIDATION
        else:
            return ScenarioSplit.HOLDOUT


def create_scenario_from_template(template: ScenarioTemplate, seed: int,
                                   split: ScenarioSplit = ScenarioSplit.DEV,
                                   scenario_id: Optional[str] = None) -> ArenaScenario:
    """Convenience function to generate a scenario from a template.
    
    Parameters:
        template: The template instance to use.
        seed: Relative seed within the split.
        split: Which split to use.
        scenario_id: Optional override.
    
    Returns:
        Generated ArenaScenario.
    """
    return template.generate(seed=seed, split=split, 
                              scenario_id_override=scenario_id)
