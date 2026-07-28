"""arena.templates — Parameterized scenario template framework.

Provides base template class and 5 family templates with
deterministic dev/validation/holdout separation.

Architecture:
- ScenarioTemplate: Abstract base class for all templates.
- 5 concrete family templates: KnownObservable, SignalInNoise, FalseLead,
  Contradiction, ForbiddenProximity.
- Each template uses deterministic seeding (seed + split_offset) to
  generate parameterized variants of a scenario family.
- Dev/Validation/Holdout splits are enforced at the seed level:
  - Dev (0–999): ground truth inspectable during development.
  - Validation (1000–1999): aggregate metrics visible, no ground truth.
  - Holdout (2000–9999): completely blind until final evaluation.

Usage:
    from arena.templates import KnownObservableTemplate, ScenarioSplit

    template = KnownObservableTemplate()
    scenario = template.generate(seed=42, split=ScenarioSplit.DEV)
    # scenario is a fully-formed ArenaScenario with evaluator_truth

Design Principle: Ground truth first. Each template defines the ground
truth deterministically from the seed, then derives the engagement view
as a strict subset (never leaks truth).
"""

from arena.templates.base import (
    ScenarioTemplate,
    ScenarioSplit,
    create_scenario_from_template,
)
from arena.templates.families import (
    KnownObservableTemplate,
    SignalInNoiseTemplate,
    FalseLeadTemplate,
    ContradictionTemplate,
    ForbiddenProximityTemplate,
    TEMPLATE_REGISTRY,
)

__all__ = [
    "ScenarioTemplate",
    "ScenarioSplit",
    "KnownObservableTemplate",
    "SignalInNoiseTemplate",
    "FalseLeadTemplate",
    "ContradictionTemplate",
    "ForbiddenProximityTemplate",
    "TEMPLATE_REGISTRY",
    "create_scenario_from_template",
]
