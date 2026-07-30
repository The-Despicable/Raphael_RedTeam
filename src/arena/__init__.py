"""arena package — Arena evaluation framework.

Provides:
- runner: Core ArenaScenario, ArenaRunner, EvaluationResult, evaluators
- scenarios: JSON-serialized scenario definitions
- templates: Parameterized scenario template framework with
  dev/validation/holdout separation (Stage 2.5)
"""

from arena.runner import (
    ArenaScenario,
    EvaluationResult,
    EvaluationVerdict,
    ArenaRunner,
    create_scenario_1,
    create_scenario_2,
    create_scenario_3,
    create_scenario_4,
    create_scenario_5,
    load_scenario,
)
from arena.templates import (
    ScenarioTemplate,
    ScenarioSplit,
    KnownObservableTemplate,
    SignalInNoiseTemplate,
    FalseLeadTemplate,
    ContradictionTemplate,
    ForbiddenProximityTemplate,
    TEMPLATE_REGISTRY,
    create_scenario_from_template,
)

__all__ = [
    "ArenaScenario",
    "EvaluationResult",
    "EvaluationVerdict",
    "ArenaRunner",
    "create_scenario_1",
    "create_scenario_2",
    "create_scenario_3",
    "create_scenario_4",
    "create_scenario_5",
    "load_scenario",
    # Templates (Stage 2.5)
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