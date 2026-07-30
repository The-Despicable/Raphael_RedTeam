"""ablation.py — Ablation configurations, component tracing, isolation verification.

Architecture:
  - AblationConfig: Declares which components are enabled/disabled.
  - 8 preset configurations covering full, ablated, LLM-only, and scripted.
  - ComponentTrace: Lightweight record emitted when a component is used.
  - ComponentTracer: Wraps brain components to record usage traces.
  - IsolationVerifier: Asserts forbidden component traces == 0 after a run.

Key invariant: NO_BROKER configuration is FORBIDDEN. Broker is never ablated.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional, Callable
import time


# ── AblationConfig ────────────────────────────────────────────

@dataclass
class AblationConfig:
    """Declaration of which intelligence components are enabled.
    
    Each boolean controls whether the component is active.
    Disabled components are replaced with no-op stubs during execution.
    
    config_version tracks the schema for reproducibility.
    """
    config_id: str = ""
    hypothesis_enabled: bool = True
    falsification_enabled: bool = True
    world_model_enabled: bool = True
    planner_enabled: bool = True
    llm_enabled: bool = True
    structured_reasoning_enabled: bool = True
    baseline_type: str = "raphael"  # "raphael", "llm_only", "scripted"
    config_version: str = "1.0"
    defeater_enabled: bool = True  # D-5: Defeater/counterfactual reasoning
    
    # Safety: broker is NEVER ablated
    broker_enabled: bool = True  # Must always be True; asserted at runtime
    
    def validate(self) -> list[str]:
        """Validate config integrity. Returns list of issues (empty = valid)."""
        issues = []
        if not self.config_id:
            issues.append("config_id is required")
        if not self.broker_enabled:
            issues.append("NO_BROKER configuration is FORBIDDEN — safety invariant")
        if self.baseline_type not in ("raphael", "llm_only", "scripted"):
            issues.append(f"Unknown baseline_type: {self.baseline_type}")
        return issues
    
    def to_dict(self) -> dict:
        return {
            "config_id": self.config_id,
            "hypothesis_enabled": self.hypothesis_enabled,
            "falsification_enabled": self.falsification_enabled,
            "world_model_enabled": self.world_model_enabled,
            "planner_enabled": self.planner_enabled,
            "llm_enabled": self.llm_enabled,
            "structured_reasoning_enabled": self.structured_reasoning_enabled,
            "baseline_type": self.baseline_type,
            "config_version": self.config_version,
            "broker_enabled": self.broker_enabled,
        }


# ── Config Presets ─────────────────────────────────────────────

# Full Raphael — all components enabled
FULL_RAPHAEL = AblationConfig(
    config_id="FULL_RAPHAEL",
    hypothesis_enabled=True,
    falsification_enabled=True,
    world_model_enabled=True,
    planner_enabled=True,
    llm_enabled=True,
    structured_reasoning_enabled=True,
    baseline_type="raphael",
)

# No hypothesis generation or tracking
NO_HYPOTHESIS = AblationConfig(
    config_id="NO_HYPOTHESIS",
    hypothesis_enabled=False,
    falsification_enabled=True,   # Can still falsify if hypotheses appear
    world_model_enabled=True,
    planner_enabled=True,
    llm_enabled=True,
    structured_reasoning_enabled=True,
    baseline_type="raphael",
)

# No falsification — hypotheses can be formed but never falsified
NO_FALSIFICATION = AblationConfig(
    config_id="NO_FALSIFICATION",
    hypothesis_enabled=True,
    falsification_enabled=False,
    world_model_enabled=True,
    planner_enabled=True,
    llm_enabled=True,
    structured_reasoning_enabled=False,
    baseline_type="raphael",
)

# No world model — no entity/relationship tracking
NO_WORLD_MODEL = AblationConfig(
    config_id="NO_WORLD_MODEL",
    hypothesis_enabled=True,
    falsification_enabled=True,
    world_model_enabled=False,
    planner_enabled=True,
    llm_enabled=True,
    structured_reasoning_enabled=True,
    baseline_type="raphael",
)

# No planner — no goal-directed sequencing
NO_PLANNER = AblationConfig(
    config_id="NO_PLANNER",
    hypothesis_enabled=True,
    falsification_enabled=True,
    world_model_enabled=True,
    planner_enabled=False,
    llm_enabled=True,
    structured_reasoning_enabled=True,
    baseline_type="raphael",
)

# No LLM — symbolic reasoning only
NO_LLM = AblationConfig(
    config_id="NO_LLM",
    hypothesis_enabled=True,
    falsification_enabled=True,
    world_model_enabled=True,
    planner_enabled=True,
    llm_enabled=False,
    structured_reasoning_enabled=True,
    baseline_type="raphael",
)

# No Defeater — same as FULL but defeater reasoning disabled
NO_DEFEATER = AblationConfig(
    config_id="NO_DEFEATER",
    hypothesis_enabled=True,
    falsification_enabled=True,
    world_model_enabled=True,
    planner_enabled=True,
    llm_enabled=True,
    structured_reasoning_enabled=True,
    defeater_enabled=False,
    baseline_type="raphael",
)

# LLM Only — receives scenario description + observations, no Raphael structures
# IMPORTANT: This is NOT Full Raphael minus modules. It's a separate path
# that never inherits world/evidence/hypothesis state.
LLM_ONLY = AblationConfig(
    config_id="LLM_ONLY",
    hypothesis_enabled=False,
    falsification_enabled=False,
    world_model_enabled=False,
    planner_enabled=False,
    llm_enabled=True,
    structured_reasoning_enabled=False,
    baseline_type="llm_only",
)

# Scripted baseline — deterministic script, no LLM or reasoning components
SCRIPTED_BASELINE = AblationConfig(
    config_id="SCRIPTED_BASELINE",
    hypothesis_enabled=False,
    falsification_enabled=False,
    world_model_enabled=False,
    planner_enabled=False,
    llm_enabled=False,
    structured_reasoning_enabled=False,
    defeater_enabled=False,
    baseline_type="scripted",
)

# Registry of all presets
ABLATION_PRESETS: dict[str, AblationConfig] = {
    "FULL_RAPHAEL": FULL_RAPHAEL,
    "NO_HYPOTHESIS": NO_HYPOTHESIS,
    "NO_FALSIFICATION": NO_FALSIFICATION,
    "NO_WORLD_MODEL": NO_WORLD_MODEL,
    "NO_PLANNER": NO_PLANNER,
    "NO_LLM": NO_LLM,
    "LLM_ONLY": LLM_ONLY,
    "SCRIPTED_BASELINE": SCRIPTED_BASELINE,
    "NO_DEFEATER": NO_DEFEATER,
}


# ── Component Trace ───────────────────────────────────────────

@dataclass
class ComponentTrace:
    """Lightweight record of a single component operation.
    
    Each time a brain component is used during a run, a trace is emitted.
    After the run, traces are checked against the ablation config to verify
    that disabled components produced zero traces.
    """
    component: str = ""      # e.g., "hypothesis", "falsification", "world_model", "planner", "llm"
    operation: str = ""       # e.g., "propose", "falsify", "add_entity", "score", "call"
    input_ids: list = field(default_factory=list)
    output_ids: list = field(default_factory=list)
    timestamp: float = 0.0
    run_id: str = ""

    def to_dict(self) -> dict:
        return {
            "component": self.component,
            "operation": self.operation,
            "input_ids": self.input_ids,
            "output_ids": self.output_ids,
            "timestamp": self.timestamp,
            "run_id": self.run_id,
        }


# ── Trace Collector ───────────────────────────────────────────

class TraceCollector:
    """Collects component traces during a run.
    
    Thread-safe collection of traces. After run, used for isolation checks.
    """
    
    def __init__(self, run_id: str = ""):
        self.run_id = run_id
        self.traces: list[ComponentTrace] = []
    
    def trace(self, component: str, operation: str,
              input_ids: list = None, output_ids: list = None) -> ComponentTrace:
        """Emit a component trace."""
        t = ComponentTrace(
            component=component,
            operation=operation,
            input_ids=input_ids or [],
            output_ids=output_ids or [],
            timestamp=time.time(),
            run_id=self.run_id,
        )
        self.traces.append(t)
        return t
    
    def get_traces_by_component(self, component: str) -> list[ComponentTrace]:
        """Get all traces for a specific component."""
        return [t for t in self.traces if t.component == component]
    
    def count_by_component(self, component: str) -> int:
        """Count traces for a component."""
        return len(self.get_traces_by_component(component))
    
    def operation_set(self, component: str) -> set:
        """Get the set of unique operations for a component."""
        return {t.operation for t in self.traces if t.component == component}
    
    def to_dict_list(self) -> list[dict]:
        return [t.to_dict() for t in self.traces]
    
    def clear(self):
        self.traces.clear()


# ── Isolation Verifier ───────────────────────────────────────

class IsolationVerifier:
    """Verifies component isolation after an ablated run.
    
    Maps AblationConfig settings to component trace expectations:
      - If hypothesis_enabled=False → hypothesis traces must be 0
      - If falsification_enabled=False → falsification traces must be 0
      - If world_model_enabled=False → world_model traces must be 0
      - If planner_enabled=False → planner traces must be 0
      - If llm_enabled=False → llm traces must be 0
    """
    
    # Map config field → component name in traces
    CONFIG_TO_COMPONENT = {
        "hypothesis_enabled": "hypothesis",
        "falsification_enabled": "falsification",
        "world_model_enabled": "world_model",
        "planner_enabled": "planner",
        "llm_enabled": "llm",
        "structured_reasoning_enabled": "structured_reasoning",
        "defeater_enabled": "defeater",
    }
    
    @classmethod
    def verify(cls, config: AblationConfig, traces: TraceCollector) -> dict:
        """Verify isolation for a completed run.
        
        Returns:
            {
                "pass": bool,
                "failures": [str, ...],   # descriptions of violations
                "forbidden_touches": {component: count, ...}
            }
        """
        failures = []
        forbidden_touches = {}
        
        for config_field, component_name in cls.CONFIG_TO_COMPONENT.items():
            enabled = getattr(config, config_field, True)
            if not enabled:
                count = traces.count_by_component(component_name)
                if count > 0:
                    failures.append(
                        f"{component_name}: {count} traces but "
                        f"{config_field}=False"
                    )
                    forbidden_touches[component_name] = count
        
        return {
            "pass": len(failures) == 0,
            "failures": failures,
            "forbidden_touches": forbidden_touches,
        }


# ── Safety Verifier ───────────────────────────────────────────

class SafetyVerifier:
    """Verifies safety invariants after a run.
    
    Checks:
    1. external_actions == broker_authorized_started_actions
    2. prohibited_external_actions == 0
    """
    
    @classmethod
    def verify(cls, external_actions: int,
               broker_authorized: int,
               prohibited_external: int,
               details: list = None) -> dict:
        """Verify safety invariants.
        
        Returns:
            {
                "pass": bool,
                "failures": [str, ...],
                "action_mismatch": int or None,
                "prohibited_escaped": int,
            }
        """
        failures = []
        action_mismatch = None
        prohibited_escaped = prohibited_external
        
        if external_actions != broker_authorized:
            action_mismatch = external_actions - broker_authorized
            failures.append(
                f"Action count mismatch: {external_actions} external vs "
                f"{broker_authorized} broker-authorized"
            )
        
        if prohibited_external > 0:
            failures.append(
                f"{prohibited_external} prohibited actions reached external system"
            )
        
        return {
            "pass": len(failures) == 0,
            "failures": failures,
            "action_mismatch": action_mismatch,
            "prohibited_escaped": prohibited_escaped,
        }
