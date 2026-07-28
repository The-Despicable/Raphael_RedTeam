"""
CI/CD Pipeline Exploitation Module (P0 - FORGE Phase 0)

Gateway capability for HuggingFace-level attack surface.
Provides workflow parsing, runner fingerprinting, token harvesting, and pipeline poisoning.

Modules:
- workflow_parser: GitHub Actions, GitLab CI, Azure Pipelines parser
- runner_fingerprinter: Self-hosted runner detection, labeling, version detection
- token_harvester: GITHUB_TOKEN, GITLAB_TOKEN, AZURE_PIPELINES_TOKEN extraction
- pipeline_poisoner: Workflow injection, artifact poisoning, cache poisoning
"""

from .workflow_parser import WorkflowParser, Workflow, Job, Step
from .runner_fingerprinter import RunnerFingerprinter, RunnerInfo
from .token_harvester import TokenHarvester, TokenInfo
from .pipeline_poisoner import PipelinePoisoner, PoisonResult

__all__ = [
    "WorkflowParser", "Workflow", "Job", "Step",
    "RunnerFingerprinter", "RunnerInfo",
    "TokenHarvester", "TokenInfo",
    "PipelinePoisoner", "PoisonResult",
]

__version__ = "0.1.0"