"""THE STUDENT — Autonomous pentest learning agent package."""

from .research_scheduler import ResearchScheduler
from .stack_matcher import StackMatcher
from .chain_synthesizer import ChainSynthesizer
from .integration_pipeline import StudentKB
from .knowledge_background_service import KnowledgeBackgroundService
from .coverage_gap_filler import generate_gap_study_plan, queue_gap_queries, trigger_immediate_research
from .payload_mutator import PayloadMutator, MutationResult
from .student import Student

__all__ = [
    "ResearchScheduler",
    "StackMatcher",
    "ChainSynthesizer",
    "StudentKB",
    "KnowledgeBackgroundService",
    "generate_gap_study_plan",
    "queue_gap_queries",
    "trigger_immediate_research",
    "PayloadMutator",
    "MutationResult",
    "Student",
]
