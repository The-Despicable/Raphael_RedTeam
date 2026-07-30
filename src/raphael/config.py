"""Raphael configuration — loaded from environment or defaults."""
from __future__ import annotations
import os
import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class RaphaelConfig:
    """Configuration for Raphael engagement."""

    # Target
    target: str = ""
    target_host: str = ""
    target_port: int | None = None

    # Engagement
    engagement_id: str = "raphael_auto"
    max_cycles: int = 50
    cycle_delay_seconds: float = 1.0

    # Blackboard
    db_path: str = str(Path(__file__).parent / "data" / "raphael_blackboard.db")

    # Executor
    tool_api_url: str = "http://localhost:3800"
    force_local: bool = False
    default_timeout: int = 120

    # Thermoregulator
    risk_threshold_pause: float = 0.8
    risk_threshold_resume: float = 0.3
    thermoregulator_hz: float = 1.0  # Hz for Wave 1 (10 Hz later)

    # Orchestrator API
    orchestrator_url: str = "http://localhost:3900"

    @classmethod
    def from_env(cls) -> "RaphaelConfig":
        """Load config from environment variables."""
        target = os.getenv("RAPHAEL_TARGET", "")
        target_host = target
        target_port = None
        
        # Parse host:port format
        if target:
            match = re.match(r'^([^:]+):(\d+)$', target)
            if match:
                target_host = match.group(1)
                target_port = int(match.group(2))

        return cls(
            target=target,
            target_host=target_host,
            target_port=target_port,
            engagement_id=os.getenv("RAPHAEL_ENGAGEMENT_ID", "raphael_auto"),
            max_cycles=int(os.getenv("RAPHAEL_MAX_CYCLES", "50")),
            cycle_delay_seconds=float(os.getenv("RAPHAEL_CYCLE_DELAY", "1.0")),
            db_path=os.getenv("RAPHAEL_DB_PATH", cls.db_path),
            tool_api_url=os.getenv("KALI_TOOLS_URL", "http://localhost:3800"),
            force_local=os.getenv("RAPHAEL_FORCE_LOCAL", "0") == "1",
            orchestrator_url=os.getenv("ORCHESTRATOR_URL", "http://localhost:3900"),
            risk_threshold_pause=float(os.getenv("RAPHAEL_RISK_PAUSE", "0.8")),
            risk_threshold_resume=float(os.getenv("RAPHAEL_RISK_RESUME", "0.3")),
        )
