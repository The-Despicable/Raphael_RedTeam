import logging
from typing import Any

logger = logging.getLogger("reflection")


def reflect_outcome(success: bool, findings: list[Any], phase: str) -> str:
    if success:
        return f"Phase '{phase}' succeeded. {len(findings)} findings collected. Continue to next phase."
    else:
        return f"Phase '{phase}' failed. {len(findings)} findings collected before failure. Adjusting strategy."
