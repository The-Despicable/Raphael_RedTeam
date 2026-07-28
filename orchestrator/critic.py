import logging

logger = logging.getLogger("critic")


class Critique:
    def __init__(self, score: float, feedback: str) -> None:
        self.score = score
        self.feedback = feedback


async def judge(output: str, criteria: dict | None = None) -> Critique:
    return Critique(score=1.0, feedback="Output accepted (critic stub)")
