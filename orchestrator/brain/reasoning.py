import logging

logger = logging.getLogger("reasoning")


def reasoning_chain(context: str, goal: str) -> str:
    steps = [
        f"1. Analyze context: {context[:100]}",
        f"2. Define objective: {goal[:100]}",
        "3. Identify available tools and vectors",
        "4. Select optimal approach",
        "5. Execute with verification",
        "6. Evaluate outcome and adapt",
    ]
    return "\n".join(steps)
