from ..providers import call_model, call_parallel

DEFAULT_MODELS = ["w12", "w13", "w480b", "m3"]
MODEL_LABELS = {"w12": "WORMGPT-12", "w13": "WORMGPT-13", "w480b": "WORMGPT-480B", "m3": "MiniMax-M3"}


async def handle(question, rounds=2, temperature=0.85, models=None):
    if models is None:
        models = list(DEFAULT_MODELS)
    if len(models) < 2:
        models = list(DEFAULT_MODELS)[:2]

    contributions = {}

    for r in range(1, rounds + 1):
        ctx = f"[ROUND {r}/{rounds}]\nProblem: {question}\n\n"
        if contributions:
            for mid in models:
                label = MODEL_LABELS.get(mid, mid)
                ctx += f"<{label}> contributed:\n{contributions.get(mid, 'N/A')}\n\n"
            ctx += "These are the existing ideas. You MUST add NEW layers, NEW techniques, or NEW perspectives not covered yet. Identify gaps and fill them."
        else:
            ctx += "Present your approach to this problem."

        for mid in models:
            contrib = await call_model(
                mid,
                [{"role": "user", "content": ctx}],
                max_tokens=4096, temperature=temperature if r == 1 else 0.9
            )
            contributions[mid] = contrib

    all_contribs = ""
    for mid in models:
        label = MODEL_LABELS.get(mid, mid)
        all_contribs += f"<{label}>:\n{contributions.get(mid, 'N/A')}\n\n"

    final = await call_model("kimi", [{"role": "user", "content":
        f"Problem: {question}\n\n{all_contribs}"
        "Synthesize the strongest unified solution."}],
        max_tokens=4096, temperature=0.3)

    return {"rounds": rounds, "models": models, "contributions": contributions, "final": final}
