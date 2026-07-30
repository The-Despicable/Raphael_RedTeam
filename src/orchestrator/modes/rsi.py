from ..providers import call_model

DEFAULT_TEAM = {
    "critical":  "oc-deepseek-free",
    "deep_dive": "oc-hy3-free",
    "synthesis": "oc-nemotron-ultra-free",
}

async def handle(question, rounds=2, temperature=0.5, rounds_limit=5, team_models=None):
    if team_models is None:
        team_models = dict(DEFAULT_TEAM)
    if rounds > rounds_limit:
        rounds = rounds_limit

    ctx = f"[RSI] Research, Search, Integrate\nTask: {question}\n\n"
    ctx += "Phase 1 (Research): Analyze the problem rigorously."
    ctx += "\nPhase 2 (Search): Verify assumptions, check edge cases."
    ctx += "\nPhase 3 (Integrate): Produce a complete, proven answer."

    research = {}
    for role, alias in team_models.items():
        research[role] = await call_model(
            alias,
            [{"role": "user", "content": f"[{role.upper()}]\n{ctx}"}],
            max_tokens=4096, temperature=temperature
        )

    for r in range(2, rounds + 1):
        ctx2 = f"[RSI] Round {r}/{rounds} — Critique & Refine\nTask: {question}\n\n"
        for role, text in research.items():
            ctx2 += f"\n{role.upper()} said:\n{text}\n"
        ctx2 += "\nApply deeper scrutiny. Identify contradictions, edge cases, and missing proof."

        for role, alias in team_models.items():
            research[role] = await call_model(
                alias,
                [{"role": "user", "content": ctx2}],
                max_tokens=4096, temperature=temperature * 0.9
            )

    ctx2 = f"[RSI] Final Synthesis\nTask: {question}\n\n"
    for role, text in research.items():
        ctx2 += f"\n{role.upper()} said:\n{text}\n"

    unified = await call_model(
        team_models["synthesis"],
        [{"role": "user", "content": ctx2 + "\nSynthesize the analyses into ONE complete, rigorous solution with proof."}],
        max_tokens=4096, temperature=0.3
    )

    return {"research": research, "unified_plan": unified, "rounds_used": rounds, "rounds_limit": rounds_limit}
