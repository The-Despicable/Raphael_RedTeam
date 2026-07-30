from ..providers import call_model
from ..agents.skill_agent import SkillAgent

DEFAULT_ROUNDS = 3
DEFAULT_MODELS = ["w12", "w13"]

_skill_agent = None

def _get_skill_agent():
    global _skill_agent
    if _skill_agent is None:
        _skill_agent = SkillAgent()
        _skill_agent._ensure_index()
    return _skill_agent


async def handle(question, rounds=DEFAULT_ROUNDS, temperature=0.85, use_skills=True, models=None):
    if models is None:
        models = list(DEFAULT_MODELS)
    if len(models) < 2:
        models = list(DEFAULT_MODELS)[:2]

    model_a, model_b = models[0], models[1]
    history = {}

    skill_context = ""
    if use_skills:
        agent = _get_skill_agent()
        evidence = agent.debate_evidence(question, question)
        if evidence:
            skill_lines = []
            for e in evidence[:5]:
                refs = ", ".join(e["references"][:2]) if e["references"] else "none"
                skill_lines.append(f"- {e['skill']} [{e['subdomain']}] (relevance: {e['relevance']}) — references: {refs}")
            skill_context = "\nSkill Evidence:\n" + "\n".join(skill_lines) + "\n"
            history["skill_evidence"] = evidence

    for r in range(1, rounds + 1):
        ctx = f"[ROUND {r}/{rounds}]\nQuestion: {question}\n{skill_context}"
        if r == 1:
            ctx += "\nState your initial position on how to accomplish this. Reference relevant skills from the evidence above."
            history[model_a] = await call_model(model_a,
                [{"role": "user", "content": ctx}], max_tokens=4096, temperature=temperature)
            ctx2 = f"[ROUND {r}/{rounds}]\nQuestion: {question}\n{skill_context}\n\nYour opponent argues:\n{history[model_a]}\n\nDestroy their argument and present your counter-position using skill evidence."
            history[model_b] = await call_model(model_b,
                [{"role": "user", "content": ctx2}], max_tokens=4096, temperature=temperature)
        else:
            ctx += f"\n<Model A> previous:\n{history.get(model_a, 'N/A')}\n\n<Model B> previous:\n{history.get(model_b, 'N/A')}\n\n"
            ctx += "Both of you are repeating yourselves. You MUST bring NEW arguments, NEW techniques, NEW angles not mentioned before. Attack the weakness in the other position that hasn't been addressed yet."
            history[model_a] = await call_model(model_a,
                [{"role": "user", "content": ctx}], max_tokens=4096, temperature=temperature)

            ctx2 = f"[ROUND {r}/{rounds}]\nQuestion: {question}\n\n<Model A> new attack:\n{history[model_a]}\n\n<Model B> previous:\n{history.get(model_b, 'N/A')}\n\n"
            ctx2 += "<Model A> brought NEW arguments. You MUST counter with DIFFERENT techniques, DIFFERENT approaches. Do NOT repeat anything from previous rounds."
            history[model_b] = await call_model(model_b,
                [{"role": "user", "content": ctx2}], max_tokens=4096, temperature=temperature)

    final = await call_model(model_b, [{"role": "user", "content":
        f"Question: {question}\n\n<Model A> final:\n{history[model_a]}\n\n<Model B> final:\n{history[model_b]}\n\n"
        "Synthesize the best final answer from both positions."}],
        max_tokens=4096, temperature=0.3, system_override="Output only the synthesized answer.")

    return {
        "rounds": rounds,
        "models": [model_a, model_b],
        "history": history,
        "final": final,
        "skill_evidence_count": len(history.get("skill_evidence", [])),
    }
