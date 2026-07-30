"""
Postmortem Mode — RSI-style failure analysis using critic + LLM.

Pipeline:
  1. Execute task (or accept existing output)
  2. Critic analyzes output for failure signals
  3. LLM generates root cause analysis + specific fixes
   4. LLM replans with constraints from failures

Usage: python3 -m orchestrator.app postmortem "<task>"
       python3 -m orchestrator.app postmortem "<task>" --output "path/to/execution.log"
"""
import asyncio, json, logging, os

from ..providers import _call_model_raw
from ..critic import judge

logger = logging.getLogger("postmortem")

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data", "postmortems")


async def _call(alias, prompt, temperature=0.7, timeout=120):
    try:
        return await asyncio.wait_for(
            _call_model_raw(alias, [{"role": "user", "content": prompt}],
                          max_tokens=4096, temperature=temperature),
            timeout=timeout)
    except asyncio.TimeoutError:
        return f"[TIMEOUT after {timeout}s]"
    except Exception as e:
        return f"[ERROR: {e}]"


async def handle(question, rounds=2, temperature=0.7):
    config = {}
    output_path = None
    if isinstance(question, dict):
        config = question.get("mode_config", {})
        msgs = question.get("messages", [{}])
        question = msgs[-1].get("content", "")
        output_path = config.get("output_path") or config.get("log_file")

    if not question:
        question = "Analyze a failed execution and propose fixes"

    logger.info(f"Postmortem — '{question[:60]}...'")

    original_task = question

    # Phase 1: Read execution output
    execution_output = ""
    if output_path and os.path.exists(output_path):
        with open(output_path) as f:
            execution_output = f.read()
        logger.info(f"Read {len(execution_output)} chars from {output_path}")
    else:
        execution_output = config.get("output", "")
        if not execution_output:
            execution_output = f"[No execution output provided. Task: {question}]"

    # Phase 2: Critic analysis
    judgment = judge(execution_output, task=question)

    # Phase 3: Root cause analysis via LLM
    critic_block = f"""Critic Judgment: {judgment['summary']}
Verdict: {judgment['verdict']}
Failures: {json.dumps(judgment['failures'], indent=2)}
Successes: {json.dumps(judgment['successes'], indent=2)}
Score: {judgment['score']}"""

    rca_prompt = f"""You are performing a root cause analysis on a failed security operation.

Original task: {original_task}

Execution output (last 2000 chars):
{execution_output[-2000:]}

{critic_block}

Analyze:
1. What specific signal(s) caused the failure? (match the critic signals)
2. What is the most likely root cause (network, permissions, tool config, target behavior)?
3. What is the exact fix? (one concrete change to make)
4. What alternative approach should be tried if the fix fails?

Output a concise, actionable postmortem."""
    rca = await _call("oc-deepseek-free", rca_prompt, temperature=0.4, timeout=120)

    # Phase 4: Refined plan incorporating failure knowledge
    refine_prompt = f"""Based on this postmortem, generate a corrected execution plan.

Original task: {original_task}

Root cause analysis:
{rca[:2000]}

Produce a revised numbered plan (3-6 steps) that avoids the failure.
Include specific tool flags, alternative ports, or fallback methods.
Output only the revised plan."""
    refined = await _call("oc-deepseek-free", refine_prompt, temperature=0.5, timeout=120)

    # Save postmortem for future reference
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    safe_name = "".join(c for c in original_task[:40] if c.isalnum() or c in " _-").strip() or "postmortem"
    report_path = os.path.join(OUTPUT_DIR, f"{safe_name}_{int(asyncio.get_event_loop().time())}.md")
    report = f"""# Postmortem: {original_task}

## Critic Judgment
{judgment['summary']}
Verdict: {judgment['verdict']} | Confidence: {judgment['confidence']} | Score: {judgment['score']}

### Failures Detected
{chr(10).join(f'- {f["signal"]}: {f["match"]}' for f in judgment['failures'])}

### Successes
{chr(10).join(f'- {s["signal"]}: {s["match"]}' for s in judgment['successes'])}

## Root Cause Analysis
{rca}

## Corrected Plan
{refined}
"""
    with open(report_path, "w") as f:
        f.write(report)
    logger.info(f"Postmortem saved to {report_path}")

    full = f"""## Postmortem — {original_task}

### Critic Assessment
{judgment['summary']}
Verdict: **{judgment['verdict']}** | Confidence: {judgment['confidence']}

### Root Cause Analysis
{rca[:2500]}

### Corrected Plan
{refined[:2500]}

### Report Saved
`{report_path}`

---
Raphael 2.0 — Postmortem Mode"""

    return {
        "final": full,
        "judgment": judgment,
        "rca": rca,
        "corrected_plan": refined,
        "report_path": report_path,
    }
