import time
import logging
from typing import Any

logger = logging.getLogger("neural_memory")

_episodic_store: dict[str, list[dict]] = {}
_semantic_store: dict[str, Any] = {}
_target_profiles: dict[str, dict] = {}
_target_stats: dict[str, dict] = {}

def store_episodic(
    event_type: str, target: str, model: str, context: str,
    input_data: str, output_summary: str, success: bool,
    score: float, latency: float,
) -> None:
    episode = {
        "event_type": event_type,
        "target": target,
        "model": model,
        "context": context,
        "input_data": input_data,
        "output_summary": output_summary,
        "success": success,
        "score": score,
        "latency": latency,
        "timestamp": time.time(),
    }
    if target not in _episodic_store:
        _episodic_store[target] = []
    _episodic_store[target].append(episode)

def retrieve_episodic(target: str, limit: int = 20) -> list[dict]:
    episodes = _episodic_store.get(target, [])
    return episodes[-limit:]

def store_semantic(key: str, value: Any) -> None:
    _semantic_store[key] = value


def retrieve_semantic(key: str) -> Any | None:
    return _semantic_store.get(key)


def store_skill_memory(
    skill_name: str,
    target: str = "",
    subdomain: str = "",
    result_summary: str = "",
    success: bool = True,
    latency: float = 0.0,
) -> None:
    store_episodic(
        event_type=f"skill:{skill_name}", target=target, model="skill",
        context=subdomain, input_data=target,
        output_summary=result_summary, success=success, score=1.0 if success else 0.0, latency=latency,
    )
    _semantic_store[f"skill:{skill_name}"] = {
        "target": target,
        "subdomain": subdomain,
        "result_summary": result_summary,
        "success": success,
        "latency": latency,
    }

def store_target_profile(target: str, classification: dict) -> None:
    _target_profiles[target] = {
        "classification": classification,
        "timestamp": time.time(),
    }

def update_target_stats(target: str, success: bool) -> None:
    if target not in _target_stats:
        _target_stats[target] = {"successes": 0, "failures": 0, "total": 0}
    _target_stats[target]["total"] += 1
    if success:
        _target_stats[target]["successes"] += 1
    else:
        _target_stats[target]["failures"] += 1
