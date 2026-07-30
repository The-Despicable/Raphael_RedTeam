import asyncio
import random
import time
from typing import Callable, Awaitable, TypeVar, Optional, List, Any

import httpx


T = TypeVar("T")


class RetryExhaustedError(Exception):
    def __init__(self, attempts: List[dict]):
        self.attempts = attempts
        super().__init__(f"All retries exhausted after {len(attempts)} attempts")


def _backoff(attempt: int) -> float:
    return min(2 ** attempt, 30.0)


def _jitter(base: float) -> float:
    return random.uniform(0, base)


async def retry_with_fallback(
    call_fn: Callable[..., Awaitable[T]],
    *,
    model_list: List[str],
    brain: Optional[Any] = None,
    max_retries_per_model: int = 3,
    timeout_per_call: float = 60.0,
    estimate_success_fn: Optional[Callable[[T, bool], float]] = None,
    **call_kwargs
) -> T:
    attempts_log: List[dict] = []
    overall = 0

    for model in model_list:
        if brain is not None and callable(getattr(brain, "is_circuit_open", None)):
            try:
                if brain.is_circuit_open(model):
                    attempts_log.append({"model": model, "attempt": overall, "result": "circuit_open"})
                    continue
            except Exception:
                pass

        for attempt in range(max_retries_per_model):
            start = time.perf_counter()
            error_occurred = False
            result: T = None

            try:
                kwargs = {**call_kwargs, "model": model}
                result = await asyncio.wait_for(call_fn(**kwargs), timeout=timeout_per_call)
            except asyncio.TimeoutError:
                error_occurred = True
                attempts_log.append({"model": model, "attempt": overall, "result": "timeout"})
            except httpx.HTTPStatusError as e:
                error_occurred = True
                attempts_log.append({
                    "model": model, "attempt": overall, "result": "http_error",
                    "status": e.response.status_code,
                })
                if 400 <= e.response.status_code < 500 and e.response.status_code != 429:
                    break
            except (httpx.NetworkError, httpx.ConnectError):
                error_occurred = True
                attempts_log.append({"model": model, "attempt": overall, "result": "network_error"})
            except Exception as e:
                error_occurred = True
                attempts_log.append({
                    "model": model, "attempt": overall, "result": "unknown_error",
                    "detail": str(e),
                })

            latency = time.perf_counter() - start

            success_score = 0.0 if error_occurred else 0.9
            if estimate_success_fn is not None and not error_occurred:
                try:
                    success_score = estimate_success_fn(result, False)
                except Exception:
                    pass

            if brain is not None and callable(getattr(brain, "update_stats", None)):
                try:
                    brain.update_stats(model, success=success_score, latency=latency)
                except Exception:
                    pass

            if not error_occurred and success_score > 0.3:
                return result

            if attempt < max_retries_per_model - 1:
                delay = _jitter(_backoff(attempt))
                await asyncio.sleep(delay)

            overall += 1

    raise RetryExhaustedError(attempts_log)


def with_retry(
    model_list: List[str],
    brain: Optional[Any] = None,
    max_retries_per_model: int = 3,
    timeout_per_call: float = 60.0,
    estimate_success_fn: Optional[Callable[[T, bool], float]] = None,
):
    def decorator(func: Callable[..., Awaitable[T]]):
        async def wrapper(*args, **kwargs) -> T:
            async def call_fn(*, model: str, **inner):
                return await func(*args, model=model, **inner)

            return await retry_with_fallback(
                call_fn,
                model_list=model_list,
                brain=brain,
                max_retries_per_model=max_retries_per_model,
                timeout_per_call=timeout_per_call,
                estimate_success_fn=estimate_success_fn,
                **kwargs,
            )
        return wrapper
    return decorator
