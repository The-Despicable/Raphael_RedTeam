"""OpenAI-compatible LLM service (async httpx).

Uses OPENAI_BASE_URL + first available of OPENAI_API_KEY / OMNIROUTE_API_KEY.
Never hard-fails when no key is configured: returns a deterministic fallback
string and marks the response as `llm_used=False` so callers can degrade.

Integrates with orchestrator.brain.reasoning_chain / strategy helpers when the
orchestrator package is importable; otherwise uses the local reasoning fallback.
"""
from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional

import httpx

from .config import Settings, get_settings

log = logging.getLogger("brain.llm")


class LLMResponse:
    __slots__ = ("text", "tokens_used", "model", "llm_used", "latency_ms", "error")

    def __init__(
        self,
        text: str,
        tokens_used: int,
        model: str,
        llm_used: bool,
        latency_ms: float = 0.0,
        error: Optional[str] = None,
    ):
        self.text = text
        self.tokens_used = tokens_used
        self.model = model
        self.llm_used = llm_used
        self.latency_ms = latency_ms
        self.error = error

    def to_dict(self) -> Dict[str, Any]:
        return {
            "text": self.text,
            "tokens_used": self.tokens_used,
            "model": self.model,
            "llm_used": self.llm_used,
            "latency_ms": self.latency_ms,
            "error": self.error,
        }


class LLMService:
    """Async OpenAI-compatible chat client with graceful fallback."""

    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or get_settings()
        self.base_url = self.settings.openai_base_url.rstrip("/")
        self.api_key = self.settings.llm_api_key
        self.model = self.settings.llm_model
        self.timeout = self.settings.llm_request_timeout
        self.total_tokens_used = 0
        self._client: Optional[httpx.AsyncClient] = None

    @property
    def available(self) -> bool:
        return bool(self.api_key)

    async def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None:
            headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                headers=headers,
                timeout=self.timeout,
            )
        return self._client

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def chat(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.2,
        max_tokens: int = 1024,
        **kwargs: Any,
    ) -> LLMResponse:
        """Async chat completion. Falls back deterministically if no key."""
        if not self.available:
            fallback = self._fallback_text(messages)
            log.debug("LLM unavailable; using fallback: %s", fallback[:80])
            return LLMResponse(
                text=fallback,
                tokens_used=0,
                model="fallback",
                llm_used=False,
                latency_ms=0.0,
            )

        # Global cost-control guard: once the lifetime token spend reaches
        # MAX_SPEND_TOKENS, stop calling the provider and degrade to the
        # deterministic fallback (spec: honor budget).
        if (
            self.settings.raphael_cost_control
            and self.total_tokens_used >= self.settings.max_spend_tokens
        ):
            log.warning(
                "token budget exhausted (%d/%d); using offline fallback",
                self.total_tokens_used,
                self.settings.max_spend_tokens,
            )
            return LLMResponse(
                text=self._fallback_text(messages),
                tokens_used=0,
                model="fallback",
                llm_used=False,
                latency_ms=0.0,
                error="token budget exhausted",
            )

        client = await self._ensure_client()
        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            **kwargs,
        }
        t0 = time.perf_counter()
        try:
            r = await client.post("/chat/completions", json=payload)
            r.raise_for_status()
            data = r.json()
            text = data["choices"][0]["message"]["content"]
            tokens = data.get("usage", {}).get("total_tokens", 0)
            self.total_tokens_used += tokens
            return LLMResponse(
                text=text,
                tokens_used=tokens,
                model=self.model,
                llm_used=True,
                latency_ms=(time.perf_counter() - t0) * 1000,
            )
        except httpx.HTTPStatusError as e:
            log.warning("LLM HTTP %s: %s", e.response.status_code, str(e)[:200])
            return LLMResponse(
                text=self._fallback_text(messages),
                tokens_used=0,
                model="fallback",
                llm_used=False,
                latency_ms=(time.perf_counter() - t0) * 1000,
                error=f"http {e.response.status_code}",
            )
        except (httpx.RequestError, KeyError, ValueError) as e:
            log.warning("LLM error: %s", str(e)[:200])
            return LLMResponse(
                text=self._fallback_text(messages),
                tokens_used=0,
                model="fallback",
                llm_used=False,
                latency_ms=(time.perf_counter() - t0) * 1000,
                error=str(e)[:200],
            )

    async def reasoning_chain(self, context: Dict[str, Any], goal: str) -> str:
        """Run a reasoning chain. Reuses orchestrator.brain.reasoning_chain when
        available; otherwise an inline LLM call with a planning prompt."""
        try:
            from orchestrator.brain.reasoning import reasoning_chain as _impl  # type: ignore

            return _impl(context, goal)
        except Exception:
            pass

        messages = [
            {
                "role": "system",
                "content": (
                    "You are the reasoning core of the Raphael 2.0 autonomous brain. "
                    "Produce a concise step-by-step plan to achieve the stated goal given the "
                    "current context. Avoid prohibited actions and respect engagement scope."
                ),
            },
            {
                "role": "user",
                "content": f"Context:\n{context}\n\nGoal:\n{goal}",
            },
        ]
        resp = await self.chat(messages, temperature=0.1, max_tokens=800)
        return resp.text

    async def build_strategy(
        self, target: str, profile: Dict[str, Any], findings: List[Dict[str, Any]]
    ) -> List[str]:
        """Reuse orchestrator.brain.strategy.build_strategy if available."""
        try:
            from orchestrator.brain.strategy import build_strategy as _impl  # type: ignore

            return _impl(target, profile, findings)
        except Exception:
            pass

        messages = [
            {
                "role": "system",
                "content": (
                    "Output a JSON array of short, executable attack-strategy steps for the "
                    "given target, profile, and findings. Only JSON, no prose."
                ),
            },
            {
                "role": "user",
                "content": (
                    f"target={target}\nprofile={profile}\nfindings={findings}"
                ),
            },
        ]
        resp = await self.chat(messages, temperature=0.2, max_tokens=600)
        import json as _json
        try:
            parsed = _json.loads(resp.text)
            if isinstance(parsed, list):
                return [str(s) for s in parsed]
        except _json.JSONDecodeError:
            pass
        # Fallback: split by newline into steps
        return [line.strip("- ").strip() for line in resp.text.splitlines() if line.strip()][:8]

    def _fallback_text(self, messages: List[Dict[str, str]]) -> str:
        """Deterministic offline fallback when no LLM is configured."""
        if not messages:
            return ""
        last_user = next(
            (m["content"] for m in reversed(messages) if m.get("role") == "user"),
            "",
        )
        return (
            "[offline] Plan derived from heuristics only. Goal: "
            + (last_user[:120] if last_user else "unspecified")
            + ". Steps: enumerate -> profile -> identify findings -> propose actions."
        )

    def health(self) -> Dict[str, Any]:
        return {
            "configured": self.available,
            "base_url": self.base_url,
            "model": self.model,
            "tokens_used_lifetime": self.total_tokens_used,
            "budget_limit": self.settings.max_spend_tokens if self.settings.raphael_cost_control else None,
        }


# Module-level instance lifecycle managed by main lifespan to avoid
# fragile singletons across reloads.
_llm: Optional[LLMService] = None


async def init_llm(settings: Optional[Settings] = None) -> LLMService:
    global _llm
    _llm = LLMService(settings)
    return _llm


def get_llm() -> LLMService:
    global _llm
    if _llm is None:
        _llm = LLMService()
    return _llm


async def close_llm() -> None:
    global _llm
    if _llm is not None:
        await _llm.close()
        _llm = None
