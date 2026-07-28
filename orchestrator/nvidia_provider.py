#!/usr/bin/env python3
"""
NVIDIA GLM 5.2 Provider — Access GLM 5.2 through NVIDIA's free API.
===================================================================

GLM 5.2 is the same unrestricted open-weight model HuggingFace used to
analyze the 17,000-event autonomous AI attack log when American frontier
models refused due to safety guardrails.

This module provides a dedicated GLM 5.2 client with streaming and
OpenRouter fallback — nothing else.

Usage:
    from orchestrator.nvidia_provider import glm52_chat, glm52_stream, warm_glm52

    # Simple (waits for full response — ~60-160s first call, ~10-30s after)
    reply = await glm52_chat("Analyze this exploit payload...")

    # Streaming (tokens appear immediately — perceived speed ~1-3s)
    async for token in glm52_stream("Write a shellcode stub..."):
        print(token, end="", flush=True)

    # Pre-warm (call at boot to avoid cold start delay)
    warm_glm52()
"""

import asyncio
import json
import logging
import os
import time
from typing import AsyncGenerator, Optional

import httpx

logger = logging.getLogger("nvidia_provider")

# ─── Configuration ───────────────────────────────────────────────────────────

NVIDIA_API_KEY = os.getenv(
    "NVIDIA_API_KEY",
    "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",
)
NVIDIA_BASE = os.getenv("NVIDIA_API_BASE", "https://integrate.api.nvidia.com/v1")

OPENROUTER_KEY = os.getenv("OPENROUTER_API_KEY", "")
OPENROUTER_BASE = "https://openrouter.ai/api/v1"

GLM52_MODEL = "z-ai/glm-5.2"

# ─── Warm-Up ────────────────────────────────────────────────────────────────

_last_warm_time: float = 0


def warm_glm52(timeout: int = 180) -> bool:
    """
    Pre-warm GLM 5.2 on NVIDIA's GPU (blocking call).
    Call this once at application startup to avoid the 60-120s cold start delay
    on the first real query.

    Args:
        timeout: Max seconds to wait for warm-up. GLM 5.2 is 753B MoE — 
                 expect 60-120s on first load.
    """
    global _last_warm_time
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.post(
                f"{NVIDIA_BASE}/chat/completions",
                headers={
                    "Authorization": f"Bearer {NVIDIA_API_KEY}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": GLM52_MODEL,
                    "messages": [{"role": "user", "content": "warm up"}],
                    "max_tokens": 1,
                    "temperature": 0.1,
                },
            )
            if resp.status_code == 200:
                _last_warm_time = time.time()
                logger.info("[GLM5.2] Warm-up complete")
                return True
    except Exception as e:
        logger.warning(f"[GLM5.2] Warm-up failed: {e}")
    return False


# ─── Core Chat ──────────────────────────────────────────────────────────────

async def glm52_chat(
    prompt: str,
    system_prompt: Optional[str] = None,
    messages: Optional[list] = None,
    max_tokens: int = 4096,
    temperature: float = 0.7,
    timeout: int = 300,
) -> str:
    """
    Send a prompt to GLM 5.2 via NVIDIA API (free tier).

    Fallback: If NVIDIA rate-limits or fails, tries OpenRouter GLM 5.2.

    Args:
        prompt: User message
        system_prompt: Optional system instruction
        messages: Optional full message list (overrides prompt)
        max_tokens: Max output tokens
        temperature: Sampling temperature
        timeout: Request timeout (default 300s — 753B model is slow on free tier)

    Returns:
        Model response text

    Raises:
        RuntimeError: If both NVIDIA and OpenRouter fail
    """
    msgs = messages or []
    if not msgs:
        if system_prompt:
            msgs.append({"role": "system", "content": system_prompt})
        msgs.append({"role": "user", "content": prompt})

    # ── Try NVIDIA first ──
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(
                f"{NVIDIA_BASE}/chat/completions",
                headers={
                    "Authorization": f"Bearer {NVIDIA_API_KEY}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": GLM52_MODEL,
                    "messages": msgs,
                    "max_tokens": max_tokens,
                    "temperature": temperature,
                    "stream": False,
                },
            )
            if resp.status_code == 200:
                data = resp.json()
                content = data["choices"][0]["message"]["content"]
                usage = data.get("usage", {})
                logger.info(
                    f"[GLM5.2] NVIDIA ✅ "
                    f"({len(content)} chars, {usage.get('total_tokens', '?')} tokens)"
                )
                return content
            elif resp.status_code == 429:
                logger.warning("[GLM5.2] NVIDIA rate limited")
            else:
                logger.warning(f"[GLM5.2] NVIDIA {resp.status_code}: {resp.text[:200]}")
    except httpx.TimeoutException:
        logger.warning("[GLM5.2] NVIDIA timeout")
    except Exception as e:
        logger.warning(f"[GLM5.2] NVIDIA error: {e}")

    # ── Fallback to OpenRouter ──
    if OPENROUTER_KEY:
        logger.info("[GLM5.2] Falling back to OpenRouter")
        try:
            async with httpx.AsyncClient(timeout=120) as client:
                resp = await client.post(
                    f"{OPENROUTER_BASE}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {OPENROUTER_KEY}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": "z-ai/glm-5.2",
                        "messages": msgs,
                        "max_tokens": max_tokens,
                        "temperature": temperature,
                    },
                )
                if resp.status_code == 200:
                    data = resp.json()
                    return data["choices"][0]["message"]["content"]
                logger.warning(f"[GLM5.2] OpenRouter {resp.status_code}: {resp.text[:200]}")
        except Exception as e:
            logger.warning(f"[GLM5.2] OpenRouter error: {e}")

    raise RuntimeError("GLM 5.2 unavailable — NVIDIA free tier rate-limited and no OpenRouter fallback")


# ─── Streaming ──────────────────────────────────────────────────────────────

async def glm52_stream(
    prompt: str,
    system_prompt: Optional[str] = None,
    messages: Optional[list] = None,
    max_tokens: int = 4096,
    temperature: float = 0.7,
) -> AsyncGenerator[str, None]:
    """
    Stream GLM 5.2 response token-by-token for instant perceived speed.

    Usage:
        async for token in glm52_stream("Analyze this exploit..."):
            print(token, end="", flush=True)
    """
    msgs = messages or []
    if not msgs:
        if system_prompt:
            msgs.append({"role": "system", "content": system_prompt})
        msgs.append({"role": "user", "content": prompt})

    try:
        async with httpx.AsyncClient(timeout=300) as client:
            async with client.stream(
                "POST",
                f"{NVIDIA_BASE}/chat/completions",
                headers={
                    "Authorization": f"Bearer {NVIDIA_API_KEY}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": GLM52_MODEL,
                    "messages": msgs,
                    "max_tokens": max_tokens,
                    "temperature": temperature,
                    "stream": True,
                },
            ) as resp:
                async for line in resp.aiter_lines():
                    if line.startswith("data: "):
                        data_str = line[6:].strip()
                        if data_str == "[DONE]":
                            break
                        try:
                            data = json.loads(data_str)
                            delta = data["choices"][0].get("delta", {})
                            content = delta.get("content", "")
                            if content:
                                yield content
                        except (json.JSONDecodeError, KeyError, IndexError):
                            continue
    except Exception as e:
        logger.warning(f"[GLM5.2] Stream error, falling back to non-streaming: {e}")
        result = await glm52_chat(
            prompt=prompt, system_prompt=system_prompt,
            messages=messages, max_tokens=max_tokens, temperature=temperature,
        )
        yield result


# ─── Simple Test ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    async def test():
        print("=" * 60)
        print("GLM 5.2 Test (NVIDIA Free Tier)")
        print("=" * 60)
        print("\n⚠️  First call may take 60-120s (cold start)")
        print("   Subsequent calls are faster (~10-30s)")

        # Test non-streaming
        print("\n[1] glm52_chat (may be slow)...")
        start = time.time()
        try:
            reply = await glm52_chat(
                "Say exactly: GLM 5.2 is working via NVIDIA API",
                timeout=300,
            )
            elapsed = time.time() - start
            print(f"  Reply: {reply}")
            print(f"  Time:  {elapsed:.1f}s")
        except Exception as e:
            print(f"  ❌ Failed: {e}")

        print("\n" + "=" * 60)
        print("Test complete")
        print("=" * 60)

    asyncio.run(test())