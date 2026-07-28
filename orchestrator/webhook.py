import json
import logging
from typing import Any

import httpx

logger = logging.getLogger("webhook")


async def deliver(url: str, payload: dict) -> dict:
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(url, json=payload)
            r.raise_for_status()
            return {"success": True, "status_code": r.status_code}
    except Exception as e:
        logger.warning(f"Webhook delivery failed: {e}")
        return {"success": False, "error": str(e)}
