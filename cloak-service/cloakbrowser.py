import asyncio
import json
import logging
import os
import random
import time
from typing import Any, Optional
from pathlib import Path

import httpx

logger = logging.getLogger("cloakbrowser")

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
]

VIEWPORTS = [
    {"width": 1920, "height": 1080},
    {"width": 1366, "height": 768},
    {"width": 1536, "height": 864},
    {"width": 1440, "height": 900},
]

COOKIE_JAR: dict[str, list[dict]] = {}
SESSION_STORE: dict[str, bytes] = {}


def get_random_viewport() -> dict:
    return random.choice(VIEWPORTS)


def get_random_user_agent() -> str:
    return random.choice(USER_AGENTS)


async def launch_async(
    url: str,
    viewport: Optional[dict] = None,
    user_agent: Optional[str] = None,
    proxy: Optional[str] = None,
    wait: int = 3,
) -> dict:
    vp = viewport or get_random_viewport()
    ua = user_agent or get_random_user_agent()

    headers = {
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": "1",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
    }

    transport = httpx.AsyncHTTPTransport(retries=1)
    if proxy:
        transport = httpx.AsyncHTTPTransport(retries=1, proxy=proxy)

    async with httpx.AsyncClient(
        headers=headers,
        timeout=30,
        follow_redirects=True,
        transport=transport,
    ) as client:
        # First request: fetch the page
        resp = await client.get(url)
        status = resp.status_code
        content = resp.text[:100000]
        page_title = ""
        import re
        title_match = re.search(r"<title>(.*?)</title>", content, re.IGNORECASE)
        if title_match:
            page_title = title_match.group(1)

        # Follow any links in the page for cookie setting
        links = re.findall(r'href=[\'"]([^\'"]+)[\'"]', content)
        same_origin_links = [l for l in links if not l.startswith("#") and not l.startswith("http")]
        if same_origin_links and wait > 0:
            for link in same_origin_links[:3]:
                full_url = resp.url.join(link) if link.startswith("/") else f"{url.rstrip('/')}/{link}"
                try:
                    await client.get(full_url)
                except Exception:
                    pass

        # Store cookies for session reuse
        cookies = []
        for cookie in resp.cookies.jar:
            cookies.append({
                "name": cookie.name,
                "value": cookie.value,
                "domain": cookie.domain or "",
                "path": cookie.path or "/",
            })

        return {
            "url": str(resp.url),
            "status": status,
            "title": page_title,
            "cookies": cookies,
            "content_length": len(content),
            "headers": dict(resp.headers),
            "viewport": vp,
            "user_agent": ua,
        }


def get_screenshot(url: str, output_path: Optional[str] = None) -> Optional[bytes]:
    return None


def get_page_source(url: str) -> Optional[str]:
    return None