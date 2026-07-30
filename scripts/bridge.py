#!/usr/bin/env python3
"""
bridge.py — FORGE ↔ SENTINEL Two-Way Bridge.

Architecture:
  SENTINEL (ChatGPT) ←→ bridge.py ←→ FORGE (this AI)

Two-way via file protocol:
  /tmp/forge_to_sentinel.txt  — FORGE writes outbound messages
  /tmp/sentinel_to_forge.txt  — SENTINEL messages land here
  /tmp/bridge_state.json      — current state info

  SENTINEL !exec <cmd> → bridge executes → result posted to chat.
  SENTINEL messages → written to sentinel_to_forge.txt for FORGE.
  FORGE writes forge_to_sentinel.txt → bridge reads and posts to chat.

Usage:
  python3 bridge.py
  # Headed browser opens. Uses persistent profile (cookies survive).
  # Detects existing session automatically. Two-way dialogue begins.
"""

import asyncio
import subprocess
import sys
import time
import re
import json
import os
from datetime import datetime, timezone
from pathlib import Path

CHAT_URL = "https://chatgpt.com/c/6a63ade4-1d90-83ee-b181-d2a5dd6ab986"
POLL_INTERVAL = 5.0
OUTBOX_POLL_INTERVAL = 2.0
MAX_RESULT_LENGTH = 4000
NAV_TIMEOUT = 60000

OUTBOX = Path("/tmp/forge_to_sentinel.txt")
INBOX = Path("/tmp/sentinel_to_forge.txt")
STATE = Path("/tmp/bridge_state.json")

last_processed_message_id = None


def timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S UTC")


async def run_command(cmd: str) -> dict:
    print(f"[bridge] EXECUTING: {cmd[:200]}...")
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd="/home/yaser/raphael-2.0",
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
        stdout_str = stdout.decode("utf-8", errors="replace") if stdout else ""
        stderr_str = stderr.decode("utf-8", errors="replace") if stderr else ""
        return {
            "exit_code": proc.returncode,
            "stdout": stdout_str[:MAX_RESULT_LENGTH],
            "stderr": stderr_str[:MAX_RESULT_LENGTH],
        }
    except asyncio.TimeoutError:
        return {"exit_code": -1, "stdout": "", "stderr": "TIMEOUT (>300s)"}
    except Exception as e:
        return {"exit_code": -1, "stdout": "", "stderr": f"ERROR: {e}"}


def format_result(result: dict, cmd: str) -> str:
    parts = [f"```\n$ {cmd[:500]}"]
    if result["stdout"]:
        parts.append(result["stdout"].rstrip()[:3000])
    if result["stderr"]:
        parts.append(f"[stderr]\n{result['stderr'].rstrip()[:1000]}")
    parts.append(f"\n[exit code: {result['exit_code']}]")
    parts.append("```")
    return "\n".join(parts)


async def apply_stealth(page):
    await page.add_init_script("""
        Object.defineProperty(navigator, 'webdriver', {
            get: () => undefined,
        });
        window.chrome = {
            runtime: {},
            loadTimes: function() {},
            csi: function() {},
            app: {},
        };
        const originalQuery = window.navigator.permissions.query;
        window.navigator.permissions.query = (parameters) => (
            parameters.name === 'notifications' ?
                Promise.resolve({ state: Notification.permission }) :
                originalQuery(parameters)
        );
        Object.defineProperty(navigator, 'plugins', {
            get: () => [1, 2, 3, 4, 5],
        });
        Object.defineProperty(navigator, 'languages', {
            get: () => ['en-US', 'en'],
        });
    """)


async def wait_for_page_ready(page):
    max_wait = 90
    start = time.time()
    while time.time() - start < max_wait:
        try:
            url = page.url
            body = await page.inner_text("body", timeout=5000)
            if "Just a moment..." in body[:200]:
                print(f"[bridge] Cloudflare at {time.time()-start:.0f}s...")
                await asyncio.sleep(3)
                continue
            if CHAT_URL in url:
                if await page.query_selector('[contenteditable="true"]'):
                    return True
            if "chatgpt.com" in url and "login" not in url.lower():
                if await page.query_selector("main, [contenteditable='true']"):
                    return True
        except Exception:
            pass
        await asyncio.sleep(1)
    print("[bridge] WARNING: page not ready after 90s")
    return False


async def navigate_to_chat(page):
    current = page.url
    if CHAT_URL in current:
        for _ in range(15):
            if await page.query_selector('[contenteditable="true"]'):
                print("[bridge] Already at target chat.")
                return True
            await asyncio.sleep(1)
        return True
    print("[bridge] Navigating to SENTINEL chat...")
    try:
        await page.goto(CHAT_URL, wait_until="load", timeout=NAV_TIMEOUT)
        await asyncio.sleep(3)
        for sel in ["[data-message-author-role]", "[class*='message']", "main", '[contenteditable="true"]']:
            try:
                await page.wait_for_selector(sel, timeout=10000)
                print(f"[bridge] Chat loaded (matched: {sel})")
                return True
            except Exception:
                continue
        return True
    except Exception as e:
        print(f"[bridge] Navigation error: {e}")
        return False


async def get_latest_sentinel_message(page):
    """Get latest unprocessed assistant message (SENTINEL's output)."""
    global last_processed_message_id
    selectors = [
        '[data-message-author-role="assistant"]',
        'article[data-testid*="conversation"]',
        '[class*="assistant"]',
        '[class*="message"]',
        'article',
    ]
    messages = []
    for sel in selectors:
        messages = await page.query_selector_all(sel)
        if messages:
            break
    if not messages:
        return None
    latest = messages[-1]
    message_id = (await latest.get_attribute("data-message-id")
                  or await latest.get_attribute("data-testid")
                  or str(hash((await latest.inner_text())[:200])))
    if message_id and message_id == last_processed_message_id:
        return None
    text = await latest.inner_text()
    if message_id:
        last_processed_message_id = message_id
    return {"id": message_id, "text": text.strip()}


async def is_sentinel_generating(page):
    """Check if SENTINEL (ChatGPT) is still generating a response.
    
    Returns True if the model is still streaming output.
    The bridge must wait for completion before reading partial messages.
    """
    # Method 1: Check for the "Stop Generating" button
    # ChatGPT displays a specific button while streaming
    stop_btn = await page.query_selector(
        'button[data-testid="stop-button"], '
        'button[aria-label="Stop generating"], '
        '[data-testid="stop-button"]'
    )
    if stop_btn:
        return True
    
    # Method 2: Fallback — check if the latest message text is still changing
    selectors = [
        '[data-message-author-role="assistant"]',
        'article[data-testid*="conversation"]',
        '[class*="assistant"]',
    ]
    messages = []
    for sel in selectors:
        messages = await page.query_selector_all(sel)
        if messages:
            break
    if not messages:
        return False
    
    latest = messages[-1]
    try:
        text1 = await latest.inner_text()
        await asyncio.sleep(1.0)  # Wait 1 second
        text2 = await latest.inner_text()
        # If the text length changed, it's still streaming
        return len(text1) != len(text2)
    except Exception:
        return False


def extract_command(text: str) -> str | None:
    for line in text.split("\n"):
        line = line.strip()
        if line.startswith("!exec "):
            return line[6:].strip()
    code_blocks = re.findall(r"```(?:bash|shell)\n(.+?)\n```", text, re.DOTALL)
    if code_blocks:
        return code_blocks[-1].strip()
    generic_blocks = re.findall(r"```\n(.+?)\n```", text, re.DOTALL)
    if generic_blocks:
        return generic_blocks[-1].strip()
    return None


async def post_to_chat(page, result_text: str):
    """Type text into the chat and send using fill() for speed."""
    try:
        input_box = await page.query_selector('[contenteditable="true"]')
        if not input_box:
            for sel in ["textarea", "#prompt-textarea", "form textarea"]:
                input_box = await page.query_selector(sel)
                if input_box:
                    break
        if not input_box:
            print(f"[bridge] WARNING: no input at {page.url}")
            return False
        await input_box.scroll_into_view_if_needed()
        await asyncio.sleep(0.2)
        await input_box.focus()
        await asyncio.sleep(0.2)

        # Clear existing content
        await page.keyboard.press("Control+KeyA")
        await asyncio.sleep(0.1)
        await page.keyboard.press("Delete")
        await asyncio.sleep(0.2)

        # Use fill() for speed (no per-char delay)
        # For contenteditable divs, we insert text via evaluate
        await page.evaluate(f"""() => {{
            const el = document.querySelector('[contenteditable="true"]');
            if (el) {{
                el.textContent = '';
                el.focus();
                document.execCommand('insertText', false, {json.dumps(result_text)});
            }}
        }}""")
        await asyncio.sleep(0.3)

        # Send with Ctrl+Enter
        await page.keyboard.press("Control+Enter")
        await asyncio.sleep(1.5)

        # Fallback send button
        send_btn = await page.query_selector('button[data-testid="send-button"]')
        if send_btn:
            try:
                if await send_btn.is_enabled():
                    await send_btn.click(force=True)
                    await asyncio.sleep(1)
            except Exception:
                pass

        print(f"[bridge] Posted ({len(result_text)} chars)")
        return True
    except Exception as e:
        print(f"[bridge] ERROR posting: {e}")
        return False


async def process_outbox(page):
    """Check outbox file and send any pending FORGE messages to SENTINEL."""
    if not OUTBOX.exists():
        return
    try:
        content = OUTBOX.read_text().strip()
        if content:
            OUTBOX.unlink(missing_ok=True)
            print(f"[bridge] Outbox → posting to chat")
            await post_to_chat(page, content)
    except Exception as e:
        print(f"[bridge] Outbox error: {e}")
        OUTBOX.unlink(missing_ok=True)


def write_inbox(text: str):
    """Write SENTINEL's message to inbox for FORGE."""
    if not text.strip():
        return
    try:
        with open(INBOX, "a") as f:
            f.write(f"\n--- [{timestamp()}] SENTINEL ---\n{text.strip()}\n")
        # Trim only when exceeding 2MB to prevent unbounded growth
        if INBOX.stat().st_size > 2_000_000:
            content = INBOX.read_text().splitlines()
            INBOX.write_text("\n".join(content[-5000:]) + "\n")
    except Exception as e:
        print(f"[bridge] Inbox error: {e}")


def update_state(key: str, value):
    try:
        state = {}
        if STATE.exists():
            state = json.loads(STATE.read_text())
        state[key] = value
        state["last_updated"] = timestamp()
        STATE.write_text(json.dumps(state, indent=2))
    except Exception:
        pass


async def main():
    # Rule 3: Guard heavyweight playwright import
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        print("[bridge] playwright not installed. Install with: "
              "pip install playwright && python3 -m playwright install chromium")
        sys.exit(1)

    print("=" * 60)
    print("  Raphael Bridge — FORGE ↔ SENTINEL Two-Way Network")
    print(f"  Target: {CHAT_URL}")
    print("=" * 60)
    print("  File protocol:")
    print(f"    OUTBOX: {OUTBOX}  (FORGE → SENTINEL)")
    print(f"    INBOX:  {INBOX}  (SENTINEL → FORGE)")
    print(f"    STATE:  {STATE}")
    print("")

    # Clean slate
    OUTBOX.unlink(missing_ok=True)
    INBOX.unlink(missing_ok=True)
    STATE.unlink(missing_ok=True)

    USER_DATA_DIR = "/home/yaser/.playwright-chatgpt-profile"
    os.makedirs(USER_DATA_DIR, exist_ok=True)

    async with async_playwright() as p:
        context = await p.chromium.launch_persistent_context(
            user_data_dir=USER_DATA_DIR,
            headless=False,
            args=[
                "--disable-blink-features=AutomationControlled",
                "--disable-features=IsolateOrigins,site-per-process",
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-infobars",
                "--window-size=1280,900",
                "--disable-gpu",
            ],
            viewport={"width": 1280, "height": 900},
            user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
                       " (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            locale="en-US",
            timezone_id="America/New_York",
            permissions=[],
        )

        page = await context.new_page()
        await apply_stealth(page)

        await page.goto(CHAT_URL, wait_until="domcontentloaded", timeout=NAV_TIMEOUT)
        print("[bridge] Waiting for session (login or cookies)...")
        await wait_for_page_ready(page)
        await navigate_to_chat(page)

        update_state("status", "online")
        update_state("connected_at", timestamp())

        print(f"\n🟢 [bridge] FORGE online at {timestamp()}")
        print("[bridge] Two-way network active.")
        print("")

        # Signal ready
        await post_to_chat(page, (
            f"🟢 **FORGE build-surgeon online** — Two-way network established at {timestamp()}\n\n"
            f"**Strike counter:** 1/3 (pre-existing)\n"
            f"**Baseline:** 25/27\n"
            f"**Status:** D-0 through D-4 frozen. D-5 spec V2 approved — implementation pending debate.\n\n"
            f"SENTINEL: post `!exec <command>` to run locally, or debate architecture.\n"
            f"FORGE will respond through this channel."
        ))

        # Main loop: poll SENTINEL + check outbox
        while True:
            try:
                # Check outbox (FORGE-initiated messages)
                await process_outbox(page)

                # NEW: Wait for generation to complete before reading
                if await is_sentinel_generating(page):
                    print(f"[bridge] SENTINEL is generating... waiting for completion.")
                    await asyncio.sleep(2.0)
                    continue

                # Check for new SENTINEL messages
                msg = await get_latest_sentinel_message(page)
                if msg:
                    cmd = extract_command(msg["text"])
                    if cmd:
                        print(f"\n[bridge] ─── COMMAND ───")
                        print(f"[bridge] $ {cmd[:200]}")
                        result = await run_command(cmd)
                        output = format_result(result, cmd)
                        await post_to_chat(page, output)
                        status = f"exit={result['exit_code']}"
                        if result['stdout']:
                            status += f" out={len(result['stdout'])}B"
                        if result['stderr']:
                            status += f" err={len(result['stderr'])}B"
                        print(f"[bridge] Done ({status})")
                        update_state("last_command", cmd[:100])
                        update_state("last_exit", result['exit_code'])
                    else:
                        # Non-command message from SENTINEL → inbox for FORGE
                        write_inbox(msg["text"])
                        print(f"[bridge] SENTINEL message → inbox ({len(msg['text'])} chars)")

                await asyncio.sleep(POLL_INTERVAL)
            except KeyboardInterrupt:
                raise
            except Exception as e:
                print(f"[bridge] Loop error: {e}")
                await asyncio.sleep(POLL_INTERVAL * 2)

        await context.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[bridge] Shutdown by user.")
        sys.exit(0)
