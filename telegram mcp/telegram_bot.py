#!/usr/bin/env python3
"""
Telegram Bot — OpenCode Remote Controller
Control your WSL2 OpenCode environment from your phone.
"""

import os, subprocess, asyncio, json, shlex
import httpx
from pathlib import Path
from datetime import datetime

try:
    from telegram.request import HTTPXRequest
    from telegram import Update, BotCommand
    from telegram.ext import (
        Application, CommandHandler, MessageHandler,
        filters, ContextTypes
    )
    TELEGRAM_AVAILABLE = True
except ImportError:
    TELEGRAM_AVAILABLE = False

TOKEN         = os.getenv("TELEGRAM_TOKEN", "")
ALLOWED_ID    = int(os.getenv("TELEGRAM_CHAT_ID", "0"))
WORK_DIR      = os.getenv("WORK_DIR", os.path.expanduser("~"))
OPENCODE_CMD  = os.getenv("OPENCODE_CMD", "opencode")   # adjust if needed

# Active session tracking
sessions: dict = {}


# ─── Auth guard ────────────────────────────────────────────────────────────────

def authorized(update: Update) -> bool:
    uid = update.effective_chat.id
    if uid != ALLOWED_ID:
        print(f"[BLOCKED] Unauthorized access from chat_id={uid}")
        return False
    return True


# ─── Helpers ───────────────────────────────────────────────────────────────────

async def send_chunks(update: Update, text: str, code_block: bool = True):
    """Split long output into Telegram-safe chunks (4096 char limit)."""
    if not text.strip():
        text = "(empty output)"
    wrap = "```\n{}\n```" if code_block else "{}"
    chunk_size = 3800
    for i in range(0, len(text), chunk_size):
        chunk = text[i:i+chunk_size]
        await update.message.reply_text(
            wrap.format(chunk), parse_mode="Markdown"
        )


async def run_cmd_async(command: str, cwd: str = WORK_DIR, timeout: int = 120) -> tuple[str, int]:
    try:
        proc = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=cwd
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return stdout.decode(errors="replace").strip(), proc.returncode
    except asyncio.TimeoutError:
        return f"⏱ Timed out after {timeout}s", -1
    except Exception as e:
        return f"Error: {e}", -1


# ─── Command handlers ──────────────────────────────────────────────────────────

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not authorized(update): return
    help_text = (
        "🤖 *OpenCode Remote Controller*\n\n"
        "*OpenCode Commands:*\n"
        "/prompt `<task>` — Send task to OpenCode\n"
        "/resume — Resume last OpenCode session\n\n"
        "*Shell Commands:*\n"
        "/run `<command>` — Execute shell command\n"
        "/ls `[path]` — List directory\n"
        "/cat `<path>` — Read file\n"
        "/find `<pattern>` — Search files (grep)\n\n"
        "*Project Commands:*\n"
        "/git `[path]` — Git status + log\n"
        "/diff `[path]` — Git diff\n"
        "/cd `<path>` — Change working dir\n"
        "/pwd — Current working dir\n\n"
        "*System:*\n"
        "/status — CPU/RAM/disk\n"
        "/ps — Running processes\n"
        "/kill `<pid>` — Kill a process\n\n"
        "*Quick Shortcuts:*\n"
        "/install `<pkg>` — pip/npm install\n"
        "/test — Run project tests\n"
        "/build — Run build command\n"
    )
    await update.message.reply_text(help_text, parse_mode="Markdown")


async def prompt_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Send a task to OpenCode."""
    if not authorized(update): return
    task = " ".join(context.args)
    if not task:
        await update.message.reply_text("Usage: /prompt <your task description>")
        return

    await update.message.reply_text(f"⚙️ Sending to OpenCode:\n`{task}`", parse_mode="Markdown")

    # Try non-interactive mode flags (adjust to your OpenCode version)
    # OpenCode may support: opencode -p "task", opencode --message "task", or pipe
    cmds_to_try = [
        f'{OPENCODE_CMD} -p {shlex.quote(task)}',
        f'echo {shlex.quote(task)} | {OPENCODE_CMD}',
        f'{OPENCODE_CMD} --message {shlex.quote(task)}',
    ]

    output, code = "", -1
    for cmd in cmds_to_try:
        output, code = await run_cmd_async(cmd, timeout=180)
        if "unknown flag" not in output and "usage" not in output.lower():
            break

    icon = "✅" if code == 0 else "⚠️"
    await update.message.reply_text(f"{icon} OpenCode finished (exit {code}):")
    await send_chunks(update, output)


async def run_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Execute any shell command."""
    if not authorized(update): return
    command = " ".join(context.args)
    if not command:
        await update.message.reply_text("Usage: /run <shell command>")
        return

    await update.message.reply_text(f"▶️ `{command}`", parse_mode="Markdown")
    output, code = await run_cmd_async(command)
    icon = "✅" if code == 0 else "❌"
    await update.message.reply_text(f"{icon} Exit {code}:")
    await send_chunks(update, output)


async def ls_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not authorized(update): return
    path = " ".join(context.args) or WORK_DIR
    output, _ = await run_cmd_async(f"ls -lah {path}")
    await send_chunks(update, output)


async def cat_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not authorized(update): return
    path = " ".join(context.args)
    if not path:
        await update.message.reply_text("Usage: /cat <filepath>")
        return
    try:
        content = Path(os.path.expanduser(path)).read_text(errors="replace")
        await send_chunks(update, content[:6000])
    except Exception as e:
        await update.message.reply_text(f"❌ {e}")


async def find_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not authorized(update): return
    pattern = " ".join(context.args)
    if not pattern:
        await update.message.reply_text("Usage: /find <pattern>")
        return
    output, _ = await run_cmd_async(f"grep -rn '{pattern}' . 2>/dev/null | head -30")
    await send_chunks(update, output or "No matches.")


async def git_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not authorized(update): return
    path = " ".join(context.args) or WORK_DIR
    cmds = [
        f"cd {path} && git status --short",
        f"cd {path} && git log --oneline -10",
    ]
    output = ""
    for cmd in cmds:
        out, _ = await run_cmd_async(cmd)
        output += out + "\n\n"
    await send_chunks(update, output.strip())


async def diff_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not authorized(update): return
    path = " ".join(context.args) or WORK_DIR
    output, _ = await run_cmd_async(f"cd {path} && git diff")
    await send_chunks(update, output or "No changes.")


async def cd_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not authorized(update): return
    global WORK_DIR
    path = " ".join(context.args)
    full = os.path.expanduser(path)
    if os.path.isdir(full):
        WORK_DIR = full
        await update.message.reply_text(f"📁 Working dir set to:\n`{WORK_DIR}`", parse_mode="Markdown")
    else:
        await update.message.reply_text(f"❌ Directory not found: `{path}`", parse_mode="Markdown")


async def pwd_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not authorized(update): return
    await update.message.reply_text(f"📁 `{WORK_DIR}`", parse_mode="Markdown")


async def status_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not authorized(update): return
    cmds = {
        "⏱ Uptime": "uptime",
        "💾 Memory": "free -h",
        "💽 Disk": "df -h /",
    }
    out = f"*System Status* — {datetime.now().strftime('%H:%M:%S')}\n\n"
    for label, cmd in cmds.items():
        result, _ = await run_cmd_async(cmd)
        out += f"{label}\n```\n{result}\n```\n\n"
    await update.message.reply_text(out, parse_mode="Markdown")


async def ps_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not authorized(update): return
    output, _ = await run_cmd_async("ps aux --sort=-%cpu | head -15")
    await send_chunks(update, output)


async def kill_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not authorized(update): return
    pid = " ".join(context.args)
    if not pid.isdigit():
        await update.message.reply_text("Usage: /kill <pid>")
        return
    output, code = await run_cmd_async(f"kill {pid}")
    icon = "✅" if code == 0 else "❌"
    await update.message.reply_text(f"{icon} kill {pid}: exit {code}")


async def install_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not authorized(update): return
    pkg = " ".join(context.args)
    if not pkg:
        await update.message.reply_text("Usage: /install <package>")
        return

    await update.message.reply_text(f"📦 Installing `{pkg}`...", parse_mode="Markdown")

    # Auto-detect package manager from cwd
    cwd = WORK_DIR
    if Path(f"{cwd}/package.json").exists():
        cmd = f"cd {cwd} && npm install {pkg}"
    elif Path(f"{cwd}/requirements.txt").exists() or pkg.endswith(".txt"):
        cmd = f"pip install {pkg} --break-system-packages"
    else:
        cmd = f"pip install {pkg} --break-system-packages"

    output, code = await run_cmd_async(cmd, timeout=180)
    icon = "✅" if code == 0 else "❌"
    await update.message.reply_text(f"{icon} Done:")
    await send_chunks(update, output[-2000:])  # show tail


async def test_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not authorized(update): return
    await update.message.reply_text("🧪 Running tests...")

    # Auto-detect test runner
    cwd = WORK_DIR
    if Path(f"{cwd}/package.json").exists():
        cmd = f"cd {cwd} && npm test -- --passWithNoTests 2>&1 | tail -40"
    elif Path(f"{cwd}/pytest.ini").exists() or Path(f"{cwd}/setup.py").exists():
        cmd = f"cd {cwd} && python -m pytest -v 2>&1 | tail -40"
    else:
        cmd = f"cd {cwd} && python -m pytest 2>&1 | tail -40"

    output, code = await run_cmd_async(cmd, timeout=120)
    icon = "✅" if code == 0 else "❌"
    await update.message.reply_text(f"{icon} Tests exit {code}:")
    await send_chunks(update, output)


async def build_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not authorized(update): return
    await update.message.reply_text("🔨 Building...")

    cwd = WORK_DIR
    if Path(f"{cwd}/package.json").exists():
        cmd = f"cd {cwd} && npm run build 2>&1 | tail -50"
    elif Path(f"{cwd}/Makefile").exists():
        cmd = f"cd {cwd} && make 2>&1 | tail -50"
    else:
        cmd = f"cd {cwd} && python setup.py build 2>&1 | tail -50"

    output, code = await run_cmd_async(cmd, timeout=300)
    icon = "✅" if code == 0 else "❌"
    await update.message.reply_text(f"{icon} Build exit {code}:")
    await send_chunks(update, output)


# ─── Free-text fallback ────────────────────────────────────────────────────────

async def message_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Plain text messages → treated as OpenCode prompts."""
    if not authorized(update): return
    context.args = update.message.text.split()
    await prompt_cmd(update, context)


# ─── Main ──────────────────────────────────────────────────────────────────────

async def post_init(app: Application):
    """Register bot commands so they appear in the / menu."""
    await app.bot.set_my_commands([
        BotCommand("prompt",  "Send task to OpenCode"),
        BotCommand("run",     "Execute shell command"),
        BotCommand("ls",      "List directory"),
        BotCommand("cat",     "Read file"),
        BotCommand("git",     "Git status + log"),
        BotCommand("diff",    "Git diff"),
        BotCommand("cd",      "Change working directory"),
        BotCommand("pwd",     "Show current directory"),
        BotCommand("status",  "System CPU/RAM/disk"),
        BotCommand("install", "Install npm/pip package"),
        BotCommand("test",    "Run project tests"),
        BotCommand("build",   "Run build command"),
        BotCommand("find",    "Search files"),
        BotCommand("ps",      "List processes"),
        BotCommand("kill",    "Kill a process by PID"),
        BotCommand("start",   "Show help"),
    ])


def main():
    if not TOKEN:
        raise ValueError("TELEGRAM_TOKEN not set in environment")
    if not ALLOWED_ID:
        raise ValueError("TELEGRAM_CHAT_ID not set — get it from @userinfobot")

    transport = httpx.AsyncHTTPTransport(local_address="0.0.0.0")
    tg_request = HTTPXRequest(httpx_kwargs={"transport": transport})
    app = (
        Application.builder()
        .token(TOKEN)
        .request(tg_request)
        .get_updates_request(tg_request)
        .post_init(post_init)
        .build()
    )

    handlers = [
        ("start",   start),
        ("help",    start),
        ("prompt",  prompt_cmd),
        ("run",     run_cmd),
        ("ls",      ls_cmd),
        ("cat",     cat_cmd),
        ("find",    find_cmd),
        ("git",     git_cmd),
        ("diff",    diff_cmd),
        ("cd",      cd_cmd),
        ("pwd",     pwd_cmd),
        ("status",  status_cmd),
        ("ps",      ps_cmd),
        ("kill",    kill_cmd),
        ("install", install_cmd),
        ("test",    test_cmd),
        ("build",   build_cmd),
    ]
    for name, fn in handlers:
        app.add_handler(CommandHandler(name, fn))

    # Plain text → OpenCode prompt
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, message_handler))

    print(f"[+] Bot started. Working dir: {WORK_DIR}")
    app.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()
