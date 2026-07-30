import asyncio, logging, os, time
from collections import defaultdict

logger = logging.getLogger("stealth")

DEFAULT_BUDGET = int(os.getenv("RAPHAEL_NOISE_BUDGET", "100"))
DEFAULT_WINDOW = int(os.getenv("RAPHAEL_NOISE_WINDOW", "300"))
DEFAULT_TOOL_DELAY = float(os.getenv("RAPHAEL_TOOL_DELAY", "1.0"))

TOOL_NOISE_WEIGHTS = {
    "dns_enum": 1,
    "whois": 1,
    "web_fingerprint": 2,
    "subdomain_scan": 5,
    "port_scan": 10,
    "directory_scan": 5,
    "service_scan": 8,
    "vuln_scan": 15,
    "ssl_scan": 3,
    "sqlmap": 20,
    "hydra": 25,
    "searchsploit": 2,
    "custom_payload": 5,
    "netexec": 10,
    "winrm": 10,
    "bloodhound": 15,
    "ladon": 5,
    "pupy": 10,
}


class StealthController:
    """Noise budget and timing controls for agent actions.

    Each tool call consumes noise from a per-target budget.
    When the budget is exhausted, the agent must wait for the window to reset.
    """

    def __init__(self, budget: int = DEFAULT_BUDGET, window: int = DEFAULT_WINDOW,
                 tool_delay: float = DEFAULT_TOOL_DELAY):
        self.budget = budget
        self.window = window
        self.tool_delay = tool_delay
        self._usage: dict[str, list[float]] = defaultdict(list)
        self._paused: set[str] = set()

    def tool_weight(self, tool_name: str) -> int:
        return TOOL_NOISE_WEIGHTS.get(tool_name, 5)

    def consume(self, target: str, tool_name: str) -> tuple[bool, int, int]:
        now = time.time()
        cutoff = now - self.window
        bucket = self._usage[target]
        bucket[:] = [t for t in bucket if t > cutoff]
        used = len(bucket)
        remaining = max(0, self.budget - used)

        if remaining <= 0:
            logger.warning(f"[stealth] Budget exhausted for {target} — wait {self.window}s")
            return False, used, remaining

        weight = self.tool_weight(tool_name)
        for _ in range(weight):
            self._usage[target].append(time.time())

        new_used = len(self._usage[target])
        new_remaining = max(0, self.budget - new_used)
        return True, new_used, new_remaining

    async def wait_if_needed(self, target: str):
        now = time.time()
        cutoff = now - self.window
        bucket = self._usage[target]
        bucket[:] = [t for t in bucket if t > cutoff]
        used = len(bucket)

        if used >= self.budget:
            sleep = self.window - (now - (bucket[0] if bucket else now))
            if sleep > 0:
                logger.info(f"[stealth] Throttling {target} — sleeping {sleep:.0f}s")
                await asyncio.sleep(sleep)

        await asyncio.sleep(self.tool_delay)

    def stats(self, target: str) -> dict:
        now = time.time()
        cutoff = now - self.window
        bucket = [t for t in self._usage.get(target, []) if t > cutoff]
        return {
            "target": target,
            "used": len(bucket),
            "budget": self.budget,
            "remaining": max(0, self.budget - len(bucket)),
            "window_seconds": self.window,
            "reset_at": (bucket[0] + self.window) if bucket else now,
        }
