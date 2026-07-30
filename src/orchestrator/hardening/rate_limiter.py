import asyncio, logging, random, time
from collections import defaultdict

logger = logging.getLogger("rate_limiter")


class RateLimiter:
    def __init__(self, default_delay: float = 0.5, jitter: float = 0.3,
                 max_per_minute: int = 30, account_lockout_protection: bool = True):
        self._default_delay = default_delay
        self._jitter = jitter
        self._max_per_minute = max_per_minute
        self._account_lockout_protection = account_lockout_protection
        self._last_call: dict[str, float] = defaultdict(float)
        self._minute_count: dict[str, list[float]] = defaultdict(list)

    async def wait(self, key: str = "default"):
        now = time.time()
        # Per-minute rate cap
        window = self._minute_count[key]
        window[:] = [t for t in window if now - t < 60]
        if len(window) >= self._max_per_minute:
            sleep = window[0] + 60 - now
            if sleep > 0:
                logger.debug(f"  [throttle] {key}: rate limit hit, sleeping {sleep:.1f}s")
                await asyncio.sleep(sleep)
            window.clear()

        # Per-call delay with jitter
        last = self._last_call[key]
        if last:
            elapsed = now - last
            delay = self._default_delay + random.uniform(0, self._jitter)
            if elapsed < delay:
                await asyncio.sleep(delay - elapsed)

        self._last_call[key] = time.time()
        self._minute_count[key].append(time.time())

    def account_safe_delay(self, attempts: int = 1):
        """Return delay needed to avoid account lockout (3-5 bad attempts = lockout)."""
        if not self._account_lockout_protection:
            return 0
        if attempts >= 3:
            return 30.0 + random.uniform(0, 10)
        if attempts >= 2:
            return 10.0 + random.uniform(0, 5)
        return 0

    def set_delay(self, key: str, delay: float):
        self._last_call[key] = time.time() - self._default_delay + delay


_limiter: RateLimiter = None


def get_limiter() -> RateLimiter:
    global _limiter
    if _limiter is None:
        _limiter = RateLimiter()
    return _limiter
