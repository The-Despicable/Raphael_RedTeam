import asyncio, functools, logging, signal

logger = logging.getLogger("timeout_guard")


class TimeoutError(RuntimeError):
    pass


async def async_timeout(coro, timeout: float, label: str = "operation"):
    """Run a coroutine with a hard timeout. Raises TimeoutError if exceeded."""
    try:
        return await asyncio.wait_for(coro, timeout=timeout)
    except asyncio.TimeoutError:
        raise TimeoutError(f"{label} timed out after {timeout}s")


def sync_timeout(timeout: float):
    """Decorator for sync functions to run with a timeout via executor."""
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            loop = asyncio.get_running_loop()
            try:
                return await asyncio.wait_for(
                    loop.run_in_executor(None, lambda: func(*args, **kwargs)),
                    timeout=timeout,
                )
            except asyncio.TimeoutError:
                raise TimeoutError(f"{func.__name__} timed out after {timeout}s")
        return wrapper
    return decorator


class TimeoutGuard:
    def __init__(self, default_timeout: float = 120.0):
        self._default = default_timeout
        self._overrides: dict[str, float] = {}

    def set_timeout(self, operation: str, timeout: float):
        self._overrides[operation] = timeout

    def get_timeout(self, operation: str) -> float:
        return self._overrides.get(operation, self._default)

    async def run(self, operation: str, coro, timeout: float = None):
        t = timeout or self.get_timeout(operation)
        return await async_timeout(coro, t, label=operation)

    def stats(self) -> dict:
        return {
            "default_timeout": self._default,
            "overrides": dict(self._overrides),
        }


_guard: TimeoutGuard = None


def get_timeout_guard() -> TimeoutGuard:
    global _guard
    if _guard is None:
        _guard = TimeoutGuard()
    return _guard
