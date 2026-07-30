import time, logging
from collections import defaultdict

logger = logging.getLogger("circuit_breaker")

STATE_CLOSED = "closed"
STATE_OPEN = "open"
STATE_HALF_OPEN = "half_open"


class CircuitBreaker:
    def __init__(self, failure_threshold: int = 3, reset_timeout: float = 300.0):
        self._failure_threshold = failure_threshold
        self._reset_timeout = reset_timeout
        self._failures: dict[str, int] = defaultdict(int)
        self._state: dict[str, str] = defaultdict(lambda: STATE_CLOSED)
        self._last_failure: dict[str, float] = {}
        self._half_open_tested: set[str] = set()

    def record_failure(self, key: str):
        self._failures[key] += 1
        self._last_failure[key] = time.time()
        if self._failures[key] >= self._failure_threshold:
            self._state[key] = STATE_OPEN
            logger.warning(f"  [breaker] {key} → OPEN ({self._failures[key]} failures)")

    def record_success(self, key: str):
        if self._state.get(key) == STATE_HALF_OPEN:
            self._state[key] = STATE_CLOSED
            self._failures[key] = 0
            self._half_open_tested.discard(key)
            logger.info(f"  [breaker] {key} → CLOSED (half-open test passed)")
        elif self._state.get(key) == STATE_CLOSED:
            self._failures[key] = max(0, self._failures[key] - 1)

    def allow(self, key: str) -> bool:
        state = self._state.get(key, STATE_CLOSED)
        if state == STATE_CLOSED:
            return True
        if state == STATE_OPEN:
            elapsed = time.time() - self._last_failure.get(key, 0)
            if elapsed > self._reset_timeout:
                if key not in self._half_open_tested:
                    self._state[key] = STATE_HALF_OPEN
                    self._half_open_tested.add(key)
                    logger.info(f"  [breaker] {key} → HALF_OPEN (testing)")
                    return True
                return False
            return False
        if state == STATE_HALF_OPEN:
            return True
        return True

    def reset(self, key: str):
        self._failures[key] = 0
        self._state[key] = STATE_CLOSED
        self._half_open_tested.discard(key)

    def state(self, key: str) -> str:
        return self._state.get(key, STATE_CLOSED)

    def stats(self) -> dict:
        return {
            "open": [k for k, v in self._state.items() if v == STATE_OPEN],
            "half_open": [k for k, v in self._state.items() if v == STATE_HALF_OPEN],
            "failures": dict(self._failures),
        }


_breaker: CircuitBreaker = None


def get_breaker() -> CircuitBreaker:
    global _breaker
    if _breaker is None:
        _breaker = CircuitBreaker()
    return _breaker
