import asyncio, logging, time
from collections import defaultdict

from orchestrator.events import EventBus, event_bus

logger = logging.getLogger("agent_supervisor")


class AgentSupervisor:
    def __init__(self, bus: EventBus = None, heartbeat_timeout: float = 15.0,
                 livelock_threshold: int = 5, max_progress_stall: float = 120.0):
        self.bus = bus or event_bus
        self.heartbeat_timeout = heartbeat_timeout
        self.livelock_threshold = livelock_threshold
        self.max_progress_stall = max_progress_stall

        self._heartbeats: dict[str, float] = {}
        self._consecutive_no_progress: dict[str, int] = defaultdict(int)
        self._last_finding_count: dict[str, int] = defaultdict(int)
        self._last_progress_time: dict[str, float] = defaultdict(float)
        self._running = False

    async def start(self):
        self._running = True
        asyncio.create_task(self._monitor_loop())
        logger.info("AgentSupervisor started")

    async def stop(self):
        self._running = False

    def record_heartbeat(self, agent: str, task_id: str, iteration: int, timestamp: float):
        key = f"{agent}:{task_id}"
        self._heartbeats[key] = timestamp

    def record_progress(self, agent: str, task_id: str, findings_count: int, timestamp: float):
        key = f"{agent}:{task_id}"
        prev = self._last_finding_count.get(key, 0)
        if findings_count > prev:
            self._consecutive_no_progress[key] = 0
            self._last_finding_count[key] = findings_count
            self._last_progress_time[key] = timestamp
        else:
            self._consecutive_no_progress[key] += 1

    def record_error(self, agent: str, task_id: str, action: dict, error: str):
        key = f"{agent}:{task_id}"
        logger.warning(f"[supervisor] Error in {key}: {error}")

    def is_dead(self, key: str, now: float) -> bool:
        last = self._heartbeats.get(key)
        if last is None:
            return False
        return (now - last) > self.heartbeat_timeout

    def is_livelocked(self, key: str) -> bool:
        return self._consecutive_no_progress.get(key, 0) >= self.livelock_threshold

    def is_stalled(self, key: str, now: float) -> bool:
        last_progress = self._last_progress_time.get(key)
        if last_progress is None:
            return False
        return (now - last_progress) > self.max_progress_stall

    async def _monitor_loop(self):
        while self._running:
            now = time.time()
            for key in list(self._heartbeats.keys()):
                if self.is_dead(key, now):
                    logger.warning(f"[supervisor] Agent {key} is DEAD — no heartbeat in {self.heartbeat_timeout}s")
                    await self.bus.publish("supervisor", "dead_agent", {"key": key, "timestamp": now})
                    del self._heartbeats[key]

                if self.is_livelocked(key):
                    logger.warning(f"[supervisor] Agent {key} is LIVELOCKED — {self.livelock_threshold}+ iterations without progress")
                    await self.bus.publish("supervisor", "livelocked_agent", {"key": key, "timestamp": now})

                if self.is_stalled(key, now):
                    logger.warning(f"[supervisor] Agent {key} is STALLED — no progress in {self.max_progress_stall}s")
                    await self.bus.publish("supervisor", "stalled_agent", {"key": key, "timestamp": now})

            await asyncio.sleep(5)
