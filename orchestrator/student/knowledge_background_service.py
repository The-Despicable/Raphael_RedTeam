"""
KnowledgeBackgroundService — Async background knowledge ingestion service (S1-C).

Architecture:
    Timer → ResearchScheduler.run_research_cycle()
        → extract techniques → StudentKB.integrate()
        → sleep until next cycle

Can be triggered on-demand via request_immediate_cycle().
Runs as an isolated asyncio task — never blocks the primary cognitive loop.
Techniques survive restarts via StudentKB SQLite persistence.
"""

import asyncio
import logging
from typing import Optional

logger = logging.getLogger("student.knowledge_bg")


class KnowledgeBackgroundService:
    """
    Runs periodic research cycles in the background, persisting
    discovered techniques to StudentKB.

    Usage:
        service = KnowledgeBackgroundService(scheduler, kb, interval_minutes=60)
        await service.start()
        ...
        await service.stop()
    """

    def __init__(
        self,
        research_scheduler,
        student_kb,
        interval_minutes: int = 60,
    ):
        """
        Args:
            research_scheduler: ResearchScheduler instance
            student_kb: StudentKB instance
            interval_minutes: Minutes between full research cycles (default 60)
        """
        self._scheduler = research_scheduler
        self._kb = student_kb
        self._interval = interval_minutes * 60  # Convert to seconds
        self._task: Optional[asyncio.Task] = None
        self._trigger = asyncio.Event()
        self._running = False

        logger.info(
            "KnowledgeBackgroundService initialized (interval=%d min)",
            interval_minutes,
        )

    # ── Lifecycle ─────────────────────────────────────────────

    async def start(self):
        """Start the background research loop as an isolated asyncio task."""
        if self._running:
            logger.warning("KnowledgeBackgroundService already running")
            return

        self._running = True
        self._task = asyncio.create_task(self._run_loop())
        logger.info("KnowledgeBackgroundService started")

    async def stop(self):
        """Gracefully stop the background research loop."""
        if not self._running:
            return

        self._running = False
        self._trigger.set()  # Wake up the loop so it can exit

        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

        logger.info("KnowledgeBackgroundService stopped")

    @property
    def is_running(self) -> bool:
        return self._running

    # ── Immediate Cycle Trigger ──────────────────────────────

    def request_immediate_cycle(self):
        """
        Trigger an immediate research cycle outside the normal interval.

        Thread-safe: sets an asyncio.Event that the loop picks up.
        Can be called from synchronous code (CoverageGapFiller, etc.).
        """
        if not self._running:
            logger.warning("request_immediate_cycle called but service not running")
            return
        self._trigger.set()
        logger.debug("KnowledgeBackgroundService: immediate cycle requested")

    # ── Internal Loop ─────────────────────────────────────────

    async def _run_loop(self):
        """
        Main loop:
          1. Run full research cycle
          2. Extract unexported techniques
          3. Persist to StudentKB via integrate()
          4. Wait for interval or immediate trigger
        """
        logger.info("KnowledgeBackgroundService loop started")

        while self._running:
            cycle_start = asyncio.get_running_loop().time()

            try:
                await self._run_persist_cycle()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(
                    "KnowledgeBackgroundService cycle failed: %s", e, exc_info=True
                )

            # Calculate remaining sleep time
            elapsed = asyncio.get_running_loop().time() - cycle_start
            remaining = max(0.0, self._interval - elapsed)

            logger.debug(
                "KnowledgeBackgroundService cycle took %.1fs, sleeping %.1fs",
                elapsed,
                remaining,
            )

            # Wait for interval or immediate trigger
            try:
                await asyncio.wait_for(self._trigger.wait(), timeout=remaining)
                self._trigger.clear()
                logger.debug("KnowledgeBackgroundService: early wake (trigger)")
            except asyncio.TimeoutError:
                # Normal timeout — proceed to next cycle
                pass

        logger.info("KnowledgeBackgroundService loop ended")

    async def _run_persist_cycle(self):
        """
        Single cycle: research → extract → persist → mark exported.

        Can be called externally for synchronous testing.
        """
        # Phase 1: Run full research cycle
        session = await self._scheduler.run_research_cycle()
        logger.info(
            "Research cycle %s: %d CVEs, %d writeups, %d gaps",
            session.session_id,
            session.cves_found,
            session.writeups_found,
            len(session.gaps_identified),
        )

        # Phase 2: Process queued gap queries
        try:
            queued_ingested = await self._scheduler.run_queued_research(max_queries=10)
            if queued_ingested > 0:
                logger.info("Queued research ingested %d additional writeups", queued_ingested)
        except Exception as e:
            logger.warning("Queued research error: %s", e)

        # Phase 3: Extract unexported techniques for StudentKB
        techniques = self._scheduler.extract_techniques_for_kb(limit=50)
        if not techniques:
            logger.debug("No new techniques to persist — all writeups already exported")
            return

        logger.info(
            "Extracted %d techniques for KB integration", len(techniques)
        )

        # Phase 4: Persist to StudentKB
        result = self._kb.integrate(techniques)

        # Phase 5: Mark writeups as exported
        derived_ids = [
            t.get("derived_from", "")
            for t in techniques
            if t.get("derived_from")
        ]
        if derived_ids:
            updated = self._scheduler.mark_exported_to_kb(derived_ids)
            logger.info("Marked %d writeups as exported to KB", updated)

        # Log integration results
        if result.get("errors"):
            logger.warning(
                "KB integration had %d errors: %s",
                len(result["errors"]),
                result["errors"][:3],
            )
        logger.info(
            "Persist cycle complete: %d techniques, %d merged, %d errors",
            result.get("valid", 0),
            result.get("merged", 0),
            len(result.get("errors", [])),
        )

    # ── Context Manager Support ───────────────────────────────

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.stop()
