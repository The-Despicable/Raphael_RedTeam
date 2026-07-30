#!/usr/bin/env python3
"""
RAPHAEL — Integration Loop Main Entry Point.

Wave 1: Core loop with circulatory system, planner, executor, 
thermoregulator, and inline memory prior.
"""
from __future__ import annotations
import asyncio
import logging
import sys
import time
import json
import os
from datetime import datetime
from pathlib import Path

# Ensure raphael package is importable
sys.path.insert(0, str(Path(__file__).parent.parent))

from raphael.config import RaphaelConfig
from raphael.circulatory.blackboard import Blackboard
from raphael.circulatory.event_bus import EventBus
from raphael.circulatory.spinal_reflex import SpinalReflex
from raphael.models.engagement_state import EngagementState
from raphael.models.target_model import TargetModel
from raphael.models.capability_model import CapabilityModel
from raphael.cortex.planner import Planner, Action
from raphael.executor.executor import Executor
from raphael.techniques import TECHNIQUE_REGISTRY
from raphael.hippocampus.episode_store import get_hippocampus, Hippocampus
from raphael.limbic.parallel_recon import ParallelRecon

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("raphael.main")


class Thermoregulator:
    """
    Spinal reflex circuit breaker. Runs at configurable cadence (1 Hz Wave 1).
    Directly inhibits executor if risk exceeds threshold.
    """

    def __init__(self, config: RaphaelConfig, executor: Executor,
                 blackboard: Blackboard, event_bus: EventBus,
                 spinal_reflex: SpinalReflex):
        self._config = config
        self._executor = executor
        self._blackboard = blackboard
        self._event_bus = event_bus
        self._spinal_reflex = spinal_reflex
        self._current_risk = 0.0
        self._running = False

    @property
    def current_risk(self) -> float:
        return self._current_risk

    async def start(self):
        """Start the thermoregulator tick loop."""
        self._running = True
        interval = 1.0 / self._config.thermoregulator_hz
        logger.info(f"Thermoregulator started ({self._config.thermoregulator_hz} Hz)")
        while self._running:
            await self._tick()
            await asyncio.sleep(interval)

    async def stop(self):
        self._running = False

    async def _tick(self):
        """
        Estimate current detection risk based on recent execution volume.
        Simplified for Wave 1 — counts recent technique attempts as risk proxy.
        """
        # Wave 1: simple heuristic — more techniques = higher risk
        # In future waves, this queries the risk_scores table and considers
        # target detection stack, time of day, burn rate, etc.
        if self._executor.paused:
            # If paused, risk should decay
            self._current_risk = max(0.0, self._current_risk - 0.05)
        else:
            # Slight natural decay if not spamming
            self._current_risk = max(0.0, self._current_risk - 0.01)

        await self._blackboard.write_risk_score(
            "raphael_active", self._current_risk, "thermoregulator"
        )

        # Spinal reflex check
        if self._current_risk > self._config.risk_threshold_pause and not self._executor.paused:
            self._spinal_reflex.inhibit(f"risk threshold exceeded: {self._current_risk:.2f}")
            await self._event_bus.publish("detection_risk_spike", {
                "risk": self._current_risk,
                "threshold": self._config.risk_threshold_pause,
            })

        elif self._current_risk < self._config.risk_threshold_resume and self._executor.paused:
            self._spinal_reflex.release()
            await self._event_bus.publish("operations_resumed", {
                "risk": self._current_risk,
            })


class RaphaelOrganism:
    """
    The whole organism. Wires together all organs and runs the engagement loop.
    """

    def __init__(self, config: RaphaelConfig):
        self.config = config
        self.blackboard = Blackboard(config.db_path)
        self.event_bus = EventBus()
        self.planner = Planner()
        self.executor = Executor(self.event_bus, self.blackboard)
        self.spinal_reflex = SpinalReflex(self.executor)
        self.hippocampus = get_hippocampus()
        self.parallel_recon = ParallelRecon(self.executor)
        self.thermoregulator = Thermoregulator(
            config, self.executor, self.blackboard,
            self.event_bus, self.spinal_reflex
        )
        self.state: EngagementState | None = None
        self._running = False

    async def initialize(self):
        """Connect blackboard and create engagement state."""
        self.blackboard.connect()
        logger.info("Blackboard connected")

        # Create or load engagement state
        eid = self.config.engagement_id
        target_addr = self.config.target_host or self.config.target
        existing = await self.blackboard.get_engagement_state(eid)
        if existing:
            self.state = EngagementState.from_dict({
                "engagement_id": eid,
                "target": json.loads(existing.get("profile_json", "{}")),
                "capabilities": {},
                "current_cycle": existing.get("current_cycle", 0),
                "target_address": existing.get("target", ""),
                "status": existing.get("status", "running"),
            })
            logger.info(f"Resumed engagement {eid} at cycle {self.state.current_cycle}")
        else:
            self.state = EngagementState.fresh(eid, target_addr)
            await self.blackboard.save_engagement_state(
                eid, target_addr, 0
            )
            logger.info(f"New engagement {eid} against {target_addr}")

        # If no target configured, state survives but does nothing
        if not self.config.target and not self.state.target_address:
            logger.warning("No target configured. Set RAPHAEL_TARGET or pass --target")

    async def run(self):
        """Main engagement loop."""
        if not self.state or not self.state.target_address:
            logger.error("No target — nothing to do. Set RAPHAEL_TARGET=...")
            return

        logger.info(f"╔══ RAPHAEL ENGAGEMENT START ══╗")
        logger.info(f"║ Target:     {self.state.target_address}")
        logger.info(f"║ Engagement: {self.state.engagement_id}")
        logger.info(f"║ Max cycles: {self.config.max_cycles}")
        logger.info(f"╚═══════════════════════════════╝")

        self._running = True

        # Start thermoregulator in background
        thermo_task = asyncio.create_task(self.thermoregulator.start())

        # ParallelRecon batch — fire all available recon techniques concurrently
        try:
            batch_delta = await self.parallel_recon.run_batch(self.state)
            if not batch_delta.is_empty():
                logger.info(f"ParallelRecon: +{len(batch_delta.new_affordances)} affordances, "
                            f"{len(batch_delta.new_constraints)} constraints (batch 0)")
        except Exception as e:
            logger.debug(f"ParallelRecon batch failed: {e}")

        try:
            while self._running and self.state.current_cycle < self.config.max_cycles:
                cycle = self.state.current_cycle
                logger.info(f"\n{'='*60}")
                logger.info(f"CYCLE {cycle + 1}/{self.config.max_cycles}")
                logger.info(f"{'='*60}")

                # Check if paused by thermoregulator
                if self.executor.paused:
                    logger.info(f"Executor paused ({self.executor.pause_reason}), waiting...")
                    await asyncio.sleep(5)
                    continue

                # Get current affordances/constraints
                domain_state = self.state.target.domains.get("network", None)
                if domain_state is None:
                    domain_state = self.state.target.domains.setdefault(
                        "network", __import__("raphael.models.target_model", fromlist=["DomainState"]).DomainState()
                    )
                affs = domain_state.affordances
                cons = domain_state.constraints

                logger.info(f"  Affordances ({len(affs)}): {sorted(affs)[:8]}...")
                logger.info(f"  Constraints ({len(cons)}): {sorted(cons)[:8]}...")

                # Plan next action
                action = await self.planner.select_next_step(self.state, affs, cons)
                logger.info(f"  Action: {action}")

                # Execute
                if action.action_type == "execute" and action.technique:
                    delta, produced = await self.executor.execute(self.state, action.technique)
                    self.planner.mark_executed(action.technique, produced_new_info=produced, new_affordances=delta.new_affordances)
                    if produced:
                        logger.info(f"  Delta: +{len(delta.new_affordances)} affordances, "
                                     f"+{len(delta.new_constraints)} constraints, "
                                     f"resolved {len(delta.resolved_unknowns)} unknowns")
                        logger.info(f"  New affordances: {sorted(delta.new_affordances)}")
                        logger.info(f"  New constraints: {sorted(delta.new_constraints)}")
                    else:
                        logger.info(f"  Delta: empty (no new info)")

                    # Check if acquired new info
                    if not produced:
                        logger.info("  No new info — incrementing stuck counter")
                    else:
                        # Log to blackboard
                        await self.blackboard.write_target_model(
                            self.state.engagement_id, "network",
                            list(domain_state.constraints),
                            list(domain_state.affordances),
                            list(domain_state.unknowns),
                            "planner"
                        )

                elif action.action_type == "acquire_capability" and action.target:
                    logger.info(f"  Acquiring capability: {action.target}")
                    # Simplified: mark as owned immediately for Wave 1
                    self.state.capabilities.ensure_owned(action.target)

                elif action.action_type == "stuck":
                    logger.info(f"  STUCK: {action.reason}")
                    # Save state and break
                    await self.blackboard.save_engagement_state(
                        self.state.engagement_id,
                        self.state.target_address,
                        self.state.current_cycle,
                        status="stuck",
                        profile_json=json.dumps(self.state.target.to_dict()),
                        is_stuck=True,
                    )
                    # Check if target is genuinely stuck
                    if self.state.target.is_stuck(self.state.current_cycle):
                        logger.warning("Target model hasn't changed in 5+ cycles. Ending engagement.")
                        break

                # Advance cycle
                self.state.current_cycle += 1
                await asyncio.sleep(self.config.cycle_delay_seconds)

        except KeyboardInterrupt:
            logger.info("\nEngagement interrupted by operator")
        finally:
            thermo_task.cancel()
            try:
                await thermo_task
            except asyncio.CancelledError:
                pass
            await self.shutdown()

    async def shutdown(self):
        """Save final state and close connections."""
        if self.state:
            await self.blackboard.save_engagement_state(
                self.state.engagement_id,
                self.state.target_address,
                self.state.current_cycle,
                status="completed" if self.state.current_cycle >= self.config.max_cycles else "interrupted",
                profile_json=json.dumps(self.state.target.to_dict()),
            )
            logger.info(f"Engagement state saved at cycle {self.state.current_cycle}")

            # Print summary
            logger.info(f"\n{'='*60}")
            logger.info(f"ENGAGEMENT SUMMARY")
            logger.info(f"{'='*60}")
            logger.info(f"  Target:     {self.state.target_address}")
            logger.info(f"  Cycles:     {self.state.current_cycle}")
            logger.info(f"  Status:     {self.state.status}")

            ds = self.state.target.domains.get("network", None)
            if ds:
                logger.info(f"  Affordances found: {len(ds.affordances)}")
                logger.info(f"  Constraints found: {len(ds.constraints)}")
                logger.info(f"  Unknowns remaining: {len(ds.unknowns)}")
                logger.info(f"  Techniques failed: {len(self.state.target.failed_techniques)}")

        # Store in hippocampal memory
        self.hippocampus.store(self.state, outcome=self.state.status,
                                reflection=f"Wave 2 engagement against {self.state.target_address}")
        logger.info(f"Hippocampus: stored episode ({self.hippocampus.episode_count} total)")

        self.blackboard.close()
        logger.info("Raphael engagement complete")


async def main():
    config = RaphaelConfig.from_env()

    # Override target from command line if provided
    if len(sys.argv) > 1 and sys.argv[1] not in ("-h", "--help"):
        config.target = sys.argv[1]
        # Re-parse host:port
        import re
        match = re.match(r'^([^:]+):(\d+)$', config.target)
        if match:
            config.target_host = match.group(1)
            config.target_port = int(match.group(2))

    if not config.target:
        target = os.environ.get("RAPHAEL_TARGET", "")
        if not target:
            print("Usage: python -m raphael.main <target_ip_or_domain>")
            print("  or set RAPHAEL_TARGET environment variable")
            sys.exit(1)
        config.target = target

    if "-h" in sys.argv or "--help" in sys.argv:
        print("RAPHAEL — Self-growing offensive AI")
        print(f"Usage: python -m raphael.main <target> [options]")
        print(f"")
        print(f"Environment variables:")
        print(f"  RAPHAEL_TARGET          Target IP or domain (host:port)")
        print(f"  RAPHAEL_MAX_CYCLES      Max engagement cycles (default: 50)")
        print(f"  RAPHAEL_CYCLE_DELAY     Delay between cycles in seconds (default: 1.0)")
        print(f"  RAPHAEL_DB_PATH         Blackboard SQLite path")
        print(f"  RAPHAEL_FORCE_LOCAL     Force local execution (default: 0)")
        print(f"  KALI_TOOLS_URL          Kali tools API URL (default: http://localhost:3800)")
        return

    organism = RaphaelOrganism(config)
    await organism.initialize()
    await organism.run()


if __name__ == "__main__":
    asyncio.run(main())
