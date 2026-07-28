"""
End-to-end integration test harness for the Raphael pipeline.
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    import fakeredis
    FAKEREDIS_AVAILABLE = True
except ImportError:
    FAKEREDIS_AVAILABLE = False

from raphael.eventbus import EventBus, EventBusConfig
from raphael.blackboard import Blackboard
from raphael.verifier.core import VerificationLoop
from raphael.techniques.vhost_enum import VHOSTEnumTechnique
from raphael.techniques.vhost_enum.types import EnumConfig, EnumMethod, VHOSTTarget, EnumSession
from raphael.exploit_factory import ExploitFactory, ExploitFactoryConfig
from raphael.exploit_factory.cve_database import CVEDatabase
from raphael.exploit_factory.types import ExploitStatus
from raphael.cognitive import (
    TargetModel, CapabilityModel, MemoryPrior, Thermoregulator,
    ThermoregulatorConfig, GreedyPlanner, RiskLevel
)
from raphael.verifier.types import (
    PayloadVariant,
    VerificationResult,
    ObservationChannel,
    generate_trace_id,
)

logger = logging.getLogger(__name__)


@dataclass
class IntegrationConfig:
    """Configuration for the integration test."""
    # Redis
    redis_url: str = "redis://localhost:6379/0"
    
    # Target
    target_ip: str = "10.129.41.98"
    target_hostname: str = "bedside.htb"
    target_port: int = 80
    target_ssl: bool = False
    
    # VHOST Enum
    vhost_methods: List[str] = field(default_factory=lambda: ["dns_brute", "ct_logs", "host_fuzz", "ssl_san"])
    vhost_recursive: bool = True
    vhost_recursive_depth: int = 2
    vhost_threads: int = 50
    vhost_timeout: float = 10.0
    
    # Exploit Factory
    cve_database_path: str = "data/cves.json"
    templates_path: str = "templates/exploits/"
    auto_deliver: bool = True
    callback_ip: str = "10.10.14.18"
    callback_port: int = 4444
    bind_port: int = 4445
    verification_timeout: float = 30.0
    
    # Verification Loop
    canary_base_url: str = "http://target/uploads/"
    
    def __post_init__(self):
        if self.vhost_methods is None:
            self.vhost_methods = ["dns_brute", "ct_logs", "host_fuzz", "ssl_san"]


class IntegrationHarness:
    """End-to-end integration test harness for Raphael pipeline."""

    def __init__(self, config: IntegrationConfig):
        self.config = config
        self.eventbus: Optional[EventBus] = None
        self.blackboard: Optional[Blackboard] = None
        self.vhost_technique: Optional[VHOSTEnumTechnique] = None
        self.exploit_factory: Optional[ExploitFactory] = None
        self.verification_loop: Optional[VerificationLoop] = None
        self.target_model: Optional[TargetModel] = None
        self.capability_model: Optional[CapabilityModel] = None
        self.memory_prior: Optional[MemoryPrior] = None
        self.thermoregulator: Optional[Thermoregulator] = None
        self.planner: Optional[GreedyPlanner] = None
        self._running = False
        self._redis_client: Optional[redis.Redis] = None
        self._results: Dict[str, Any] = {}
        self._vhost_session: Optional[EnumSession] = None

    async def setup(self) -> None:
        """Initialize all components."""
        logger.info("Setting up integration harness...")
        
        # Connect to Redis (use fakeredis for testing)
        self._redis_client = fakeredis.FakeAsyncRedis(decode_responses=True)
        await self._redis_client.ping()
        logger.info("Connected to FakeRedis")
        
        # Initialize EventBus with fakeredis
        self.eventbus = EventBus(EventBusConfig(redis_url="redis://fake"))
        self.eventbus._redis = self._redis_client
        await self.eventbus.connect()
        logger.info("EventBus connected")
        
        # Initialize Blackboard
        self.blackboard = Blackboard(self.eventbus)
        logger.info("Blackboard initialized")
        
        # Initialize Cognitive Components
        self.target_model = TargetModel(
            identifier=self.config.target_hostname,
            type="host",
            metadata={"ip": self.config.target_ip}
        )
        self.capability_model = CapabilityModel()
        self.memory_prior = MemoryPrior()
        
        thermo_config = ThermoregulatorConfig(
            check_interval=1.0,
            critical_threshold=0.85,
            pause_on_critical=True,
            resume_threshold=0.3,
        )
        self.thermoregulator = Thermoregulator(thermo_config)
        
        self.planner = GreedyPlanner(
            techniques={},
            target_model=self.target_model,
            capability_model=self.capability_model,
            memory_prior=self.memory_prior,
            negative_cache=self.memory_prior,
        )
        self.planner.set_thermoregulator(self.thermoregulator)
        self.planner.register_event_bus(self.eventbus)
        
        # Wire Thermoregulator to watch TargetModel
        self.thermoregulator.watch("target", self.target_model, "risk_score")
        
        # Initialize VHOST Enum Technique
        self.vhost_technique = VHOSTEnumTechnique(self.blackboard, self.eventbus)
        logger.info("VHOST Enum Technique initialized")
        
        # Initialize Exploit Factory
        factory_config = ExploitFactoryConfig(
            cve_database_path=self.config.cve_database_path,
            templates_path=self.config.templates_path,
            auto_deliver=self.config.auto_deliver,
            verification_timeout=self.config.verification_timeout,
        )
        
        self.exploit_factory = ExploitFactory(factory_config, self.blackboard)
        await self.exploit_factory.initialize()
        logger.info("Exploit Factory initialized")
        
        # Add risk_score property to ExploitFactory for Thermoregulator
        self.exploit_factory._current_detection_risk = 0.0
        
        # Wire Thermoregulator to watch ExploitFactory
        self.thermoregulator.watch("exploit_factory", self.exploit_factory, "_current_detection_risk")
        
        # Wire ExploitFactory to Thermoregulator for risk governance
        self.exploit_factory.set_thermoregulator(self.thermoregulator)
        logger.info("ExploitFactory wired to Thermoregulator")
        
        # Initialize Verification Loop
        self.verification_loop = VerificationLoop()
        logger.info("Verification Loop initialized")
        
        # Signal EventBus startup complete
        await self.eventbus.publish("SystemStartupCompleteEvent", {
            "timestamp": asyncio.get_event_loop().time(),
            "components": ["eventbus", "blackboard", "vhost_technique", "exploit_factory", "verification_loop", "cognitive"],
            "status": "ready"
        })
        logger.info("SystemStartupCompleteEvent published - system ready")

    async def run_vhost_enum(self) -> Dict[str, Any]:
        """Run VHOST enumeration and return discovered hosts."""
        logger.info(f"Starting VHOST enumeration on {self.config.target_ip}")
        
        target = VHOSTTarget(
            ip=self.config.target_ip,
            port=self.config.target_port,
            hostname=self.config.target_hostname,
            ssl=self.config.target_ssl,
        )
        
        methods = [EnumMethod(m) for m in self.config.vhost_methods]
        
        enum_config = EnumConfig(
            target=target,
            methods=methods,
            recursive=self.config.vhost_recursive,
            recursive_depth=self.config.vhost_recursive_depth,
            threads=self.config.vhost_threads,
            timeout=self.config.vhost_timeout,
        )
        
        session = await self.vhost_technique.execute(enum_config)
        self._vhost_session = session
        
        results = {
            "session_id": session.session_id,
            "target": target.ip,
            "discovered_count": len(session.discovered),
            "hosts": [
                {
                    "host": h.host,
                    "port": h.port,
                    "method": h.method.value,
                    "status_code": h.status_code,
                    "content_length": h.content_length,
                    "confidence": h.confidence,
                    "technique_id": h.technique_id,
                }
                for h in session.discovered
            ],
            "errors": session.errors,
        }
        
        logger.info(f"VHOST enumeration complete: {results['discovered_count']} hosts discovered")
        return results

    async def run_exploit_factory(self, wait_time: float = 5.0) -> Dict[str, Any]:
        """Wait for exploit factory to process discoveries and generate exploits."""
        logger.info(f"Waiting {wait_time}s for exploit factory to process discoveries...")
        await asyncio.sleep(wait_time)
        
        pending = self.exploit_factory.get_pending_deliveries()
        
        results = {
            "pending_deliveries": len(pending),
            "deliveries": [
                {
                    "delivery_id": d.delivery_id,
                    "target": d.target_host.host,
                    "cve_id": d.cve_record.cve_id,
                    "vector": d.payload.delivery_vector.value,
                    "status": d.status.value,
                }
                for d in pending
            ],
        }
        
        logger.info(f"Exploit factory processed: {results['pending_deliveries']} pending deliveries")
        return results

    async def run_verification_loop(self, technique_id: str, payload_variant: str, 
                                    callback_config: Dict[str, Any]) -> Dict[str, Any]:
        """Run verification loop for a specific exploit delivery."""
        logger.info(f"Running verification for {technique_id} with {payload_variant}")
        
        trace_id = generate_trace_id()
        
        # Map payload variant string to enum
        variant_map = {
            "reverse_shell": PayloadVariant.REVERSE_SHELL,
            "bind_shell": PayloadVariant.BIND_SHELL,
            "command_injection": PayloadVariant.COMMAND_INJECTION,
            "dns_exfil": PayloadVariant.DNS_EXFIL,
            "web_shell": PayloadVariant.WEB_SHELL,
        }
        variant = variant_map.get(payload_variant, PayloadVariant.REVERSE_SHELL)
        
        # Run preflight
        preflight_id = await self.verification_loop.preflight(
            technique_id=technique_id,
            payload_variant=variant,
            trace_id=trace_id,
            callback_config=callback_config,
        )
        
        # Wait for exploit to be delivered (in real scenario, this is async)
        # For test, we simulate by just running observation
        await asyncio.sleep(2.0)
        
        # Observe
        observation = await self.verification_loop.observe(preflight_id)
        
        # Decide
        decision = self.verification_loop.adapt(observation)
        
        # Cleanup
        await self.verification_loop.cleanup(preflight_id)
        
        results = {
            "preflight_id": preflight_id,
            "trace_id": trace_id,
            "technique_id": technique_id,
            "payload_variant": payload_variant,
            "observation": {
                "preflight_id": observation.preflight_id,
                "overall_result": observation.overall_result.value,
                "channel_results": [
                    {
                        "channel": r.channel.value,
                        "success": r.success,
                        "evidence": r.evidence,
                        "error": r.error,
                        "duration_ms": r.duration_ms,
                    }
                    for r in observation.channel_results
                ],
                "primary_evidence": observation.primary_evidence,
                "duration_ms": observation.duration_ms,
            },
            "adaptation": {
                "should_retry": decision.should_retry,
                "next_variant": decision.next_variant.value if decision.next_variant else None,
                "reason": decision.reason,
            },
        }
        
        logger.info(f"Verification complete: {observation.overall_result.value}")
        return results

    async def run_full_pipeline(self) -> Dict[str, Any]:
        """Run the complete end-to-end pipeline using the Planner's planning loop."""
        logger.info("=== STARTING FULL PIPELINE ===")
        start_time = datetime.now(timezone.utc)
        
        # Phase 1: VHOST Enumeration (recon phase)
        vhost_results = await self.run_vhost_enum()
        self._results["vhost_enum"] = vhost_results
        
        # Initialize Verification Loop
        logger.info("Verification Loop initialized")
        
        # Phase 2-3: Planning Loop drives Exploit Factory + Verification
        factory_results = {"pending_deliveries": 0, "deliveries": []}
        verification_results = []
        self._results["exploit_factory"] = factory_results
        
        try:
            async for technique_id in self.planner.planning_loop():
                logger.info(f"Planner selected technique: {technique_id}")
                
                # Execute the technique via Exploit Factory
                # For now, just run the exploit factory cycle
                factory_results = await self.run_exploit_factory(wait_time=5.0)
                self._results["exploit_factory"] = factory_results
                
                # If we have pending deliveries, run verification
                pending = self.exploit_factory.get_pending_deliveries()
                for delivery in pending:
                    technique_id = f"exploit_{delivery.cve_record.cve_id}"
                    payload_variant = delivery.payload.exploit_type.value
                    
                    callback_config = {
                        "listener_port": self.config.callback_port,
                        "http_canary_base_url": self.config.canary_base_url,
                        "listener_timeout": 30.0,
                        "canary_timeout": 15.0,
                    }
                    
                    ver_result = await self.run_verification_loop(
                        technique_id=technique_id,
                        payload_variant=delivery.payload.exploit_type.value,
                        callback_config=callback_config,
                    )
                    verification_results.append(ver_result)
                
                # Check if we should continue or stop
                pending = self.exploit_factory.get_pending_deliveries()
                if not pending:
                    break
            
        except Exception as e:
            logger.error(f"Planning loop error: {e}")
        
        # Summary
        end_time = datetime.now(timezone.utc)
        self._results["summary"] = {
            "started_at": start_time.isoformat(),
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "duration_seconds": (datetime.now(timezone.utc) - start_time).total_seconds(),
            "vhost_discovered": vhost_results["discovered_count"],
            "exploits_generated": factory_results["pending_deliveries"],
            "verifications_run": len(verification_results),
        }
        
        logger.info(f"=== PIPELINE COMPLETE in {self._results['summary']['duration_seconds']:.1f}s ===")
        return self._results

    async def teardown(self) -> None:
        """Clean up all resources."""
        logger.info("Tearing down integration harness...")
        
        if self.exploit_factory:
            # ExploitFactory doesn't have a stop method, just clean up pending
            pass
        
        if self.verification_loop:
            await self.verification_loop.cleanup_all()
        
        if self.vhost_technique:
            await self.vhost_technique.stop()
        
        if self.eventbus:
            await self.eventbus.disconnect()
        
        if self._redis_client:
            await self._redis_client.close()
        
        logger.info("Integration harness torn down")

    @asynccontextmanager
    async def run(self):
        """Context manager for full lifecycle."""
        try:
            await self.setup()
            yield self
        finally:
            await self.teardown()


async def main():
    """Main entry point for integration test."""
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    
    # Load config from environment
    config = IntegrationConfig(
        target_ip=os.getenv("TARGET_IP", "10.129.41.98"),
        target_hostname=os.getenv("TARGET_HOSTNAME", "bedside.htb"),
        redis_url="redis://fake",  # Use fake redis for testing
        callback_ip=os.getenv("CALLBACK_IP", "10.10.14.18"),
        callback_port=int(os.getenv("CALLBACK_PORT", "4444")),
    )
    
    harness = IntegrationHarness(config)
    
    # Handle signals
    loop = asyncio.get_event_loop()
    
    def signal_handler():
        logger.info("Received shutdown signal")
        asyncio.create_task(harness.teardown())
    
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, signal_handler)
        except NotImplementedError:
            pass  # Windows
    
    try:
        async with harness.run() as h:
            results = await h.run_full_pipeline()
            
            # Print summary
            print("\n" + "="*60)
            print("INTEGRATION TEST RESULTS")
            print("="*60)
            import json
            print(json.dumps(results["summary"], indent=2))
            
            if results["vhost_enum"]["hosts"]:
                print("\nDiscovered hosts:")
                for h in results["vhost_enum"]["hosts"]:
                    print(f"  {h['host']}:{h['port']} ({h['method']}) - {h['status_code']} {h['content_length']}B")
            
            if results["exploit_factory"]["deliveries"]:
                print("\nExploits generated:")
                for d in results["exploit_factory"]["deliveries"]:
                    print(f"  {d['cve_id']} -> {d['vector']} ({d['status']})")
            
            print("\nDone.")
            
    except Exception as e:
        logger.error(f"Integration test failed: {e}")
        raise


if __name__ == "__main__":
    asyncio.run(main())