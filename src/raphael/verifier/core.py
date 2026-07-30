from __future__ import annotations

import asyncio
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from raphael.verifier.types import (
    ChannelConfig,
    PreflightRecord,
    ObservationChannel,
    ObservationResult,
    VerificationResult,
    PayloadVariant,
    PAYLOAD_FALLBACK_CHAIN,
    generate_canary_token,
    AdaptationDecision,
    ChannelObservation,
)
from raphael.verifier.channels import (
    create_channel,
    TCPListenerChannel,
    HTTPCanaryChannel,
    DNSCallbackChannel,
    BaseChannel,
)

logger = logging.getLogger(__name__)


class VerificationLoop:
    """Orchestrates exploit verification with fallback adaptation."""

    def __init__(self):
        self._preflights: Dict[str, PreflightRecord] = {}
        self._channels: Dict[str, Dict[ObservationChannel, BaseChannel]] = {}
        self._running_observations: Dict[str, asyncio.Task] = {}

    async def preflight(
        self,
        technique_id: str,
        payload_variant: PayloadVariant,
        trace_id: str,
        callback_config: Dict[str, Any],
    ) -> str:
        """
        Set up verification infrastructure before exploit fires.

        Args:
            technique_id: ID of the technique being verified
            payload_variant: Type of payload (determines which channels to use)
            trace_id: Trace ID for correlation
            callback_config: Dict with keys like:
                - listener_port: int (for reverse shell)
                - bind_port: int (for bind shell)
                - http_canary_base_url: str (e.g., "http://target/uploads/")
                - dns_callback_domain: str (for blind RCE)

        Returns:
            preflight_id to track this verification
        """
        preflight_id = f"pf-{uuid.uuid4().hex[:8]}"
        canary_token = generate_canary_token()

        channels = self._build_channel_configs(payload_variant, callback_config)

        preflight = PreflightRecord(
            preflight_id=preflight_id,
            trace_id=trace_id,
            technique_id=technique_id,
            payload_variant=payload_variant,
            channels=channels,
            canary_token=canary_token,
        )

        await self._start_listeners(preflight, callback_config)

        self._preflights[preflight_id] = preflight

        logger.info(f"Preflight {preflight_id} ready for technique {technique_id} with variant {payload_variant}")
        return preflight_id

    def _build_channel_configs(self, variant: PayloadVariant, callback_config: Dict) -> List[ChannelConfig]:
        """Build channel configs based on payload variant."""
        configs = []

        configs.append(ChannelConfig(
            channel=ObservationChannel.HTTP_CANARY,
            enabled=True,
            timeout=callback_config.get("canary_timeout", 30.0),
            params={},
        ))

        if variant == PayloadVariant.REVERSE_SHELL:
            configs.append(ChannelConfig(
                channel=ObservationChannel.TCP_LISTENER,
                enabled=True,
                timeout=callback_config.get("listener_timeout", 60.0),
                params={"port": callback_config.get("listener_port", 4444)},
            ))
        elif variant == PayloadVariant.BIND_SHELL:
            configs.append(ChannelConfig(
                channel=ObservationChannel.TCP_LISTENER,
                enabled=True,
                timeout=callback_config.get("listener_timeout", 60.0),
                params={"port": callback_config.get("bind_port", 4444)},
            ))
        elif variant == PayloadVariant.DNS_EXFIL:
            configs.append(ChannelConfig(
                channel=ObservationChannel.DNS_CALLBACK,
                enabled=True,
                timeout=callback_config.get("dns_timeout", 60.0),
                params={"domain": callback_config.get("dns_callback_domain")},
            ))

        return configs

    async def _start_listeners(self, preflight: PreflightRecord, callback_config: Dict) -> None:
        """Start listener channels based on preflight config."""
        channels: Dict[ObservationChannel, BaseChannel] = {}

        for config in preflight.channels:
            if not config.enabled:
                continue

            channel = create_channel(config)
            channels[config.channel] = channel

            if config.channel == ObservationChannel.TCP_LISTENER:
                if isinstance(channel, TCPListenerChannel):
                    port = config.params.get("port", 4444)
                    preflight.listener_port = port
                    await channel.start(port)

            elif config.channel == ObservationChannel.HTTP_CANARY:
                if isinstance(channel, HTTPCanaryChannel):
                    canary_url = callback_config.get("http_canary_base_url", "")
                    if canary_url:
                        preflight.http_canary_url = f"{canary_url.rstrip('/')}/{preflight.canary_token}"

            elif config.channel == ObservationChannel.DNS_CALLBACK:
                if isinstance(channel, DNSCallbackChannel):
                    domain = config.params.get("domain")
                    if domain:
                        preflight.dns_callback_domain = domain
                        channel.set_domain(domain)
                        await channel.start()

        self._channels[preflight.preflight_id] = channels

    async def observe(self, preflight_id: str, timeout: Optional[float] = None) -> ObservationResult:
        """
        Run observation across all channels.

        Args:
            preflight_id: ID from preflight()
            timeout: Overall timeout (uses channel timeouts if None)

        Returns:
            Aggregated ObservationResult
        """
        preflight = self._preflights.get(preflight_id)
        if not preflight:
            raise ValueError(f"Preflight {preflight_id} not found")

        channels = self._channels.get(preflight_id, {})
        if not channels:
            raise ValueError(f"No channels for preflight {preflight_id}")

        overall_timeout = timeout or max(c.timeout for c in preflight.channels if c.enabled)
        start = time.perf_counter()

        channel_results = await asyncio.gather(*[
            self._run_channel_observation(preflight, channel, config.timeout)
            for config in preflight.channels
            if config.enabled
            for channel in [channels.get(config.channel)]
            if channel is not None
        ], return_exceptions=True)

        results = []
        for i, result in enumerate(channel_results):
            if isinstance(result, Exception):
                config = preflight.channels[i]
                results.append(ChannelObservation(
                    channel=config.channel,
                    success=False,
                    evidence={},
                    error=str(result),
                    duration_ms=0,
                ))
            else:
                results.append(result)

        overall_result = self._aggregate_results(results)
        primary_evidence = self._extract_primary_evidence(results)

        duration_ms = (time.perf_counter() - start) * 1000

        observation = ObservationResult(
            preflight_id=preflight_id,
            trace_id=preflight.trace_id,
            technique_id=preflight.technique_id,
            channel_results=results,
            overall_result=overall_result,
            primary_evidence=primary_evidence,
            duration_ms=duration_ms,
        )

        await self.cleanup(preflight_id)
        return observation

    async def _run_channel_observation(
        self,
        preflight: PreflightRecord,
        channel: BaseChannel,
        timeout: float,
    ) -> ChannelObservation:
        """Run observation on a single channel."""
        return await channel.observe(preflight, timeout)

    def _aggregate_results(self, results: List[ChannelObservation]) -> VerificationResult:
        """Aggregate channel results into overall verification result."""
        if not results:
            return VerificationResult.FAIL

        tcp_success = any(r.success for r in results if r.channel == ObservationChannel.TCP_LISTENER)
        http_success = any(r.success for r in results if r.channel == ObservationChannel.HTTP_CANARY)
        dns_success = any(r.success for r in results if r.channel == ObservationChannel.DNS_CALLBACK)

        if tcp_success:
            return VerificationResult.SUCCESS
        elif http_success:
            return VerificationResult.PARTIAL
        elif dns_success:
            return VerificationResult.BLIND_RCE
        else:
            return VerificationResult.FAIL

    def _extract_primary_evidence(self, results: List[ChannelObservation]) -> Dict[str, Any]:
        """Extract primary evidence from successful channels."""
        evidence = {}
        for r in results:
            if r.success and r.evidence:
                evidence[r.channel.value] = r.evidence
        return evidence

    def adapt(self, observation: ObservationResult) -> AdaptationDecision:
        """
        Decide how to adapt based on verification result.

        Args:
            observation: Result from observe()

        Returns:
            AdaptationDecision with next variant to try
        """
        current_variant = None
        for preflight in self._preflights.values():
            if preflight.preflight_id == observation.preflight_id:
                current_variant = preflight.payload_variant
                break

        if observation.overall_result == VerificationResult.SUCCESS:
            return AdaptationDecision(should_retry=False, reason="success")

        if observation.overall_result == VerificationResult.PARTIAL:
            return AdaptationDecision(
                should_retry=False,
                reason="partial_success_file_write_only",
            )

        if observation.overall_result == VerificationResult.BLIND_RCE:
            return AdaptationDecision(
                should_retry=False,
                reason="blind_rce_detected",
            )

        if current_variant and current_variant in PAYLOAD_FALLBACK_CHAIN:
            current_idx = PAYLOAD_FALLBACK_CHAIN.index(current_variant)
            if current_idx + 1 < len(PAYLOAD_FALLBACK_CHAIN):
                next_variant = PAYLOAD_FALLBACK_CHAIN[current_idx + 1]
                return AdaptationDecision(
                    should_retry=True,
                    next_variant=next_variant,
                    reason=f"fallback_to_{next_variant.value}",
                )

        return AdaptationDecision(
            should_retry=False,
            reason="no_more_variants",
        )

    async def cleanup(self, preflight_id: str) -> None:
        """Clean up channels and resources."""
        channels = self._channels.pop(preflight_id, {})
        for channel in channels.values():
            try:
                if hasattr(channel, 'stop'):
                    await channel.stop()
                elif hasattr(channel, 'close'):
                    await channel.close()
            except Exception as e:
                logger.warning(f"Error cleaning up channel {channel}: {e}")

        preflight = self._preflights.pop(preflight_id, None)
        if preflight:
            for f in preflight.temp_files:
                try:
                    import os
                    os.unlink(f)
                except Exception:
                    pass

    async def cleanup_all(self) -> None:
        """Clean up all preflights."""
        for pf_id in list(self._preflights.keys()):
            await self.cleanup(pf_id)