#!/usr/bin/env python3
"""Verification Loop Technique - CLI Entry Point"""
from __future__ import annotations

import asyncio
import sys
import os
import json
import argparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from raphael.verifier.core import VerificationLoop
from raphael.verifier.types import PayloadVariant
from raphael.blackboard import Blackboard
from raphael.config import RaphaelConfig


async def main():
    parser = argparse.ArgumentParser(description="Verification Loop - Verify exploit delivery")
    parser.add_argument("target_ip", help="Target IP address")
    parser.add_argument("target_hostname", nargs="?", help="Target hostname (optional)")
    parser.add_argument("--port", type=int, default=80, help="Target port")
    parser.add_argument("--variant", type=str, default="reverse_shell", help="Payload variant to verify")
    parser.add_argument("--listener-port", type=int, default=4444, help="Listener port for reverse shell")
    parser.add_argument("--canary-url", type=str, help="HTTP canary base URL")
    parser.add_argument("--dns-domain", type=str, help="DNS callback domain")
    parser.add_argument("--timeout", type=float, default=60.0, help="Verification timeout")
    args = parser.parse_args()

    config = RaphaelConfig.from_env()
    blackboard = Blackboard(config.db_path)
    blackboard.connect()

    loop = VerificationLoop()

    try:
        variant = PayloadVariant(args.variant)
    except ValueError:
        print(f"Invalid variant: {args.variant}. Valid: {[v.value for v in PayloadVariant]}", file=sys.stderr)
        sys.exit(1)

    callback_config = {
        "listener_port": args.listener_port,
        "bind_port": args.listener_port,
        "http_canary_base_url": args.canary_url or f"http://{args.target_ip}:{args.port}",
        "dns_callback_domain": args.dns_domain,
        "canary_timeout": args.timeout,
        "listener_timeout": args.timeout,
        "dns_timeout": args.timeout,
    }

    trace_id = f"trace_{args.target_ip}_{args.port}"
    technique_id = "verification_loop"

    preflight_id = await loop.preflight(technique_id, variant, trace_id, callback_config)
    observation = await loop.observe(preflight_id, timeout=args.timeout)

    result = {
        "target": args.target_ip,
        "hostname": args.target_hostname,
        "port": args.port,
        "variant": args.variant,
        "preflight_id": preflight_id,
        "trace_id": trace_id,
        "overall_result": observation.overall_result.value,
        "duration_ms": observation.duration_ms,
        "channels": [
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
    }

    print(json.dumps(result, indent=2))

    blackboard.close()


if __name__ == "__main__":
    asyncio.run(main())