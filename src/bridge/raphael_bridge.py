#!/usr/bin/env python3
"""
Raphael Bridge Service - JSON-RPC over stdio for OpenCode integration.
Exposes all Raphael orchestrator capabilities as callable methods.
"""

import asyncio
import json
import sys
import logging
from typing import Any, Dict, Optional
from dataclasses import dataclass, asdict

# Import all Raphael modules
sys.path.insert(0, "/home/yaser/raphael-2.0")

from orchestrator.modes import autonomous, community, debate, deep_research, scan, student
from orchestrator.agents import recon, exploit, postex, engage
from orchestrator.c2 import manager, beacon, implant_builder, sliver_backend
from orchestrator.exploit import llm_exploit_engine, relay_chain, pipeline
from orchestrator.harvester.harvester_engine import HarvesterEngine
from orchestrator.kali_tools_client import kali
from orchestrator.conductor import conductor_call, select_strategy
from orchestrator.brain.adaptive_brain import get_analytics
from orchestrator.providers import call_model, resolve_persona_override

logging.basicConfig(level=logging.INFO, stream=sys.stderr)
logger = logging.getLogger("raphael_bridge")


@dataclass
class BridgeRequest:
    id: str
    method: str
    params: Dict[str, Any]


@dataclass
class BridgeResponse:
    id: str
    result: Any = None
    error: Optional[str] = None


class RaphaelBridge:
    def __init__(self):
        self.methods = {
            # === MODES ===
            "mode.autonomous": self.mode_autonomous,
            "mode.community": self.mode_community,
            "mode.debate": self.mode_debate,
            "mode.deep_research": self.mode_deep_research,
            "mode.scan": self.mode_scan,
            "mode.student": self.mode_student,

            # === AGENTS ===
            "agent.recon": self.agent_recon,
            "agent.exploit": self.agent_exploit,
            "agent.postex": self.agent_postex,
            "agent.engage": self.agent_engage,

            # === C2 / IMPLANTS ===
            "c2.build_implant": self.c2_build_implant,
            "c2.deploy": self.c2_deploy,
            "c2.list_beacons": self.c2_list_beacons,
            "c2.task_beacon": self.c2_task_beacon,
            "c2.sliver_connect": self.c2_sliver_connect,

            # === EXPLOIT ===
            "exploit.generate": self.exploit_generate,
            "exploit.relay_chain": self.exploit_relay_chain,
            "exploit.payload_db": self.exploit_payload_db,
            "exploit.mcp_start": self.exploit_mcp_start,
            "exploit.mcp_exploit": self.exploit_mcp_exploit,

            # === KALI TOOLS ===
            "kali.run": self.kali_run,
            "kali.nuclei": self.kali_nuclei,
            "kali.sqlmap": self.kali_sqlmap,
            "kali.hashcat": self.kali_hashcat,
            "kali.impacket": self.kali_impacket,
            "kali.list_tools": self.kali_list_tools,

            # === HARVESTER / INTEL ===
            "harvester.run_cycle": self.harvester_run_cycle,
            "harvester.search_techniques": self.harvester_search_techniques,
            "harvester.get_cves": self.harvester_get_cves,

            # === CONDUCTOR / BRAIN ===
            "conductor.call": self.conductor_call,
            "conductor.select_strategy": self.conductor_select_strategy,
            "brain.analytics": self.brain_analytics,
            "brain.memory_store": self.brain_memory_store,
            "brain.memory_recall": self.brain_memory_recall,

            # === PROVIDERS / PERSONAS ===
            "model.call": self.model_call,
            "persona.set": self.persona_set,
            "persona.resolve": self.persona_resolve,

            # === TARGET / SCOPE ===
            "target.set": self.target_set,
            "target.profile": self.target_profile,
            "scope.set": self.scope_set,
        }

    async def handle_request(self, request: BridgeRequest) -> BridgeResponse:
        method = self.methods.get(request.method)
        if not method:
            return BridgeResponse(id=request.id, error=f"Unknown method: {request.method}")
        try:
            result = await method(**request.params)
            return BridgeResponse(id=request.id, result=result)
        except Exception as e:
            logger.exception(f"Error in {request.method}")
            return BridgeResponse(id=request.id, error=str(e))

    # === MODE IMPLEMENTATIONS ===
    async def mode_autonomous(self, target: str, phases: list = None, persona: str = "blackhat", **kwargs):
        return await autonomous.handle(target, phases, persona=persona, **kwargs)

    async def mode_community(self, question: str, rounds: int = 2, models: list = None, **kwargs):
        return await community.handle(question, rounds, models=models, **kwargs)

    async def mode_debate(self, question: str, rounds: int = 3, use_skills: bool = True, models: list = None, **kwargs):
        return await debate.handle(question, rounds, use_skills, models, **kwargs)

    async def mode_deep_research(self, topic: str, **kwargs):
        from orchestrator.modes.deep_research import handle as deep_research_handle
        return await deep_research_handle(topic, **kwargs)

    async def mode_scan(self, target: str, **kwargs):
        return await scan.handle(target, **kwargs)

    async def mode_student(self, target: str, target_type: str = "web", deep: bool = True, do_research: bool = True, **kwargs):
        return await student.handle(target, target_type=target_type, deep=deep, do_research=do_research, **kwargs)

    # === AGENT IMPLEMENTATIONS ===
    async def agent_recon(self, target: str, depth: str = "full", **kwargs):
        return await recon.handle(target, depth, **kwargs)

    async def agent_exploit(self, target: str, vuln_info: dict = None, **kwargs):
        return await exploit.handle(target, vuln_info, **kwargs)

    async def agent_postex(self, session: dict, **kwargs):
        return await postex.handle(session, **kwargs)

    async def agent_engage(self, target: str, chain: str = "full", **kwargs):
        return await engage.handle(target, chain, **kwargs)

    # === C2 / IMPLANTS ===
    async def c2_build_implant(self, config: dict):
        return await implant_builder.build(**config)

    async def c2_deploy(self, implant_path: str, target: str, method: str = "ssh", **kwargs):
        return await manager.deploy(implant_path, target, method, **kwargs)

    async def c2_list_beacons(self):
        return await manager.list_beacons()

    async def c2_task_beacon(self, beacon_id: str, task: dict):
        return await manager.task_beacon(beacon_id, task)

    async def c2_sliver_connect(self, config: dict):
        return await sliver_backend.connect(**config)

    # === EXPLOIT ===
    async def exploit_generate(self, vuln_type: str, target_info: dict, **kwargs):
        return await llm_exploit_engine.generate_exploit(vuln_type, target_info, **kwargs)

    async def exploit_relay_chain(self, target: str, chain_config: list, **kwargs):
        return await relay_chain.execute_chain(target, chain_config, **kwargs)

    async def exploit_payload_db(self, query: str = "", category: str = None):
        from orchestrator.exploit.payloads_db import search_payloads
        return search_payloads(query, category)

    async def exploit_mcp_start(self, port: int = 9500):
        """Start the MCP bridge HTTP server on a background thread."""
        from orchestrator.exploit.mcp_bridge import MCPBridge
        self._mcp_bridge = MCPBridge(port=port)
        self._mcp_bridge.start()
        return {"status": "started", "port": port, "url": f"http://127.0.0.1:{port}/health"}

    async def exploit_mcp_exploit(self, target: str, url: str = None):
        """Trigger exploitation through the MCP bridge HTTP API."""
        import httpx
        if not hasattr(self, '_mcp_bridge') or not self._mcp_bridge:
            return {"error": "MCP bridge not started. Call exploit.mcp_start first."}
        port = self._mcp_bridge.port
        try:
            async with httpx.AsyncClient(timeout=120) as c:
                resp = await c.post(
                    f"http://127.0.0.1:{port}/exploit",
                    json={"target": target, "url": url or f"http://{target}:80"},
                )
                return resp.json()
        except Exception as e:
            return {"error": f"MCP bridge request failed: {e}"}

    # === KALI TOOLS ===
    async def kali_run(self, tool: str, args: str = "", timeout: int = 300):
        return await kali.run(tool, args, timeout)

    async def kali_nuclei(self, target: str, templates: list = None, severity: str = None, rate_limit: int = 50):
        return await kali.run_nuclei(target, templates, severity, rate_limit)

    async def kali_sqlmap(self, url: str, args: str = "", timeout: int = 120):
        return await kali.run_sqlmap(url, args, timeout)

    async def kali_hashcat(self, args: str = "", timeout: int = 600):
        return await kali.run_hashcat(args, timeout)

    async def kali_impacket(self, script: str, args: str = "", timeout: int = 120):
        return await kali.run_impacket(script, args, timeout)

    async def kali_list_tools(self):
        return await kali.tools_list()

    # === HARVESTER ===
    async def harvester_run_cycle(self, target: str = None):
        engine = HarvesterEngine()
        cycle = await engine.run_cycle(target)
        return asdict(cycle)

    async def harvester_search_techniques(self, query: str, category: str = None):
        engine = HarvesterEngine()
        return engine.search_techniques(query, category)

    async def harvester_get_cves(self, keyword: str = "", days: int = 30):
        engine = HarvesterEngine()
        return await engine.cve_ingester.get_recent_cves(keyword, days)

    # === CONDUCTOR / BRAIN ===
    async def conductor_call(self, prompt: str, model: str = "kimi", category: str = "default"):
        return await conductor_call(prompt, model, category)

    async def conductor_select_strategy(self, context: str, findings: list):
        from orchestrator.conductor import select_strategy
        return await select_strategy(context, findings)

    async def brain_analytics(self):
        return get_analytics()

    async def brain_memory_store(self, key: str, value: dict, memory_type: str = "episodic"):
        from orchestrator.brain.neural_memory import store_episodic, store_semantic
        if memory_type == "episodic":
            return await store_episodic(key, value)
        return await store_semantic(key, value)

    async def brain_memory_recall(self, query: str, memory_type: str = "episodic", limit: int = 10):
        from orchestrator.brain.neural_memory import retrieve_episodic, retrieve_semantic
        if memory_type == "episodic":
            return await retrieve_episodic(query, limit)
        return await retrieve_semantic(query, limit)

    # === PROVIDERS / PERSONAS ===
    async def model_call(self, model: str, messages: list, **kwargs):
        return await call_model(model, messages, **kwargs)

    async def persona_set(self, persona: str):
        import os
        os.environ["RAPHAEL_PERSONA"] = persona
        return {"persona": persona, "override": resolve_persona_override(persona)}

    async def persona_resolve(self, persona: str):
        return resolve_persona_override(persona)

    # === TARGET / SCOPE ===
    async def target_set(self, target: str):
        from orchestrator.config.target import set_target
        set_target(target)
        return {"target": target}

    async def target_profile(self, target: str):
        from orchestrator.brain.target_profiler import profile_target
        return profile_target(target)

    async def scope_set(self, scope: dict):
        from orchestrator.config.paths import set_scope
        set_scope(scope)
        return {"scope": scope}


async def main():
    bridge = RaphaelBridge()

    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    await asyncio.get_event_loop().connect_read_pipe(lambda: protocol, sys.stdin)

    writer_transport, writer_protocol = await asyncio.get_event_loop().connect_write_pipe(
        asyncio.streams.FlowControlMixin, sys.stdout
    )
    writer = asyncio.StreamWriter(writer_transport, writer_protocol, None, asyncio.get_event_loop())

    while True:
        line = await reader.readline()
        if not line:
            break
        try:
            request_data = json.loads(line.decode().strip())
            request = BridgeRequest(**request_data)
            response = await bridge.handle_request(request)
            writer.write((json.dumps(asdict(response)) + "\n").encode())
            await writer.drain()
        except json.JSONDecodeError:
            continue


if __name__ == "__main__":
    asyncio.run(main())