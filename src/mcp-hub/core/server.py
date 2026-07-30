import json
import logging
import time
from pathlib import Path
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse

from .auth import authenticate, load_api_keys
from .registry import ToolRegistry
from .decision_engine import DecisionEngine
from .security import validate_scope, audit_logger, load_scope_rules
from config.paths import get_base_dir

logging.basicConfig(level=logging.INFO, format="[MCP] %(levelname)s %(message)s")
logger = logging.getLogger("mcp_hub")


class MCPServer:
    def __init__(self):
        self.app = FastAPI(title="Raphael 2.0 MCP Hub", version="2.0.0")
        self.registry = ToolRegistry()
        self.decision_engine = DecisionEngine(self.registry)

        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_methods=["*"],
            allow_headers=["*"],
        )

        load_api_keys()
        load_scope_rules()
        self.registry.load_tools()
        self.registry.export_registry_json()
        logger.info(f"MCP Hub ready — {len(self.registry._tools)} tools loaded")

        self._setup_routes()

    def _setup_routes(self):
        @self.app.get("/health")
        async def health():
            return {
                "status": "ok",
                "version": "2.0.0",
                "tools_loaded": len(self.registry._tools),
                "categories": self.registry.get_categories(),
            }

        @self.app.get("/tool-registry.json")
        async def tool_registry():
            registry_path = get_base_dir() / "mcp-hub" / "static" / "tool-registry.json"
            return FileResponse(
                str(registry_path),
                media_type="application/json",
            )

        @self.app.post("/mcp")
        async def mcp_endpoint(request: Request):
            t0 = time.time()
            user = await authenticate(request)

            try:
                payload = await request.json()
            except json.JSONDecodeError:
                raise HTTPException(status_code=400, detail="Invalid JSON")

            method = payload.get("method", "")
            params = payload.get("params", {})
            req_id = payload.get("id")

            if method == "tools.list":
                category = params.get("category") if isinstance(params, dict) else None
                tools = self.registry.list_tools(category)
                audit_logger.log(user["key"], method, params, 200, time.time() - t0)
                return JSONResponse({"result": {"tools": tools}, "id": req_id})

            elif method == "tools.call":
                tool_name = params.get("name", "") if isinstance(params, dict) else ""
                arguments = params.get("arguments", {}) if isinstance(params, dict) else {}

                tool = self.registry.get_tool(tool_name)
                if not tool:
                    return JSONResponse({
                        "result": {"content": [{"type": "text", "text": f"Tool '{tool_name}' not found"}], "isError": True},
                        "id": req_id,
                    })

                target = arguments.get("target") or arguments.get("url") or arguments.get("domain", "")
                if target and not validate_scope(target):
                    return JSONResponse({
                        "result": {"content": [{"type": "text", "text": f"Target '{target}' is out of scope"}], "isError": True},
                        "id": req_id,
                    })

                try:
                    result = await tool.execute(arguments)
                    audit_logger.log(user["key"], f"tools.call:{tool_name}", arguments, 200, time.time() - t0)
                    return JSONResponse({
                        "result": {"content": [{"type": "text", "text": str(result)}], "isError": False},
                        "id": req_id,
                    })
                except Exception as e:
                    logger.error(f"Tool {tool_name} failed: {e}")
                    return JSONResponse({
                        "result": {"content": [{"type": "text", "text": f"Execution failed: {e}"}], "isError": True},
                        "id": req_id,
                    })

            elif method == "tools.recommend":
                target = params.get("target", "") if isinstance(params, dict) else ""
                chain = self.decision_engine.recommend_chain(target)
                return JSONResponse({"result": {"chain": chain}, "id": req_id})

            elif method == "resources.list":
                return JSONResponse({
                    "result": {"resources": [
                        {"uri": "mcp://tools/registry", "name": "Tool Registry", "mimeType": "application/json"},
                        {"uri": "mcp://health", "name": "Server Health", "mimeType": "application/json"},
                    ]},
                    "id": req_id,
                })

            elif method == "prompts.list":
                return JSONResponse({
                    "result": {"prompts": [
                        {
                            "name": "analyze_target",
                            "description": "Analyze a target and recommend tool chain",
                            "arguments": [{"name": "target", "description": "Target domain/IP/URL", "required": True}],
                        },
                        {
                            "name": "audit_summary",
                            "description": "Summarize recent audit log entries",
                            "arguments": [{"name": "limit", "description": "Number of entries", "required": False}],
                        },
                    ]},
                    "id": req_id,
                })

            else:
                return JSONResponse({
                    "result": {"content": [{"type": "text", "text": f"Unknown method: {method}"}], "isError": True},
                    "id": req_id,
                })
