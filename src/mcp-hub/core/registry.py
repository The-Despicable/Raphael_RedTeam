import importlib
import inspect
import json
import logging
import os
import pkgutil
import sys
from typing import Any

logger = logging.getLogger("mcp_hub.registry")


class BaseTool:
    name: str = ""
    description: str = ""
    category: str = ""
    params_schema: type = None
    output_schema: type = None

    async def execute(self, params: Any) -> Any:
        raise NotImplementedError

    def get_input_schema(self) -> dict:
        if self.params_schema:
            return self.params_schema.model_json_schema()
        return {"type": "object", "properties": {}}

    def get_output_schema(self) -> dict:
        if self.output_schema:
            return self.output_schema.model_json_schema()
        return {}


class ToolRegistry:
    def __init__(self):
        self._tools: dict[str, BaseTool] = {}
        self._categories: dict[str, list[BaseTool]] = {}

    def load_tools(self, tools_dir: str = None):
        if tools_dir is None:
            tools_dir = os.path.join(os.path.dirname(__file__), "..", "tools")

        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        if base_dir not in sys.path:
            sys.path.insert(0, base_dir)

        categories = [d for d in os.listdir(tools_dir)
                      if os.path.isdir(os.path.join(tools_dir, d)) and not d.startswith("_")]

        for category in categories:
            cat_path = os.path.join(tools_dir, category)

            for importer, modname, ispkg in pkgutil.iter_modules([cat_path]):
                if modname.startswith("_"):
                    continue
                try:
                    full_module = importlib.import_module(f"tools.{category}.{modname}")
                    for attr_name in dir(full_module):
                        attr = getattr(full_module, attr_name)
                        if (isinstance(attr, type) and issubclass(attr, BaseTool)
                                and attr is not BaseTool):
                            instance = attr()
                            instance.category = category
                            self._tools[instance.name] = instance
                            self._categories.setdefault(category, []).append(instance)
                            logger.info(f"Loaded tool: {instance.name} ({category})")
                except Exception as e:
                    logger.warning(f"Failed to load {modname}: {e}")

    def get_tool(self, name: str) -> BaseTool | None:
        return self._tools.get(name)

    def list_tools(self, category: str = None) -> list[dict]:
        tools = self._tools.values()
        if category:
            tools = self._categories.get(category, [])
        return [
            {
                "name": t.name,
                "description": t.description,
                "category": t.category,
                "input_schema": t.get_input_schema(),
                "output_schema": t.get_output_schema(),
            }
            for t in tools
        ]

    def get_categories(self) -> list[str]:
        return list(self._categories.keys())

    def export_registry_json(self, path: str = None):
        if path is None:
            path = os.path.join(os.path.dirname(__file__), "..", "static", "tool-registry.json")
        data = {
            "version": "1.0",
            "categories": {},
        }
        for cat, tools in self._categories.items():
            data["categories"][cat] = [
                {
                    "name": t.name,
                    "description": t.description,
                    "input_schema": t.get_input_schema(),
                }
                for t in tools
            ]
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        return path
