import logging
from typing import Any

logger = logging.getLogger("skill_indexer")


class SkillIndexer:
    def __init__(self) -> None:
        self._index: dict[str, Any] = {}

    def index(self, skill_name: str, metadata: dict) -> None:
        self._index[skill_name] = metadata

    def search(self, query: str) -> list[dict]:
        return [{"name": k, "metadata": v} for k, v in self._index.items() if query.lower() in k.lower()]
