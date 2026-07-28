import json
import logging
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger("checkpoint")


class CheckpointManager:
    def __init__(self, base_dir: str | Path = "") -> None:
        self._dir = Path(base_dir) if base_dir else Path("/tmp/raphael_checkpoints")
        self._dir.mkdir(parents=True, exist_ok=True)

    def save(self, key: str, data: Any) -> None:
        path = self._dir / f"{key}.json"
        try:
            path.write_text(json.dumps({"data": data, "timestamp": time.time()}))
        except OSError as e:
            logger.warning(f"Checkpoint save failed: {e}")

    def load(self, key: str) -> Any | None:
        path = self._dir / f"{key}.json"
        if path.exists():
            try:
                return json.loads(path.read_text()).get("data")
            except (json.JSONDecodeError, OSError):
                return None
        return None
