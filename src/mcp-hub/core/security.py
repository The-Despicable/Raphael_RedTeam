import json
import os
import re
import time
from datetime import datetime, timezone
from typing import Optional


SCOPE_RULES: list[dict] = []
AUDIT_LOG_PATH = os.path.join(os.path.dirname(__file__), "..", "logs", "audit.log")


def load_scope_rules(config_path: Optional[str] = None):
    import yaml
    path = config_path or os.path.join(os.path.dirname(__file__), "..", "config.yaml")
    try:
        with open(path) as f:
            cfg = yaml.safe_load(f)
            for rule in cfg.get("scope_rules", []):
                SCOPE_RULES.append({
                    "pattern": re.compile(rule["pattern"]),
                    "action": rule.get("action", "allow"),
                })
    except (FileNotFoundError, yaml.YAMLError):
        pass


def validate_scope(target: str) -> bool:
    if not SCOPE_RULES:
        return True
    for rule in SCOPE_RULES:
        if rule["pattern"].search(target):
            return rule["action"] == "allow"
    return False


class AuditLogger:
    def __init__(self, log_path: str = AUDIT_LOG_PATH):
        self.log_path = log_path
        os.makedirs(os.path.dirname(log_path), exist_ok=True)

    def log(self, user: str, method: str, params: dict, status: int, duration: float):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "user": user,
            "method": method,
            "params": {k: v for k, v in params.items() if k not in ("api_key", "token", "password")},
            "status": status,
            "duration_ms": round(duration * 1000, 2),
        }
        with open(self.log_path, "a") as f:
            f.write(json.dumps(entry) + "\n")


audit_logger = AuditLogger()
