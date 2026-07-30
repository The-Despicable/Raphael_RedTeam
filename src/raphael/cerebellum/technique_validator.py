"""TechniqueValidator — checks technique parameters before execution."""
from __future__ import annotations
import re
from typing import Optional
from raphael.techniques import Technique, TECHNIQUE_REGISTRY


class TechniqueValidator:
    """
    Pre-execution validation. Catches malformed technique parameters
    before they produce noisy failure entries in the negative cache.
    """

    @staticmethod
    def validate(technique: Technique, target: str, ports: Optional[str] = None) -> list[str]:
        """
        Validate a technique's parameters before execution.
        Returns a list of validation errors (empty = valid).
        """
        errors = []

        # Target validation
        if not target or target == "":
            errors.append("target is empty")
        
        # IP validation (if target looks like an IP)
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', target):
            parts = target.split(".")
            for p in parts:
                if not (0 <= int(p) <= 255):
                    errors.append(f"invalid IP octet: {p}")
                    break
        
        # Port validation
        if ports:
            for port_str in ports.split(","):
                try:
                    p = int(port_str.strip())
                    if not (1 <= p <= 65535):
                        errors.append(f"invalid port: {p}")
                except ValueError:
                    errors.append(f"invalid port string: {port_str}")

        # Tool-specific validations
        if technique.tool == "nmap" and target:
            if " " in target and not target.startswith("-"):
                errors.append("nmap target contains spaces (possible injection)")
        
        if technique.parser.startswith("http") or "http" in technique.prerequisites:
            if not target.startswith("http"):
                pass  # HTTP techniques can use IPs — the executor prepends protocol

        return errors

    @staticmethod
    def suggests_param_fix(technique: Technique, errors: list[str]) -> Optional[str]:
        """
        If validation failed, suggest a fix for the technique parameters.
        """
        if not errors:
            return None
        if "target is empty" in errors:
            return "Provide a target IP or domain via RAPHAEL_TARGET"
        return None


# Singleton
_validator: TechniqueValidator | None = None

def get_validator() -> TechniqueValidator:
    global _validator
    if _validator is None:
        _validator = TechniqueValidator()
    return _validator
