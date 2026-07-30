"""
Blind Probe Parser — Extracts structural affordances from perturbation responses.
Used by the Executor's PARSER_REGISTRY.
"""
import json
import logging
from typing import Any, Dict

from raphael.models.target_model import ConstraintDelta

logger = logging.getLogger("raphael.blind_probe")


class BlindProbeParser:
    """Parses blind_probe JSON output into ConstraintDelta affordances."""

    @staticmethod
    def parse(stdout: str, target: str) -> ConstraintDelta:
        affordances = set()
        constraints = {}
        evidence = stdout[:2000]

        try:
            results = json.loads(stdout)
        except json.JSONDecodeError:
            affordances.add("blind_probe_output_raw")
            return ConstraintDelta(
                new_affordances=affordances,
                evidence=evidence,
            )

        for vec_name, response in results.items():
            if response not in ("EMPTY_ACK", "CONN_REFUSED", "CONN_TIMEOUT") and not response.startswith("SOCKET_ERR"):
                affordances.add(f"VECTOR_RESPONDED:{vec_name}")
                affordances.add("SIGNATURE_ACQUIRED")

                if "HTTP/" in response or "Server:" in response:
                    affordances.add("http_service")
                    affordances.add("SIG:HTTP_DETECTED")
                if "SSH-" in response:
                    affordances.add("ssh_service")
                    affordances.add("SIG:SSH_DETECTED")
                if "SpELParseException" in response or "org.springframework" in response:
                    affordances.add("LEAK:SPRING_BOOT_SPEL_EVAL")
                    affordances.add("SIG:SPRING_BOOT_DETECTED")
                if "StreamCorruptedException" in response or "ObjectInputStream" in response:
                    affordances.add("LEAK:JAVA_DESERIALIZATION_ACTIVE")
                    affordances.add("SIG:JAVA_STREAM_DETECTED")
                if "Django" in response or "django" in response:
                    affordances.add("SIG:DJANGO_DETECTED")
                if "Werkzeug" in response or "WSGI" in response:
                    affordances.add("SIG:WERKZEUG_DETECTED")
                    affordances.add("LEAK:WERKZEUG_DEBUG")
                if "SQL syntax" in response or "ORA-" in response or "PostgreSQL" in response:
                    affordances.add("SIG:SQL_ERROR_DETECTED")
                    affordances.add("SQLI_VULNERABLE")
                if "at " in response and "(" in response and ")" in response:
                    affordances.add("SIG:STACK_TRACE_LEAKED")

            if response == "CONN_REFUSED":
                affordances.add(f"PORT_REJECTED:{vec_name}")
            elif response == "CONN_TIMEOUT":
                affordances.add(f"PORT_HUNG:{vec_name}")
                affordances.add("SIG:TIMEOUT_ON_ANOMALY")
            elif response.startswith("SOCKET_ERR"):
                affordances.add(f"PORT_DROPPED:{vec_name}")

        vector_responded = [k for k, v in results.items()
                            if v not in ("EMPTY_ACK", "CONN_REFUSED", "CONN_TIMEOUT")
                            and not v.startswith("SOCKET_ERR")]

        if vector_responded:
            constraints["responding_vectors"] = ",".join(vector_responded)
        else:
            affordances.add("PORT_MUTE_ON_ALL_VECTORS")

        return ConstraintDelta(
            new_affordances=affordances,
            new_constraints=set(constraints.values()) if constraints else set(),
            resolved_unknowns={"service_identity_unknown"} if "SIGNATURE_ACQUIRED" in affordances else set(),
            evidence=evidence,
        )