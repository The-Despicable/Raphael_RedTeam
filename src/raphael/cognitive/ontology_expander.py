"""
Ontology Expander — Pure functional ephemeral affordance minting.
Classmethod interface. No state. Called by Executor after blind_probe.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Dict, Set, Optional

from raphael.models.target_model import ConstraintDelta, DomainState

logger = logging.getLogger("raphael.ontology_expander")


class OntologyExpander:
    """Mints ephemeral affordances from blind_probe raw signatures."""

    # Anomaly signature → affordance mapping
    ANOMALY_SIGNATURES: dict[str, re.Pattern] = {
        "SPRING_BOOT_SPEL_EVAL": re.compile(
            r"SpELParseException|org\.springframework\.expression\.spel"
        ),
        "JAVA_DESERIALIZATION_ACTIVE": re.compile(
            r"StreamCorruptedException|ObjectInputStream|java\.io\.(?!Object)"
        ),
        "WERKZEUG_DEBUG": re.compile(
            r"Werkzeug|Debugger|WSGI\s+Server"
        ),
        "EXPRESS_JS_LEAK": re.compile(
            r"at\s+Layer\.handle|Express|Node\.js"
        ),
        "DJANGO_DEBUG": re.compile(
            r"Django.*Traceback|django\.core"
        ),
        "FLASK_DEBUG": re.compile(
            r"Flask.*Debugger|flask\.app"
        ),
        "GENERIC_SQL_ERR": re.compile(
            r"(SQL\s+syntax|ORA-\d{5}|PostgreSQL\s+query\s+failed|mysql_fetch)"
        ),
        "RAILS_DEBUG": re.compile(
            r"Rails|ruby.*error|ActionController"
        ),
        "TOMCAT_LEAK": re.compile(
            r"Apache\s+Tomcat|org\.apache\.catalina"
        ),
        "NGINX_ERROR": re.compile(
            r"nginx/\d+\.\d+\.\d+|400\s+Bad\s+Request|414\s+Request-URI\s+Too\s+Large"
        ),
    }

    @classmethod
    def mint_affordances(
        cls,
        raw_output: str,
        domain_state: Optional[DomainState] = None,
    ) -> ConstraintDelta:
        """
        Process raw blind_probe output. Mint new affordances from signatures.
        
        Args:
            raw_output: JSON string from blind_probe runner
            domain_state: Optional domain state for deduplication
            
        Returns:
            ConstraintDelta with minted ephemeral affordances
        """
        new_affordances: Set[str] = set()
        new_constraints: Set[str] = set()

        # Parse JSON if structured
        results = {}
        try:
            results = json.loads(raw_output) if raw_output.strip().startswith("{") else {}
        except json.JSONDecodeError:
            pass

        # Process each probe response
        probe_responses = []
        if results and isinstance(results, dict):
            for vec_name, response in results.items():
                cls._check_signatures(response, vec_name, new_affordances, new_constraints)
                probe_responses.append(response)
        else:
            # Raw output — treat as single response
            cls._check_signatures(raw_output, "raw", new_affordances, new_constraints)
            probe_responses = [raw_output]

        # Dynamic ephemeral minting (heuristic capability inference)
        for response in probe_responses:
            if not isinstance(response, str):
                continue

            # JSON parser active if malformed JSON didn't crash
            if "json_recursion_depth" in str(probe_responses):
                if "Exception" not in response and "SOCKET_ERR" not in response:
                    new_affordances.add("JSON_PARSER_ACTIVE")

            # Custom binary protocol
            if len(response) > 10 and "SOCKET_ERR" not in response and "EMPTY_ACK" not in response:
                non_printable = sum(1 for c in response[:16] if ord(c) < 0x20 and ord(c) not in (0x0a, 0x0d))
                if non_printable > 4:
                    header_hex = response[:8].encode("utf-8", "ignore").hex()
                    new_affordances.add(f"CUSTOM_PROTO_{header_hex}")

            # Template engine active
            if "polyglot_rupture" in str(probe_responses):
                if "500" in response or "Error" in response:
                    new_affordances.add("TEMPLATE_EVAL_ACTIVE")

            # Chunked parser
            if "desync_allocator" in str(probe_responses):
                if "timeout" in response.lower() or "CONN_TIMEOUT" in response:
                    new_affordances.add("CHUNKED_PARSER_ACTIVE")

        # Deduplicate
        if domain_state:
            actual_new = new_affordances - domain_state.affordances
        else:
            actual_new = new_affordances

        if actual_new:
            logger.info(f"OntologyExpander: minted {len(actual_new)} ephemeral affordances: {actual_new}")

        return ConstraintDelta(
            new_affordances=actual_new,
            new_constraints=new_constraints,
            evidence=raw_output[:2000],
        )

    @classmethod
    def _check_signatures(
        cls,
        response: str,
        vector_name: str,
        affordances: Set[str],
        constraints: Set[str],
    ) -> None:
        """Match response against known anomaly signatures."""
        for aff_name, pattern in cls.ANOMALY_SIGNATURES.items():
            if pattern.search(response):
                affordances.add(f"LEAK_{aff_name}")
                logger.debug(f"OntologyExpander: matched {aff_name} in vector {vector_name}")

        # Stack trace heuristic
        if re.search(r'^\s+at\s+', response, re.MULTILINE):
            affordances.add("LEAK_STACK_TRACE")
            affordances.add("STACK_TRACE_LEAKED")