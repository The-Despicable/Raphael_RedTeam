"""
StackMatcher — Fuzzy target stack signature matching for THE STUDENT.

Takes a target's technology stack (identified via OSINT) and matches
it against the Knowledge Base's known vulnerability patterns using
partial overlap scoring — not exact version matching.
"""

import logging
from typing import Any, Optional

logger = logging.getLogger("student.stack_matcher")


class StackMatcher:
    """
    Fuzzy stack signature matcher.
    
    Given a target's technology components (e.g., ["nginx", "django", "postgresql", "jwt", "aws"]),
    matches against known vulnerability patterns using partial overlap scoring.
    """

    def __init__(self, growth_db=None):
        self._growth_db = growth_db
        self._signatures: list[dict] = []
        self._load_signatures()

    def _load_signatures(self):
        """Load known target signatures from GrowthDB and built-in patterns."""
        # Pre-loaded signatures from case study and technique data
        self._signatures = [
            {
                "id": "sig_nginx_django_jwt",
                "components": {"nginx", "django", "python", "jwt"},
                "label": "nginx + Django + JWT",
                "vulnerabilities": [
                    {"technique_id": "jwt_alg_none", "probability": 0.65,
                     "notes": "Common on unpatched Django REST Framework"},
                    {"technique_id": "ssrf_imds_aws", "probability": 0.50,
                     "notes": "If URL param reaches internal service"},
                    {"technique_id": "idor_parameter_manipulation", "probability": 0.70,
                     "notes": "API likely uses sequential IDs"},
                ],
            },
            {
                "id": "sig_nextjs_aws",
                "components": {"nextjs", "nodejs", "react", "aws"},
                "label": "Next.js + AWS",
                "vulnerabilities": [
                    {"technique_id": "nextjs_middleware_bypass_2025", "probability": 0.75,
                     "notes": "If Next.js < 15.2.3 with middleware auth"},
                    {"technique_id": "nextjs_ssrf_server_actions", "probability": 0.50,
                     "notes": "If server actions enabled"},
                    {"technique_id": "ssrf_imds_aws", "probability": 0.60,
                     "notes": "SSRF + AWS = cloud credential exposure"},
                ],
            },
            {
                "id": "sig_nginx_php_mysql",
                "components": {"nginx", "php", "mysql", "linux"},
                "label": "nginx + PHP + MySQL (LAMP)",
                "vulnerabilities": [
                    {"technique_id": "sqli_union_basic", "probability": 0.75,
                     "notes": "Classic LAMP SQL injection"},
                    {"technique_id": "lfi_rfi", "probability": 0.60,
                     "notes": "PHP file inclusion common"},
                    {"technique_id": "file_upload_shell", "probability": 0.55,
                     "notes": "Upload form + writable upload dir"},
                ],
            },
            {
                "id": "sig_iis_windows_sqlserver",
                "components": {"iis", "windows", "sqlserver", "asp"},
                "label": "IIS + Windows + MSSQL",
                "vulnerabilities": [
                    {"technique_id": "sqli_union_basic", "probability": 0.70,
                     "notes": "ASP.NET + MSSQL = classic SQLi"},
                    {"technique_id": "httperf_overflow_rce", "probability": 0.40,
                     "notes": "If unpatched before July 2026"},
                ],
            },
            {
                "id": "sig_glassfish_java",
                "components": {"glassfish", "java", "admin"},
                "label": "GlassFish + Java",
                "vulnerabilities": [
                    {"technique_id": "glassfish_el_injection", "probability": 0.80,
                     "notes": "Admin console gadget handler exposure"},
                ],
            },
            {
                "id": "sig_aws_cloud",
                "components": {"aws", "s3", "lambda", "api_gateway", "ec2"},
                "label": "AWS Cloud Native",
                "vulnerabilities": [
                    {"technique_id": "ssrf_imds_aws", "probability": 0.70,
                     "notes": "IMDSv1 exposure via SSRF"},
                    {"technique_id": "s3_bucket_misconfig", "probability": 0.65,
                     "notes": "Public S3 bucket enumeration"},
                    {"technique_id": "aws_iam_privesc", "probability": 0.50,
                     "notes": "IAM role trust policy abuse"},
                ],
            },
            {
                "id": "sig_ad_windows",
                "components": {"windows", "ad", "ldap", "kerberos", "dns"},
                "label": "Active Directory",
                "vulnerabilities": [
                    {"technique_id": "kerberoasting", "probability": 0.80,
                     "notes": "SPN service account hash extraction"},
                    {"technique_id": "asrep_roast", "probability": 0.70,
                     "notes": "Users without pre-auth"},
                    {"technique_id": "bloodhound_path", "probability": 0.85,
                     "notes": "AD attack path mapping"},
                ],
            },
        ]

        # Try to load additional signatures from GrowthDB
        if self._growth_db:
            try:
                rows = self._growth_db.conn.execute(
                    "SELECT technique_name, category, description FROM techniques WHERE confidence > 0.6"
                ).fetchall()
                # Group by category to build signature patterns
                category_groups = {}
                for row in rows:
                    cat = row[1] if row[1] else "general"
                    if cat not in category_groups:
                        category_groups[cat] = []
                    category_groups[cat].append(row[0])

                for cat, techs in category_groups.items():
                    # Derive likely stack components from category name
                    components = set(cat.lower().replace("_", " ").split())
                    sig_id = f"sig_growthdb_{cat.lower().replace(' ', '_')}"
                    if sig_id not in {s["id"] for s in self._signatures}:
                        self._signatures.append({
                            "id": sig_id,
                            "components": components,
                            "label": cat,
                            "vulnerabilities": [
                                {"technique_id": t[:50], "probability": 0.5, "notes": "Auto-derived from KB"}
                                for t in techs[:5]
                            ],
                        })
            except Exception as e:
                logger.debug("Could not load GrowthDB signatures: %s", e)

    def match(self, stack_components: list[str]) -> list[dict]:
        """
        Match a target's technology stack against known signatures.
        
        Args:
            stack_components: List of identified tech components
                e.g., ["nginx", "django", "postgresql", "jwt", "aws"]
        
        Returns:
            Ranked list of matching signatures with matched components and vulnerabilities.
        """
        target_set = set(c.lower().strip() for c in stack_components)
        results = []

        for sig in self._signatures:
            # Calculate overlap score: |intersection| / |signature|
            intersection = target_set & sig["components"]
            if not intersection:
                continue

            overlap_ratio = len(intersection) / max(len(sig["components"]), 1)

            # Calculate precision: what fraction of matched sig components are relevant
            precision = len(intersection) / max(len(target_set), 1)

            # F1 score: harmonic mean of overlap and precision
            if overlap_ratio + precision > 0:
                f1 = 2 * (overlap_ratio * precision) / (overlap_ratio + precision)
            else:
                f1 = 0

            results.append({
                "signature_id": sig["id"],
                "signature_label": sig.get("label", sig["id"]),
                "matched_components": sorted(intersection),
                "unmatched_components": sorted(sig["components"] - intersection),
                "overlap_ratio": round(overlap_ratio, 3),
                "precision": round(precision, 3),
                "f1_score": round(f1, 3),
                "vulnerabilities": [
                    {
                        "technique_id": v["technique_id"],
                        "probability": round(v["probability"] * f1, 3),
                        "notes": v["notes"],
                    }
                    for v in sig["vulnerabilities"]
                ],
            })

        # Sort by F1 score descending
        results.sort(key=lambda r: r["f1_score"], reverse=True)

        return results

    def get_ranked_hypotheses(self, stack_components: list[str]) -> list[dict]:
        """
        Generate a ranked hypothesis list from stack match results.
        
        Returns each vulnerability hypothesis scored by (match_f1 × probability × impact).
        """
        matches = self.match(stack_components)
        hypotheses = []

        for match in matches:
            for vuln in match["vulnerabilities"]:
                # Estimate impact from technique_id keywords
                impact = self._estimate_impact(vuln["technique_id"])
                confidence = match["f1_score"] * vuln["probability"]

                hypotheses.append({
                    "technique_id": vuln["technique_id"],
                    "signature": match["signature_label"],
                    "matched_components": match["matched_components"],
                    "confidence": round(confidence, 3),
                    "estimated_impact": impact,
                    "rank": round(confidence * (impact / 10.0), 3),
                    "notes": vuln["notes"],
                })

        # Sort by rank descending
        hypotheses.sort(key=lambda h: h["rank"], reverse=True)

        return hypotheses

    def _estimate_impact(self, technique_id: str) -> float:
        """Estimate CVSS impact from technique ID keywords."""
        impact_map = {
            "rce": 9.8,
            "remote_code_execution": 9.8,
            "sqli": 8.5,
            "sql_injection": 8.5,
            "ssrf": 8.5,
            "auth_bypass": 8.0,
            "authentication_bypass": 8.0,
            "idor": 7.5,
            "lfi": 7.0,
            "file_read": 6.5,
            "xss": 6.0,
            "info_disclosure": 5.0,
            "cloud": 9.0,
            "privesc": 8.0,
            "privilege_escalation": 8.0,
        }
        tid_lower = technique_id.lower()
        for keyword, impact in impact_map.items():
            if keyword in tid_lower:
                return impact
        return 7.0  # default medium-high

    def add_signature(self, signature: dict):
        """Add a new target signature to the matcher."""
        sig_id = signature.get("id", f"sig_{len(self._signatures)}")
        sig_id = sig_id.replace(" ", "_")
        signature["id"] = sig_id
        self._signatures.append(signature)
        logger.info("[StackMatcher] Added signature: %s (%d components)",
                     sig_id, len(signature.get("components", [])))

    def stats(self) -> dict:
        return {
            "signatures": len(self._signatures),
            "technique_patterns": sum(len(s.get("vulnerabilities", [])) for s in self._signatures),
        }
