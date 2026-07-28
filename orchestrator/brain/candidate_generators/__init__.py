"""
Candidate Generators — produce Candidate dicts for the Planner to score and select.

Architecture:
    CandidateGenerator → list[dict] → Planner.decide(candidates)
    
Every candidate dict follows a standard format:
    {
        "action_type": str,      # e.g., "http_get", "scan", "direct_probe"
        "capability": str,       # tool name, e.g., "curl", "nmap"
        "target": str,           # IP, hostname, or entity identifier
        "method": str,           # e.g., "auto", "quick", "all"
        "action_id": str,        # unique identifier for this candidate
        "rationale": str,        # human-readable explanation
        "impact_estimate": float,  # estimated CVSS-like impact (0-10)
        "confidence": float,     # how confident the generator is (0-1)
        "technique_id": str,     # the vulnerability/technique being tested
        "candidate_origin": str, # "STUDENT", "BASE", "DEFEATER", etc.
    }

Generators are registered by discovery (any .py file in this directory).
"""
