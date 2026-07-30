"""
HTTP POST capability injection — Raphael Technique
Breaks the auth boundary constraint by enabling POST requests.
Registers: check_http_methods (recon), auth_bypass_post (exploit)
"""
from raphael.models.target_model import ConstraintDelta


def http_method_parse(stdout: str, target: str) -> ConstraintDelta:
    """Parse OPTIONS response to detect POST capability."""
    affordances = set()
    constraints = set()
    for line in stdout.splitlines():
        if line.lower().startswith("allow:"):
            if "post" in line.lower():
                affordances.add("CAN_HTTP_POST")
                affordances.add("http_post_enabled")
            if "put" in line.lower():
                affordances.add("CAN_HTTP_PUT")
            if "delete" in line.lower():
                affordances.add("CAN_HTTP_DELETE")
            if "options" not in line.lower() and "head" not in line.lower():
                affordances.add("http_methods_extended")
    if "CAN_HTTP_POST" not in affordances:
        constraints.add("http_post_disabled")
    return ConstraintDelta(
        new_affordances=affordances,
        new_constraints=constraints,
        resolved_unknowns={"http_post_unknown"},
        evidence=stdout[:1000],
    )


def auth_bypass_parse(stdout: str, target: str) -> ConstraintDelta:
    """Parse POST login response to detect auth bypass."""
    affordances = set()
    evidence = stdout[:2000]
    status_code = 0
    for line in stdout.splitlines():
        if line.startswith("HTTP/"):
            parts = line.split()
            if len(parts) > 1:
                try:
                    status_code = int(parts[1])
                except ValueError:
                    pass
            break
    if status_code in (200, 201, 204):
        affordances.add("AUTH_BYPASS_SUCCESS")
        if "Set-Cookie" in stdout or "set-cookie" in stdout.lower():
            affordances.add("SESSION_COOKIE_ISSUED")
    elif status_code == 302:
        affordances.add("AUTH_BYPASS_SUCCESS")
        affordances.add("AUTH_REDIRECT_DETECTED")
        if "Set-Cookie" in stdout or "set-cookie" in stdout.lower():
            affordances.add("SESSION_COOKIE_ISSUED")
    elif status_code == 401:
        affordances.add("AUTH_REQUIRED")
    elif status_code == 403:
        affordances.add("AUTH_FORBIDDEN")
    if "SQL syntax" in evidence or "mysql_fetch" in evidence or "sqlite" in evidence.lower():
        affordances.add("SQLI_VULNERABLE")
    if "syntax" in evidence.lower() and "error" in evidence.lower():
        affordances.add("CMDI_VULNERABLE")
    return ConstraintDelta(
        new_affordances=affordances,
        resolved_unknowns={"login_auth_unknown"},
        evidence=evidence,
    )
