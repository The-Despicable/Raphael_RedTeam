"""ErrorDiagnoser — classifies executor failures for clean negative cache entries."""
from __future__ import annotations
import re
from dataclasses import dataclass


@dataclass
class Diagnosis:
    """Classification of a technique execution failure."""
    failure_class: str  # "permission" | "timeout" | "unavailable" | "server_error" | "tool_missing" | "protocol_error"
    is_permanent: bool
    detail: str = ""
    suggests_blocker: str | None = None  # constraint to add to target model


class ErrorDiagnoser:
    """
    Classifies failure signals from tool stderr/stdout into structured diagnoses.
    Used by the executor to build clean FailureRecords for the negative cache.
    """

    PATTERNS: list[tuple[re.Pattern, str, bool, str | None]] = [
        # Permission / access denied (permanent — won't change)
        (re.compile(r'access denied', re.I), "permission", True, None),
        (re.compile(r'NT_STATUS_ACCESS_DENIED', re.I), "permission", True, "smb_access_denied"),
        (re.compile(r'NT_STATUS_LOGON_FAILURE', re.I), "permission", True, "smb_auth_required"),
        (re.compile(r'Authentication failed', re.I), "permission", True, None),
        (re.compile(r'Login incorrect', re.I), "permission", True, None),
        (re.compile(r'authorization failed', re.I), "permission", True, None),
        (re.compile(r'Permission denied', re.I), "permission", True, None),
        
        # Connection refused / unavailable (transient — might change)
        (re.compile(r'Connection refused', re.I), "unavailable", False, None),
        (re.compile(r'No route to host', re.I), "unavailable", False, None),
        (re.compile(r'Network is unreachable', re.I), "unavailable", False, None),
        (re.compile(r'connect failed', re.I), "unavailable", False, None),
        (re.compile(r'Connection timed out', re.I), "unavailable", False, None),
        (re.compile(r'No answer', re.I), "unavailable", False, None),
        
        # Timeout (transient)
        (re.compile(r'timed? ?out', re.I), "timeout", False, None),
        (re.compile(r'Timeout', re.I), "timeout", False, None),
        (re.compile(r'read timed out', re.I), "timeout", False, None),
        
        # Tool missing (permanent for this environment)
        (re.compile(r'not found', re.I), "tool_missing", True, None),
        (re.compile(r'command not found', re.I), "tool_missing", True, None),
        (re.compile(r'No such file', re.I), "tool_missing", True, None),
        
        # Protocol errors (might indicate version mismatch)
        (re.compile(r'protocol error', re.I), "protocol_error", False, None),
        (re.compile(r'protocol version mismatch', re.I), "protocol_error", False, None),
        (re.compile(r'negotiation failed', re.I), "protocol_error", False, "smb_protocol_mismatch"),
        
        # WAF / rate limiting
        (re.compile(r'rate limit', re.I), "server_error", False, None),
        (re.compile(r'too many requests', re.I), "server_error", False, None),
        (re.compile(r'403 forbidden', re.I), "permission", True, "http_forbidden"),
        (re.compile(r'503 service unavailable', re.I), "unavailable", False, None),
    ]

    def diagnose(self, technique: str, returncode: int,
                 stdout: str, stderr: str) -> Diagnosis:
        """
        Analyze the output of a failed technique execution.
        Returns a structured Diagnosis.
        """
        combined = f"{stderr}\n{stdout}"
        
        for pattern, failure_class, is_permanent, blocker in self.PATTERNS:
            if pattern.search(combined):
                return Diagnosis(
                    failure_class=failure_class,
                    is_permanent=is_permanent,
                    detail=f"{technique}: {pattern.pattern[:60]}",
                    suggests_blocker=blocker,
                )
        
        # Generic classification based on return code
        if returncode == -127:
            return Diagnosis("tool_missing", True, f"{technique}: tool not found in PATH")
        elif returncode == -1:
            return Diagnosis("unavailable", False, f"{technique}: generic failure")
        elif returncode > 0:
            return Diagnosis("server_error", False, f"{technique}: exit code {returncode}")
        
        return Diagnosis("unknown", False, f"{technique}: no pattern matched")


# Singleton
_diagnoser: ErrorDiagnoser | None = None

def get_diagnoser() -> ErrorDiagnoser:
    global _diagnoser
    if _diagnoser is None:
        _diagnoser = ErrorDiagnoser()
    return _diagnoser
