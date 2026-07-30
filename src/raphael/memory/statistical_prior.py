"""Statistical prior — default technique value estimates when no episodic memory exists."""
from typing import Optional

# Default priors by category
DEFAULT_PRIORS = {
    "recon": 0.6,   # curiosity before aggression
    "exploit": 0.3, # don't attack until you understand
}

# Per-technique priors (overrides category default)
TECHNIQUE_PRIORS: dict[str, float] = {
    "port_scan": 0.7,     # Always start here
    "service_scan": 0.6,   # After port scan
    "dns_lookup": 0.55,    # Cheap, passive, high value
    "smb_null_session": 0.4,
    "http_dirbust": 0.35,
    "sqlmap_check": 0.25,  # Noisy, specific prereqs
}


def expected_value(technique_name: str, category: str) -> float:
    """
    Get the expected value of a technique.
    Uses per-technique prior if available, else category default.
    """
    return TECHNIQUE_PRIORS.get(technique_name, DEFAULT_PRIORS.get(category, 0.3))
