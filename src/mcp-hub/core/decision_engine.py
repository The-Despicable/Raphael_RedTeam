import json
import logging
from typing import Optional

logger = logging.getLogger("mcp_hub.decision_engine")

TOOL_CHAINS = {
    "web_recon": ["subfinder", "httpx", "whatweb", "nuclei", "gobuster", "feroxbuster", "sqlmap"],
    "network_recon": ["nmap", "masscan", "rustscan"],
    "vuln_scan": ["nuclei", "nikto", "wpscan"],
    "exploit": ["searchsploit", "metasploit", "sqlmap"],
    "ad_pentest": ["netexec", "bloodhound", "certipy", "kerbrute"],
    "cloud_audit": ["prowler", "scout-suite", "trivy"],
}


class DecisionEngine:
    def __init__(self, registry=None):
        self.registry = registry

    def classify_target(self, target: str) -> list[str]:
        target_lower = target.lower()
        if target_lower.startswith(("http://", "https://")):
            return ["web_recon", "vuln_scan", "exploit"]
        if any(cidr in target_lower for cidr in ("/", "10.", "172.", "192.168.")):
            return ["network_recon", "ad_pentest"]
        if any(cloud in target_lower for cloud in ("aws", "azure", "gcp", "cloud")):
            return ["cloud_audit"]
        if "." in target_lower and not target_lower.startswith("192."):
            return ["web_recon", "vuln_scan"]
        return ["network_recon"]

    def recommend_chain(self, target: str, context: Optional[dict] = None) -> list[dict]:
        chains = self.classify_target(target)
        result = []
        seen = set()
        for chain_name in chains:
            for tool_name in TOOL_CHAINS.get(chain_name, []):
                if tool_name not in seen and self.registry and self.registry.get_tool(tool_name):
                    seen.add(tool_name)
                    result.append({
                        "tool": tool_name,
                        "chain": chain_name,
                        "priority": len(result) + 1,
                    })
        return result

    def optimize_params(self, tool_name: str, target: str, base_params: Optional[dict] = None) -> dict:
        params = dict(base_params or {})
        if tool_name == "nmap":
            if not params.get("ports"):
                params["ports"] = "80,443,8080" if "http" in target.lower() else "1-1000"
            params["service_detection"] = True
        elif tool_name == "gobuster" or tool_name == "feroxbuster":
            if not params.get("url"):
                params["url"] = target if target.startswith("http") else f"https://{target}"
        elif tool_name == "nuclei":
            params["target"] = target
            if not params.get("severity"):
                params["severity"] = "medium"
        return params
