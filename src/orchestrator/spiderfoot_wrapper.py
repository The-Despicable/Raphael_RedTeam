"""SpiderFoot OSINT wrapper."""

import logging

logger = logging.getLogger("spiderfoot_wrapper")


class SpiderFootWrapper:
    def __init__(self):
        self._available = False

    def scan(self, target: str, modules: str = "sfp_dnsresolve,sfp_whois") -> dict:
        logger.info(f"SpiderFoot scan requested for {target} (modules={modules})")
        return {
            "status": "unavailable",
            "target": target,
            "note": "SpiderFoot not installed",
        }
