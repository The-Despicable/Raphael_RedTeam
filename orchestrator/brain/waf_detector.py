"""
WAF Detector & Fingerprinter for P1 Stealth & Evasion.

Detects WAF presence and type by sending probe requests and analyzing responses.
Used by Student to select WAF-specific payload variants.
"""

import re
import asyncio
import aiohttp
import logging
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from enum import Enum

logger = logging.getLogger(__name__)


class WAFType(str, Enum):
    """Known WAF types."""
    CLOUDFLARE = "cloudflare"
    AWS_WAF = "aws_waf"
    AKAMAI = "akamai"
    MODSECURITY = "modsecurity"
    IMPERVA = "imperva"
    F5_ASM = "f5_asm"
    BARRACUDA = "barracuda"
    UNKNOWN = "unknown"
    NONE = "none"


@dataclass
class WAFSignature:
    """WAF detection signature."""
    name: WAFType
    headers: List[Tuple[str, str]] = None
    body_patterns: List[str] = None
    status_codes: List[int] = None
    cookies: List[str] = None

    def __post_init__(self):
        if self.headers is None:
            self.headers = []
        if self.body_patterns is None:
            self.body_patterns = []
        if self.status_codes is None:
            self.status_codes = []
        if self.cookies is None:
            self.cookies = []


# Pre-defined WAF signatures
WAF_SIGNATURES = [
    WAFSignature(
        name=WAFType.CLOUDFLARE,
        headers=[
            ("server", r"cloudflare"),
            ("cf-ray", r".+"),
            ("cf-cache-status", r".+"),
            ("cf-request-id", r".+"),
        ],
        body_patterns=[
            r"__cf_chl_",
            r"cf-browser-verification",
            r"cloudflare.*ray.*id",
            r"attention required.*cloudflare",
        ],
        cookies=[
            "__cf_bm",
            "__cfduid",
            "cf_clearance",
        ],
    ),
    WAFSignature(
        name=WAFType.AWS_WAF,
        headers=[
            ("x-amzn-requestid", r".+"),
            ("x-amzn-trace-id", r".+"),
            ("x-amz-cf-id", r".+"),
        ],
        body_patterns=[
            r"RequestBlocked",
            r"AWS.*WAF",
            r"Bad Request.*Blocked",
            r"The request could not be satisfied",
        ],
        status_codes=[403, 406],
    ),
    WAFSignature(
        name=WAFType.AKAMAI,
        headers=[
            ("server", r"akamaighost"),
            ("x-akamai-transformed", r".+"),
        ],
        body_patterns=[
            r"Reference #[\da-f]+",
            r"Akamai.*Reference",
            r"access denied.*akamai",
        ],
        status_codes=[403],
    ),
    WAFSignature(
        name=WAFType.MODSECURITY,
        headers=[
            ("server", r"mod_security"),
        ],
        body_patterns=[
            r"ModSecurity",
            r"mod_security",
            r"406 Not Acceptable",
            r"Blocking Rule.*Matched",
        ],
        status_codes=[403, 406, 501],
    ),
    WAFSignature(
        name=WAFType.IMPERVA,
        headers=[
            ("x-iinfo", r".+"),
            ("x-cdn", r"imperva"),
        ],
        body_patterns=[
            r"incapsula",
            r"imperva",
            r"Incapsula incident ID",
            r"Blocked by.*Incapsula",
        ],
        status_codes=[403, 509],
    ),
    WAFSignature(
        name=WAFType.F5_ASM,
        headers=[
            ("server", r"f5"),
            ("x-waf", r".+"),
        ],
        body_patterns=[
            r"ASM.*blocked",
            r"F5.*blocked",
            r"The requested URL was rejected",
            r"support ID",
        ],
        status_codes=[403, 406],
    ),
    WAFSignature(
        name=WAFType.BARRACUDA,
        headers=[
            ("server", r"barracuda"),
        ],
        body_patterns=[
            r"Barracuda",
            r"barracuda",
            r"WEB APPLICATION FIREWALL",
        ],
        status_codes=[403, 406],
    ),
]


class WAFDetector:
    """
    Detects WAF presence and type by sending probe requests.
    
    Performs non-invasive fingerprinting:
    1. Normal GET request to check headers/cookies
    2. Optional benign probe (X-Forwarded-For: 127.0.0.1) to trigger WAF
    3. Analyzes response headers, cookies, body, and status codes
    
    Results cached per target for 5 minutes.
    """
    
    def __init__(self, timeout: float = 10.0, cache_ttl: int = 300):
        self.timeout = timeout
        self.cache_ttl = cache_ttl
        self._cache: Dict[str, Tuple[WAFType, float]] = {}
        self._session: Optional[aiohttp.ClientSession] = None
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session."""
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            self._session = aiohttp.ClientSession(timeout=timeout)
        return self._session
    
    async def close(self):
        """Close the session."""
        if self._session and not self._session.closed:
            await self._session.close()
    
    async def fingerprint(self, target: str) -> Dict:
        """
        Fingerprint WAF for a target.
        
        Returns dict with:
            - waf_type: detected WAFType
            - confidence: confidence score 0-1
            - details: dict with matched signatures
        """
        # Check cache
        cached = self._cache.get(target)
        if cached and (time.time() - cached[1]) < self.cache_ttl:
            waf_type = cached[0]
            return {
                "waf_type": waf_type,
                "confidence": 0.9,
                "details": {"source": "cache"},
                "cached": True
            }
        
        session = await self._get_session()
        results = []
        
        # Try both HTTP and HTTPS
        for scheme in ("https", "http"):
            url = f"{scheme}://{target}"
            try:
                # Probe 1: Normal request
                async with session.get(url, allow_redirects=True) as resp:
                    headers = {k.lower(): v for k, v in resp.headers.items()}
                    body = await resp.text()
                    status = resp.status
                    cookies = list(resp.cookies.keys())
                    
                    waf_type, confidence, matched = self._analyze_response(
                        headers, body, status, cookies
                    )
                    results.append({
                        "scheme": scheme,
                        "waf_type": waf_type,
                        "confidence": confidence,
                        "matched": matched,
                        "status": status
                    })
                    
                    if waf_type != WAFType.NONE:
                        # WAF found, cache and return
                        self._cache[target] = (waf_type, time.time())
                        return {
                            "waf_type": waf_type,
                            "confidence": confidence,
                            "details": {"scheme": scheme, "matched": matched, "status": status},
                            "cached": False
                        }
                
                # Probe 2: Benign probe with X-Forwarded-For (only if no WAF found)
                if waf_type == WAFType.NONE:
                    probe_headers = {"X-Forwarded-For": "127.0.0.1"}
                    async with session.get(url, headers=probe_headers, allow_redirects=True) as resp:
                        headers = {k.lower(): v for k, v in resp.headers.items()}
                        body = await resp.text()
                        status = resp.status
                        cookies = list(resp.cookies.keys())
                        
                        waf_type, confidence, matched = self._analyze_response(
                            headers, body, status, cookies
                        )
                        results.append({
                            "scheme": scheme,
                            "waf_type": waf_type,
                            "confidence": confidence,
                            "matched": matched,
                            "status": status,
                            "probe": "x-forwarded-for"
                        })
                        
                        if waf_type != WAFType.NONE:
                            self._cache[target] = (waf_type, time.time())
                            return {
                                "waf_type": waf_type,
                                "confidence": confidence,
                                "details": {"scheme": scheme, "matched": matched, "status": status, "probe": "x-forwarded-for"},
                                "cached": False
                            }
            
            except asyncio.TimeoutError:
                results.append({"scheme": scheme, "error": "timeout"})
            except Exception as e:
                logger.debug(f"WAF fingerprint error for {target} ({scheme}): {e}")
                results.append({"scheme": scheme, "error": str(e)})
        
        # No WAF detected
        self._cache[target] = (WAFType.NONE, time.time())
        return {
            "waf_type": WAFType.NONE,
            "confidence": 0.5,
            "details": {"results": results},
            "cached": False
        }
    
    def _analyze_response(
        self, 
        headers: Dict[str, str], 
        body: str, 
        status: int, 
        cookies: List[str]
    ) -> Tuple[WAFType, float, Dict]:
        """Analyze response against known WAF signatures."""
        best_match = WAFType.NONE
        best_confidence = 0.0
        best_details = {}
        
        for sig in WAF_SIGNATURES:
            score = 0
            max_score = 0
            matched = {}
            
            # Check headers
            for header_name, pattern in sig.headers:
                max_score += 1
                header_val = headers.get(header_name.lower(), "")
                if re.search(pattern, header_val, re.IGNORECASE):
                    score += 1
                    matched.setdefault("headers", []).append(header_name)
            
            # Check cookies
            for cookie_pattern in sig.cookies:
                max_score += 1
                if any(re.search(cookie_pattern, c, re.IGNORECASE) for c in cookies):
                    score += 1
                    matched.setdefault("cookies", []).append(cookie_pattern)
            
            # Check body patterns
            for body_pattern in sig.body_patterns:
                max_score += 1
                if re.search(body_pattern, body, re.IGNORECASE):
                    score += 1
                    matched.setdefault("body", []).append(body_pattern)
            
            # Check status codes
            if sig.status_codes:
                max_score += 1
                if status in sig.status_codes:
                    score += 1
                    matched.setdefault("status", []).append(status)
            
            if max_score > 0:
                confidence = score / max_score
                if confidence > best_confidence:
                    best_confidence = confidence
                    best_match = sig.name
                    best_details = {"matched": matched, "score": score, "max": max_score}
        
        return best_match, best_confidence, best_details
    
    def select_payload_variant(self, waf_type: WAFType, technique: str) -> str:
        """
        Select appropriate payload variant based on WAF type and technique.
        
        Returns encoded payload string.
        """
        if waf_type == WAFType.NONE:
            return ""  # Use default payload
        
        # WAF-specific encoding strategies
        strategies = {
            WAFType.CLOUDFLARE: {
                "sqli": ["double_url_encode", "case_vary", "comment_insert"],
                "xss": ["double_url_encode", "hex_encode", "base64_wrap"],
                "rce": ["double_url_encode", "whitespace_obfuscate"],
            },
            WAFType.AWS_WAF: {
                "sqli": ["double_url_encode", "case_vary", "hex_encode"],
                "xss": ["double_url_encode", "base64_wrap", "charset_bypass"],
                "rce": ["double_url_encode", "whitespace_obfuscate"],
            },
            WAFType.AKAMAI: {
                "sqli": ["case_vary", "comment_insert", "whitespace_obfuscate"],
                "xss": ["hex_encode", "charset_bypass"],
                "rce": ["double_url_encode", "case_vary"],
            },
            WAFType.MODSECURITY: {
                "sqli": ["comment_insert", "whitespace_obfuscate", "hex_encode"],
                "xss": ["double_url_encode", "hex_encode", "charset_bypass"],
                "rce": ["double_url_encode", "comment_insert"],
            },
            WAFType.IMPERVA: {
                "sqli": ["double_url_encode", "case_vary", "hex_encode"],
                "xss": ["base64_wrap", "charset_bypass"],
                "rce": ["double_url_encode", "whitespace_obfuscate"],
            },
        }
        
        waf_strategies = strategies.get(waf_type, {})
        technique_strategies = waf_strategies.get(technique, ["double_url_encode"])
        
        return technique_strategies[0]  # Return primary strategy name
    
    def clear_cache(self):
        """Clear fingerprint cache."""
        self._cache.clear()


# Synchronous wrapper for simple usage
class SyncWAFDetector:
    """Synchronous wrapper for WAFDetector."""
    
    def __init__(self, timeout: float = 10.0):
        self.detector = WAFDetector(timeout=timeout)
    
    def fingerprint(self, target: str) -> Dict:
        """Synchronous fingerprint."""
        return asyncio.run(self.detector.fingerprint(target))
    
    def select_payload_variant(self, waf_type: WAFType, technique: str) -> str:
        return self.detector.select_payload_variant(waf_type, technique)
    
    def close(self):
        """Close session."""
        asyncio.run(self.detector.close())


if __name__ == "__main__":
    # Quick self-test with mock
    print("=== WAF DETECTOR SELF-TEST ===")
    
    # Test _analyze_response with mock data
    detector = SyncWAFDetector()
    
    # Test Cloudflare detection
    headers = {"server": "cloudflare", "cf-ray": "12345"}
    body = "Attention Required! Cloudflare"
    waf_type, conf, details = detector.detector._analyze_response(headers, body, 403, ["__cf_bm"])
    print(f"Cloudflare test: {waf_type} (confidence: {conf:.2f})")
    assert waf_type == WAFType.CLOUDFLARE
    
    # Test AWS WAF
    headers = {"x-amzn-requestid": "abc"}
    body = "The request could not be satisfied. RequestBlocked"
    waf_type, conf, details = detector.detector._analyze_response(headers, body, 403, [])
    print(f"AWS WAF test: {waf_type} (confidence: {conf:.2f})")
    assert waf_type == WAFType.AWS_WAF
    
    # Test Akamai
    headers = {"server": "AkamaiGHost"}
    body = "Reference #1234567890abcdef"
    waf_type, conf, details = detector.detector._analyze_response(headers, body, 403, [])
    print(f"Akamai test: {waf_type} (confidence: {conf:.2f})")
    assert waf_type == WAFType.AKAMAI
    
    # Test ModSecurity
    headers = {"server": "Mod_Security"}
    body = "ModSecurity blocked the request"
    waf_type, conf, details = detector.detector._analyze_response(headers, body, 406, [])
    print(f"ModSecurity test: {waf_type} (confidence: {conf:.2f})")
    assert waf_type == WAFType.MODSECURITY
    
    # Test no WAF
    headers = {"server": "nginx/1.20"}
    body = "Welcome to nginx!"
    waf_type, conf, details = detector.detector._analyze_response(headers, body, 200, [])
    print(f"No WAF test: {waf_type} (confidence: {conf:.2f})")
    assert waf_type == WAFType.NONE
    
    # Test payload variant selection
    strategy = detector.select_payload_variant(WAFType.CLOUDFLARE, "sqli")
    print(f"Cloudflare SQLi strategy: {strategy}")
    assert strategy == "double_url_encode"
    
    strategy = detector.select_payload_variant(WAFType.AWS_WAF, "xss")
    print(f"AWS WAF XSS strategy: {strategy}")
    assert strategy == "double_url_encode"
    
    strategy = detector.select_payload_variant(WAFType.NONE, "sqli")
    print(f"No WAF strategy: '{strategy}'")
    assert strategy == ""
    
    detector.close()
    
    print("\n=== ALL TESTS PASSED ===")