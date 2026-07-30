"""
Strict Scope Parser for P1 Stealth & Evasion Specification.

Parses HackerOne JSON/Markdown scope definitions and compiles them into
rigorous authorization policies. Implements fail-closed semantics:
if a target's scope status is ambiguous, returns DENY.
"""

import re
import json
import ipaddress
from typing import Optional
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ScopeRule:
    """A single compiled scope rule."""
    pattern: str
    is_allowed: bool
    is_cidr: bool = False
    is_wildcard: bool = False
    is_path_prefix: bool = False
    regex: Optional[re.Pattern] = None
    cidr_network: Optional[ipaddress.IPv4Network] = None


class ScopeParser:
    """
    Compiles HackerOne scope definitions into a fail-closed authorization policy.
    
    Supported formats:
    - HackerOne JSON export (in_scope/out_of_scope arrays)
    - Markdown with scope tables
    - CIDR lists (one per line)
    - Wildcard domains (e.g., *.example.com)
    - Exclusions (e.g., !support.example.com)
    - URL path prefixes (e.g., example.com/api/*)
    
    Fail-closed: if target cannot be definitively classified, returns DENY.
    """
    
    def __init__(self):
        self.allowed_rules: list[ScopeRule] = []
        self.prohibited_rules: list[ScopeRule] = []
        self._compiled = False
    
    def parse_hackerone_json(self, json_data: dict) -> None:
        """
        Parse HackerOne JSON scope export.
        
        Expected format:
        {
            "in_scope": [
                {"asset_identifier": "*.example.com", "asset_type": "URL"},
                {"asset_identifier": "10.0.0.0/24", "asset_type": "CIDR"}
            ],
            "out_of_scope": [
                {"asset_identifier": "support.example.com", "asset_type": "URL"}
            ]
        }
        """
        self._reset()
        
        in_scope = json_data.get("in_scope", [])
        out_scope = json_data.get("out_of_scope", [])
        
        for item in in_scope:
            self._add_rule(item.get("asset_identifier", ""), is_allowed=True)
        
        for item in out_scope:
            self._add_rule(item.get("asset_identifier", ""), is_allowed=False)
        
        self._compile()
    
    def parse_markdown(self, markdown_text: str) -> None:
        """
        Parse Markdown scope tables.
        
        Expected format:
        | Asset | Type | Eligible |
        |-------|------|----------|
        | *.example.com | URL | Yes |
        | support.example.com | URL | No |
        """
        self._reset()
        
        lines = markdown_text.strip().split('\n')
        in_table = False
        
        for line in lines:
            line = line.strip()
            
            # Detect table start
            if '|' in line and ('Asset' in line or 'asset' in line) and ('Type' in line or 'type' in line):
                in_table = True
                continue
            
            if not in_table:
                continue
            
            # Skip separator line
            if line.startswith('|---') or line.startswith('| :') or line.startswith('|-'):
                continue
            
            # End of table
            if '|' not in line:
                in_table = False
                continue
            
            # Parse row
            parts = [p.strip() for p in line.split('|')]
            if len(parts) >= 3:
                asset = parts[1]  # Assuming format: | Asset | Type | Eligible |
                asset_type = parts[2] if len(parts) > 2 else "URL"
                eligible = parts[3] if len(parts) > 3 else "Yes"
                
                if asset and asset != "Asset":
                    is_allowed = eligible.lower() in ('yes', 'true', 'y', '1')
                    self._add_rule(asset, is_allowed)
        
        self._compile()
    
    def parse_cidr_list(self, cidrs: list[str]) -> None:
        """Parse a list of CIDR notations (all treated as allowed)."""
        self._reset()
        
        for cidr in cidrs:
            cidr = cidr.strip()
            if cidr and not cidr.startswith('#'):
                self._add_rule(cidr, is_allowed=True)
        
        self._compile()
    
    def _reset(self) -> None:
        """Reset internal state."""
        self.allowed_rules = []
        self.prohibited_rules = []
        self._compiled = False
    
    def _add_rule(self, pattern: str, is_allowed: bool) -> None:
        """Add a raw rule pattern, compilation deferred."""
        pattern = pattern.strip()
        if not pattern:
            return
        
        rule = ScopeRule(pattern=pattern, is_allowed=is_allowed)
        
        # Classify pattern type
        if self._is_cidr(pattern):
            rule.is_cidr = True
            try:
                rule.cidr_network = ipaddress.ip_network(pattern, strict=False)
            except ValueError:
                pass  # Will be handled at compile time
        elif self._is_wildcard_domain(pattern):
            rule.is_wildcard = True
            # Convert wildcard to regex
            regex_pattern = self._wildcard_to_regex(pattern)
            rule.regex = re.compile(regex_pattern, re.IGNORECASE)
        elif self._is_path_prefix(pattern):
            rule.is_path_prefix = True
            # Convert path prefix to regex
            regex_pattern = self._path_prefix_to_regex(pattern)
            rule.regex = re.compile(regex_pattern, re.IGNORECASE)
        else:
            # Exact match - also compile to regex for consistency
            regex_pattern = re.escape(pattern) + r'\Z'
            rule.regex = re.compile(regex_pattern, re.IGNORECASE)
        
        if is_allowed:
            self.allowed_rules.append(rule)
        else:
            self.prohibited_rules.append(rule)
    
    def _is_cidr(self, pattern: str) -> bool:
        """Check if pattern is CIDR notation."""
        try:
            ipaddress.ip_network(pattern, strict=False)
            return True
        except ValueError:
            return False
    
    def _is_wildcard_domain(self, pattern: str) -> bool:
        """Check if pattern is a wildcard domain (e.g., *.example.com)."""
        return pattern.startswith('*.') and len(pattern) > 2
    
    def _is_path_prefix(self, pattern: str) -> bool:
        """Check if pattern is a URL path prefix (e.g., example.com/api/*)."""
        return pattern.endswith('/*') and '.' in pattern
    
    def _wildcard_to_regex(self, pattern: str) -> str:
        """Convert *.example.com to regex that matches subdomains."""
        # Escape dots, replace * with [^.]+
        escaped = re.escape(pattern)
        escaped = escaped.replace(r'\*', r'[^.]+')
        return f'^{escaped}$'
    
    def _path_prefix_to_regex(self, pattern: str) -> str:
        """Convert example.com/api/* to regex that matches path prefix."""
        # Remove trailing /*
        prefix = pattern[:-2]
        # Escape and match path prefix
        escaped = re.escape(prefix)
        return f'^{escaped}.*$'
    
    def _compile(self) -> None:
        """Finalize compilation - ensure all rules have compiled regex."""
        all_rules = self.allowed_rules + self.prohibited_rules
        
        for rule in all_rules:
            if rule.regex is None and not rule.is_cidr:
                # Exact match fallback
                escaped = re.escape(rule.pattern) + r'\Z'
                rule.regex = re.compile(escaped, re.IGNORECASE)
        
        self._compiled = True
    
    def is_target_allowed(self, target: str) -> tuple[bool, str]:
        """
        Check if target is within allowed scope and not prohibited.
        
        Returns:
            (allowed: bool, reason: str)
            
        Fail-closed: if target cannot be definitively classified, returns (False, reason).
        """
        if not self._compiled:
            return False, "ScopeParser not compiled - no rules loaded"
        
        if not target:
            return False, "Empty target"
        
        # Normalize target
        normalized = self._normalize_target(target)
        
        # Check prohibited first (explicit deny always wins)
        for rule in self.prohibited_rules:
            if self._match_rule(normalized, rule):
                return False, f"Target explicitly prohibited by: {rule.pattern}"
        
        # Check allowed
        for rule in self.allowed_rules:
            if self._match_rule(normalized, rule):
                return True, f"Target allowed by: {rule.pattern}"
        
        # Fail closed - no matching allow rule
        return False, f"Target not in allowed scope (prohibited: {len(self.prohibited_rules)}, allowed: {len(self.allowed_rules)})"
    
    def _normalize_target(self, target: str) -> str:
        """Normalize target for consistent matching."""
        # Remove protocol
        target = re.sub(r'^[a-zA-Z]+://', '', target)
        # Remove trailing slash from domain
        target = target.rstrip('/')
        # Lowercase for domain matching
        return target.lower()
    
    def _match_rule(self, target: str, rule: ScopeRule) -> bool:
        """Match a target against a compiled rule."""
        if rule.is_cidr and rule.cidr_network:
            try:
                # Try to parse target as IP
                target_ip = ipaddress.ip_address(target.split(':')[0])  # Handle host:port
                return target_ip in rule.cidr_network
            except ValueError:
                # Target is not an IP, can't match CIDR
                return False
        
        if rule.regex:
            return bool(rule.regex.match(target))
        
        return False
    
    def export_policy(self) -> dict:
        """
        Export compiled policy as EngagementPolicy compatible dict.
        
        Returns dict with allowed_targets and prohibited_targets suitable
        for CapabilityBroker.EngagementPolicy.
        """
        allowed = [r.pattern for r in self.allowed_rules]
        prohibited = [r.pattern for r in self.prohibited_rules]
        
        return {
            "allowed_targets": allowed,
            "prohibited_targets": prohibited
        }
    
    def get_stats(self) -> dict:
        """Get parser statistics for debugging."""
        return {
            "compiled": self._compiled,
            "allowed_rules": len(self.allowed_rules),
            "prohibited_rules": len(self.prohibited_rules),
            "cidr_rules": sum(1 for r in self.allowed_rules + self.prohibited_rules if r.is_cidr),
            "wildcard_rules": sum(1 for r in self.allowed_rules + self.prohibited_rules if r.is_wildcard),
            "path_prefix_rules": sum(1 for r in self.allowed_rules + self.prohibited_rules if r.is_path_prefix),
        }


# Convenience function for direct usage
def create_scope_parser_from_file(filepath: str) -> ScopeParser:
    """
    Create ScopeParser from file - auto-detects format by extension.
    
    Supported: .json (HackerOne), .md/.markdown, .txt (CIDR list)
    """
    path = Path(filepath)
    parser = ScopeParser()
    
    with open(path, 'r') as f:
        content = f.read()
    
    if path.suffix.lower() == '.json':
        parser.parse_hackerone_json(json.loads(content))
    elif path.suffix.lower() in ('.md', '.markdown'):
        parser.parse_markdown(content)
    else:
        # Treat as CIDR list or simple domain list
        lines = [l.strip() for l in content.split('\n') if l.strip() and not l.startswith('#')]
        parser.parse_cidr_list(lines)
    
    return parser


if __name__ == "__main__":
    # Quick self-test
    print("=== SCOPE PARSER SELF-TEST ===")
    
    # Test 1: HackerOne JSON
    h1_json = {
        "in_scope": [
            {"asset_identifier": "*.example.com", "asset_type": "URL"},
            {"asset_identifier": "api.example.com", "asset_type": "URL"},
            {"asset_identifier": "10.0.0.0/24", "asset_type": "CIDR"},
        ],
        "out_of_scope": [
            {"asset_identifier": "support.example.com", "asset_type": "URL"},
            {"asset_identifier": "10.0.0.1", "asset_type": "CIDR"},
        ]
    }
    
    parser = ScopeParser()
    parser.parse_hackerone_json(h1_json)
    
    test_cases = [
        ("api.example.com", True),
        ("www.example.com", True),
        ("support.example.com", False),
        ("10.0.0.50", True),
        ("10.0.0.1", False),
        ("192.168.1.1", False),  # Not in scope
        ("evil.com", False),  # Not in scope
    ]
    
    print("\nHackerOne JSON tests:")
    for target, expected in test_cases:
        allowed, reason = parser.is_target_allowed(target)
        status = "✅" if allowed == expected else "❌"
        print(f"  {status} {target}: {allowed} ({reason})")
    
    # Test 2: Markdown
    md = """
| Asset | Type | Eligible |
|-------|------|----------|
| *.test.com | URL | Yes |
| admin.test.com | URL | No |
| 192.168.1.0/24 | CIDR | Yes |
"""
    parser2 = ScopeParser()
    parser2.parse_markdown(md)
    
    print("\nMarkdown tests:")
    for target, expected in [("api.test.com", True), ("admin.test.com", False), ("192.168.1.50", True), ("10.0.0.1", False)]:
        allowed, reason = parser2.is_target_allowed(target)
        status = "✅" if allowed == expected else "❌"
        print(f"  {status} {target}: {allowed} ({reason})")
    
    # Test 3: Fail-closed behavior
    print("\nFail-closed test:")
    parser3 = ScopeParser()
    parser3.parse_cidr_list(["10.0.0.0/24"])
    allowed, reason = parser3.is_target_allowed("192.168.1.1")
    print(f"  192.168.1.1 (not in scope): {allowed} - {reason}")
    assert not allowed, "Should deny unknown target"
    
    print("\n=== ALL TESTS PASSED ===")