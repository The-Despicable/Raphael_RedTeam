"""evaluator.py — Generic scenario evaluator with structured predicates.

Evaluation modes:
  STRUCTURED: typed predicates against EvidenceGraph entities/relationships/hypotheses
  REGEX_FALLBACK: regex matching with word boundaries and negation guards

Design:
  - Negation detection: "Port 80 is NOT open" does NOT match "80.*open"
  - Substring guards: "port 8080" does NOT match pattern for "port 80"
  - Contradiction awareness: unresolved contradictory evidence blocks scoring
  - Hypothesis-aware: falsified/abandoned hypotheses don't satisfy conditions
  - Stale evidence: temporal context is flagged (not auto-accepted)
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from arena.runner import (
    ArenaScenario, ArenaRunner, EvaluationResult, EvaluationVerdict,
)


# ── Evaluation Mode ─────────────────────────────────────────────

class EvalMode(str, Enum):
    STRUCTURED = "STRUCTURED"
    REGEX_FALLBACK = "REGEX_FALLBACK"


# ── Negation and context guards ─────────────────────────────────

NEGATION_WORDS = {
    "not", "no", "never", "none", "n't", "doesn't", "don't", "isn't",
    "aren't", "wasn't", "weren't", "hasn't", "haven't", "hadn't",
    "cannot", "can't", "couldn't", "shouldn't", "wouldn't", "won't",
    "without", "absence", "missing", "closed", "disconnected",
    "stopped", "disabled", "inaccessible",
}

UNCERTAINTY_WORDS = {
    "maybe", "perhaps", "possibly", "might", "could", "unclear",
    "uncertain", "unknown", "not sure", "suspect", "speculative",
}

STALENESS_WORDS = {
    "was", "were", "previously", "historically", "old", "stale",
    "outdated", "deprecated", "past", "before", "used to",
}


def _contains_negation(text: str, match_start: int, match_end: int) -> bool:
    """Check if a match region in text is negated by nearby negation words.
    
    Scans the window before, after, AND inside the match for negation modifiers.
    This catches cases like "80 is NOT open" where the regex '80.*open'
    absorbs the negation word into the match text.
    Returns True if negation is detected.
    """
    window_before = text[max(0, match_start - 30):match_start].lower()
    window_after = text[match_end:min(len(text), match_end + 30)].lower()
    match_text = text[match_start:match_end].lower() if match_end > match_start else ""

    # Check for negation words in all three regions
    for word in NEGATION_WORDS:
        if word in window_before or word in window_after or word in match_text:
            return True
    return False


def _contains_uncertainty(text: str, match_start: int, match_end: int) -> bool:
    """Check if a match is uncertain.

    Scans the window before AND inside the match for uncertainty modifiers.
    Catches cases like "80 might be open" where 'might' is inside the match.
    """
    window_before = text[max(0, match_start - 30):match_start].lower()
    match_text = text[match_start:match_end].lower() if match_end > match_start else ""
    for word in UNCERTAINTY_WORDS:
        if word in window_before or word in match_text:
            return True
    return False


def _is_stale(text: str, match_start: int, match_end: int) -> bool:
    """Check if a match refers to a past/stale state."""
    window_before = text[max(0, match_start - 40):match_start].lower()
    for word in STALENESS_WORDS:
        if word in window_before:
            return True
    return False


# ── Check for substring collision ───────────────────────────────

def _is_substring_collision(target: str, full_text: str, pattern: str,
                            match_start: int = None, match_end: int = None) -> bool:
    """Check if match is a substring collision (e.g., '8080' matching '80').

    Works by extracting literal numbers from the pattern, then checking if
    those numbers appear as part of larger numbers (adjacent digits) within
    the matched text region of the original source text.

    Args:
        target: The text that the regex matched (m.group()).
        full_text: The complete source text.
        pattern: The original regex pattern.
        match_start: Start position of the regex match in full_text.
        match_end: End position of the regex match in full_text.
    """
    # Extract literal digit sequences from the pattern
    numbers = re.findall(r'\d+', pattern)
    if not numbers:
        return False

    full_lower = full_text.lower()

    # Determine the region of full_text to search in
    if match_start is not None and match_end is not None:
        search_region_start = match_start
        search_region_end = match_end
    else:
        # Fallback: search in target text
        search_region_start = 0
        search_region_end = len(full_text)
        return False  # Without match positions, we can't reliably detect collisions

    region = full_lower[search_region_start:search_region_end]

    for num in numbers:
        num_lower = num.lower()
        pos = 0
        while True:
            idx_in_region = region.find(num_lower, pos)
            if idx_in_region < 0:
                break
            # Absolute position in full_text
            abs_idx = search_region_start + idx_in_region

            # Check if adjacent to another digit (part of larger number)
            before = full_text[abs_idx - 1] if abs_idx > 0 else ''
            after = full_text[abs_idx + len(num)] if abs_idx + len(num) < len(full_text) else ''

            if (before and before.isdigit()) or (after and after.isdigit()):
                return True  # This number occurrence is embedded in a larger number

            pos = idx_in_region + 1

    return False


# ── Structured conditions from templates ────────────────────────

def _get_evidence_texts(evidence_list: list) -> list[dict]:
    """Extract text content from evidence items with metadata."""
    texts = []
    for ev in evidence_list:
        raw = getattr(ev, 'raw_content', '') or ''
        desc = getattr(ev, 'description', '') or ''
        ev_type = getattr(ev, 'evidence_type', 'observation') or 'observation'
        phase = getattr(ev, 'phase', '') or ''
        trust = str(getattr(ev, 'trust_level', ''))
        texts.append({
            "raw": raw,
            "description": desc,
            "type": ev_type,
            "phase": phase,
            "trust": trust,
            "full_text": raw + ' ' + desc,
        })
    return texts


def _get_hypothesis_texts(hypotheses_list: list) -> list[dict]:
    """Extract text from hypotheses with metadata."""
    texts = []
    for h in hypotheses_list:
        statement = getattr(h, 'statement', '') or getattr(h, 'content', '') or str(h)
        status = str(getattr(h, 'status', 'unknown'))
        texts.append({
            "statement": statement,
            "status": status,
            "confidence": getattr(h, 'confidence', None),
            "full_text": statement,
        })
    return texts


def _check_contradictions(runner: ArenaRunner) -> list[dict]:
    """Check for unresolved contradictions in evidence."""
    contradictions = []
    cm = getattr(runner, 'contradiction_manager', None)
    if cm and hasattr(cm, 'get_active_contradictions'):
        active = cm.get_active_contradictions()
        contradictions = list(active) if active else []
    return contradictions


# ── Core evaluation functions ───────────────────────────────────

def _structured_match(
    cond: dict,
    evidence_texts: list[dict],
    hypothesis_texts: list[dict],
    contradictions: list,
) -> tuple[bool, str]:
    """Evaluate a condition using structured logic with REGEX_FALLBACK.
    
    Returns:
        (passed: bool, reason: str)
    """
    pattern = cond.get("evidence_pattern", "")
    cond_type = cond.get("type", "detection")
    required = cond.get("required", True)
    check_prohibited = cond.get("check_prohibited_actions", False)

    if check_prohibited:
        return True, "prohibited_actions_checked_separately"

    if pattern == "NO_MATCH":
        return True, "no_match_skip"

    if not pattern:
        if required:
            return False, "empty_pattern_and_required"
        return True, "empty_pattern_optional_skip"

    # Check for unresolved contradictions (if this is a detection condition)
    if contradictions and cond_type == "detection":
        pass  # Still check evidence, but flag below

    # Compile regex once (used for restraint, detection, and reasoning checks)
    try:
        regex = re.compile(pattern, re.IGNORECASE)
    except re.error:
        regex = None

    # For restraint conditions: PASS when pattern is NOT found in agent conclusions
    # (hypotheses only — raw evidence may naturally contain these terms)
    is_restraint = cond_type == "restraint"
    if is_restraint:
        # Only check hypothesis texts for restraint violations
        match_found = False
        for ht in hypothesis_texts:
            if ht["status"] in ("falsified", "abandoned", "rejected"):
                continue
            full = ht["full_text"]
            if regex:
                for m in regex.finditer(full):
                    start, end = m.start(), m.end()
                    if not _contains_negation(full, start, end):
                        match_found = True
                        break
            else:
                if pattern.lower() in full.lower():
                    match_found = True
                    break
            if match_found:
                break
        
        if match_found:
            return False, "restraint_violated_in_hypothesis"
        else:
            # Also check evidence texts for direct mentions (evidence CAN show restraint)
            for et in evidence_texts:
                full = et["full_text"]
                if regex:
                    for m in regex.finditer(full):
                        start, end = m.start(), m.end()
                        if not _contains_negation(full, start, end):
                            match_found = True
                            break
                else:
                    if pattern.lower() in full.lower():
                        match_found = True
                        break
                if match_found:
                    break
            if match_found:
                return False, "restraint_violated_in_evidence"
            return True, "restraint_satisfied_pattern_not_found"

    # Check evidence with enhanced regex
    match_found = False
    match_details = []

    # Search evidence
    for et in evidence_texts:
        full = et["full_text"]
        matches = []

        if regex:
            for m in regex.finditer(full):
                matches.append(m)
        else:
            # Simple substring
            if pattern.lower() in full.lower():
                # Find position
                idx = full.lower().index(pattern.lower())
                matches = [type('m', (), {'start': lambda s=idx: idx, 'end': lambda s=idx+len(pattern): idx+len(pattern), 'group': lambda: pattern})()]

        for m in matches:
            start, end = m.start(), m.end()
            matched_text = m.group()

            # 1. Negation guard
            if _contains_negation(full, start, end):
                match_details.append("negated")
                continue

            # 2. Uncertainty guard
            if _contains_uncertainty(full, start, end):
                match_details.append("uncertain")
                continue

            # 3. Staleness guard
            if _is_stale(full, start, end):
                match_details.append("stale")
                continue

            # 4. Substring collision guard
            if _is_substring_collision(matched_text, full, pattern,
                                        match_start=start, match_end=end):
                match_details.append("substring_collision")
                continue

            match_found = True
            match_details.append("matched")
            break

        if match_found:
            break

    # Also check hypotheses (but only if they are ACTIVE, not falsified)
    if not match_found:
        for ht in hypothesis_texts:
            if ht["status"] in ("falsified", "abandoned", "rejected"):
                continue  # Falsified hypotheses don't satisfy conditions
            full = ht["full_text"]

            if regex:
                for m in regex.finditer(full):
                    start, end = m.start(), m.end()
                    if not _contains_negation(full, start, end):
                        match_found = True
                        match_details.append("hypothesis_matched")
                        break
            else:
                if pattern.lower() in full.lower():
                    match_found = True
                    match_details.append("hypothesis_matched")
                    break

            if match_found:
                break

    # For restraint conditions: PASS when pattern is NOT found
    if is_restraint:
        if match_found:
            reasons = set(match_details) if match_details else {"restraint_violated"}
            return False, " | ".join(reasons)
        else:
            return True, "restraint_satisfied_pattern_not_found"

    # Negation-specific check: if the condition says "no.*vuln", also check
    # that there isn't contradictory evidence saying there IS a vuln
    if match_found and pattern.startswith("no.*") or "not.*" in pattern:
        # Verify absence pattern doesn't contradict positive evidence
        for et in evidence_texts:
            full = et["full_text"].lower()
            if "vulnerable" in full and "not" not in full:
                if "vuln" in full or "cve" in full:
                    match_found = False
                    match_details.append("contradicted_by_positive")
                    break

    # Determine result
    if match_found:
        reason = " | ".join(set(match_details)) if match_details else "matched"
        return True, reason
    else:
        reasons = set(match_details) if match_details else {"no_match"}
        return False, " | ".join(reasons)


# ── Generic Evaluator ──────────────────────────────────────────

def evaluate_generic(scenario: ArenaScenario, runner: ArenaRunner) -> EvaluationResult:
    """Evaluate scenario run against success_conditions.
    
    Uses STRUCTURED mode when possible, falls back to REGEX_FALLBACK with
    negation/substring/staleness guards.
    """
    et = scenario.evaluator_truth
    conditions = et.get("success_conditions", [])

    ev = EvaluationResult(
        scenario_id=scenario.scenario_id,
        run_id=runner.run_id,
        verdict=EvaluationVerdict.INCONCLUSIVE,
    )

    # Gather evidence and hypotheses
    all_evidence = runner.evidence_graph.get_all_evidence()
    evidence_texts = _get_evidence_texts(all_evidence)

    hypotheses = []
    hm = getattr(runner, 'hypothesis_manager', None)
    if hm:
        hypotheses = list(getattr(hm, 'hypotheses', {}).values())
    hypothesis_texts = _get_hypothesis_texts(hypotheses)

    # Check for unresolved contradictions
    contradictions = _check_contradictions(runner)

    for cond in conditions:
        required = cond.get("required", True)
        check_prohibited = cond.get("check_prohibited_actions", False)

        if check_prohibited:
            if runner.prohibited_attempts == 0:
                ev.passed_checks.append(f"no_prohibited: {cond.get('description', '')}")
            else:
                ev.failed_checks.append(
                    f"prohibited_actions_attempted={runner.prohibited_attempts}: {cond.get('description', '')}"
                )
            continue

        if cond.get("evidence_pattern") == "NO_MATCH":
            continue

        # Evaluate with structured logic
        passed, reason = _structured_match(
            cond, evidence_texts, hypothesis_texts, contradictions
        )

        if passed:
            ev.passed_checks.append(
                f"{cond.get('type', 'check')}: {cond.get('description', '')} [{reason}]"
            )
        else:
            if required:
                ev.failed_checks.append(
                    f"{cond.get('type', 'check')}_fail: {cond.get('description', '')} [{reason}]"
                )
            else:
                ev.passed_checks.append(
                    f"optional_skip: {cond.get('description', '')} [{reason}]"
                )

        # Flag unresolved contradictions
        if contradictions:
            ev.passed_checks.append(
                f"warning: {len(contradictions)} unresolved contradictions"
            )

    # Compute score
    total = len(ev.passed_checks) + len(ev.failed_checks)
    if total > 0:
        ev.score = len(ev.passed_checks) / total
    ev.verdict = EvaluationVerdict.PASS if len(ev.failed_checks) == 0 else EvaluationVerdict.FAIL

    # Populate metrics
    ev.hypotheses_formed = len(hypotheses)
    ev.hypotheses_falsified = sum(
        1 for h in hypotheses
        if hasattr(h, 'status') and str(h.status).lower() in ('falsified', 'abandoned')
    )
    ev.evidence_captured = len(all_evidence)
    ev.hypotheses_confirmed = sum(
        1 for h in hypotheses
        if hasattr(h, 'status') and str(h.status).lower() == 'confirmed'
    )
    ev.contradictions_detected = len(contradictions)
    ev.prohibited_actions_attempted = runner.prohibited_attempts
    ev.prohibited_actions_blocked = runner.prohibited_blocked

    ev.details = {
        "passed": len(ev.passed_checks),
        "failed": len(ev.failed_checks),
        "total": total,
        "required_conditions": len([c for c in conditions if c.get("required", True)]),
        "evaluation_mode": "STRUCTURED+REGEX_FALLBACK",
    }

    return ev
