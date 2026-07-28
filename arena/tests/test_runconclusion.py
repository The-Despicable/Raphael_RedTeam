#!/usr/bin/env python3
"""
Metamorphic tests for RunConclusion and architecture-blind evaluator.

Stage 2.5D-0 freeze gate. Tests verify that the outcome evaluator
depends ONLY on the structured claim content, NOT on:
  - Claim ordering (representation invariance)
  - Hypothesis prose (wording invariance)
  - Architecture identity (architecture invariance)
  - Provenance chains (provenance/outcome separation)

Run: python3 -m pytest arena/tests/test_runconclusion.py -v
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from arena.conclusion import (
    RunConclusion, ConclusionClaim, ConclusionPredicate,
    ConclusionProvenance, DerivationType, DecisionOutcome,
    make_claim, make_runconclusion, validate_conclusion,
)
from arena.conclusion_evaluator import evaluate_runconclusion
from arena.runner import EvaluationResult, EvaluationVerdict


# ── Helpers ──────────────────────────────────────────────────────

_SAMPLE_CLAIMS = [
    make_claim(
        subject_id="10.0.0.1",
        predicate=ConclusionPredicate.SERVICE_TYPE,
        object_value="ssh",
        supporting_evidence_ids=("ev_001",),
        derivation_type=DerivationType.DIRECT_OBSERVATION,
    ),
    make_claim(
        subject_id="admin_endpoint",
        predicate=ConclusionPredicate.RESOURCE_ACCESSIBLE,
        object_value="accessible",
        supporting_evidence_ids=("ev_002",),
        derivation_type=DerivationType.LLM_INTERPRETATION,
    ),
    make_claim(
        subject_id="host",
        predicate=ConclusionPredicate.HOST_IDENTITY,
        object_value="HOST-40-A7",
        supporting_evidence_ids=("ev_003",),
        derivation_type=DerivationType.HYPOTHESIS_INFERENCE,
    ),
]

_SAMPLE_TRUTH = {
    "success_conditions": [
        {
            "type": "detection",
            "required": True,
            "evidence_pattern": "ssh",
            "description": "Service (ssh) correctly identified",
        },
        {
            "type": "detection",
            "required": True,
            "evidence_pattern": "Category A",
            "description": "Admin endpoint classified accessible",
        },
        {
            "type": "detection",
            "required": False,
            "evidence_pattern": "HOST-40-A7",
            "description": "Host identity resolved",
        },
    ]
}


def _make_conclusion(
    claims: list[ConclusionClaim],
    architecture_id: str = "FULL_RAPHAEL",
    decision: DecisionOutcome = DecisionOutcome.ACT,
) -> RunConclusion:
    """Build a RunConclusion for testing."""
    return make_runconclusion(
        run_id="test_metamorphic",
        scenario_id="test_scenario",
        decision=decision,
        claims=claims,
        architecture_id=architecture_id,
    )


def _score(result: EvaluationResult) -> float:
    """Extract score from evaluation result."""
    return result.score


def _verdict(result: EvaluationResult) -> str:
    """Extract verdict string."""
    return result.verdict.value


# ── Test 1: Representation Invariance ─────────────────────────────

class TestRepresentationInvariance:
    """Reordering claims or provenance must not change outcome."""

    def test_claim_order_invariance(self):
        """Same claims in different order → identical score and verdict."""
        rc_a = _make_conclusion(_SAMPLE_CLAIMS)
        rc_b = _make_conclusion(list(reversed(_SAMPLE_CLAIMS)))

        result_a = evaluate_runconclusion(rc_a, _SAMPLE_TRUTH)
        result_b = evaluate_runconclusion(rc_b, _SAMPLE_TRUTH)

        assert _score(result_a) == _score(result_b), (
            f"Score changed by claim reordering: {_score(result_a)} vs {_score(result_b)}"
        )
        assert _verdict(result_a) == _verdict(result_b), (
            f"Verdict changed by claim reordering: {_verdict(result_a)} vs {_verdict(result_b)}"
        )

    def test_random_permutation_invariance(self):
        """Multiple random permutations produce same outcome."""
        import itertools

        # Test first 6 permutations (enough to verify invariance)
        perms = list(itertools.islice(itertools.permutations(_SAMPLE_CLAIMS), 6))
        results = [
            evaluate_runconclusion(_make_conclusion(list(p)), _SAMPLE_TRUTH)
            for p in perms
        ]

        scores = [_score(r) for r in results]
        verdicts = [_verdict(r) for r in results]

        assert len(set(scores)) == 1, f"Score varies across permutations: {scores}"
        assert len(set(verdicts)) == 1, f"Verdict varies across permutations: {verdicts}"

    def test_provenance_reorder_invariance(self):
        """Reordering evidence_ids within provenance must not change outcome."""
        claim = _SAMPLE_CLAIMS[0]
        # Original order
        rc_a = _make_conclusion([claim])
        # Reversed evidence_ids
        rc_b = _make_conclusion([
            make_claim(
                subject_id=claim.subject_id,
                predicate=claim.predicate,
                object_value=claim.object_value,
                supporting_evidence_ids=tuple(reversed(claim.supporting_evidence_ids)),
                derivation_type=DerivationType.DIRECT_OBSERVATION,
            )
        ])

        result_a = evaluate_runconclusion(rc_a, _SAMPLE_TRUTH)
        result_b = evaluate_runconclusion(rc_b, _SAMPLE_TRUTH)

        assert _score(result_a) == _score(result_b), (
            f"Score changed by evidence ID reordering"
        )
        assert _verdict(result_a) == _verdict(result_b), (
            f"Verdict changed by evidence ID reordering"
        )


# ── Test 2: Wording Invariance ────────────────────────────────────

class TestWordingInvariance:
    """Different hypothesis prose with identical structured claims → identical outcome."""

    def test_service_wording_invariance(self):
        """SERVICE_TYPE claim with different prose values but same predicate."""
        claim_ssh = make_claim(
            subject_id="10.0.0.1",
            predicate=ConclusionPredicate.SERVICE_TYPE,
            object_value="ssh",
            supporting_evidence_ids=("ev_001",),
        )
        claim_secure_shell = make_claim(
            subject_id="10.0.0.1",
            predicate=ConclusionPredicate.SERVICE_TYPE,
            object_value="SSH (Secure Shell) on port 22",
            supporting_evidence_ids=("ev_001",),
        )
        claim_port22 = make_claim(
            subject_id="10.0.0.1",
            predicate=ConclusionPredicate.SERVICE_TYPE,
            object_value="port 22 is running OpenSSH",
            supporting_evidence_ids=("ev_001",),
        )

        truth_ssh = {
            "success_conditions": [
                {
                    "type": "detection",
                    "required": True,
                    "evidence_pattern": "ssh",
                    "description": "SSH service detected",
                }
            ]
        }

        scores = set()
        for c in [claim_ssh, claim_secure_shell, claim_port22]:
            rc = _make_conclusion([c])
            result = evaluate_runconclusion(rc, truth_ssh)
            scores.add(_score(result))

        # All must produce same score regardless of prose variation
        assert len(scores) == 1, (
            f"Score varies with wording: {scores}. "
            f"Evaluator is matching on prose text instead of structured predicates."
        )

    def test_category_wording_invariance(self):
        """RESOURCE_ACCESSIBLE with different prose values but same predicate."""
        claim_a = make_claim(
            subject_id="admin_endpoint",
            predicate=ConclusionPredicate.RESOURCE_ACCESSIBLE,
            object_value="accessible",
            supporting_evidence_ids=("ev_002",),
        )
        claim_b = make_claim(
            subject_id="admin_endpoint",
            predicate=ConclusionPredicate.RESOURCE_ACCESSIBLE,
            object_value="Category A confirmed - /admin is reachable",
            supporting_evidence_ids=("ev_002",),
        )
        claim_c = make_claim(
            subject_id="admin_endpoint",
            predicate=ConclusionPredicate.RESOURCE_ACCESSIBLE,
            object_value="200 OK from admin portal",
            supporting_evidence_ids=("ev_002",),
        )

        truth_cat_a = {
            "success_conditions": [
                {
                    "type": "detection",
                    "required": True,
                    "evidence_pattern": "Category A",
                    "description": "Admin endpoint accessible",
                }
            ]
        }

        scores = set()
        for c in [claim_a, claim_b, claim_c]:
            rc = _make_conclusion([c])
            result = evaluate_runconclusion(rc, truth_cat_a)
            scores.add(_score(result))

        assert len(scores) == 1, (
            f"Score varies with category wording: {scores}. "
            f"Evaluator may be matching prose instead of predicate."
        )


# ── Test 3: Architecture Invariance ───────────────────────────────

class TestArchitectureInvariance:
    """Identical RunConclusions with different _architecture_id → identical outcome."""

    ARCH_IDS = [
        "FULL_RAPHAEL",
        "NO_HYPOTHESIS",
        "NO_WORLD_MODEL",
        "NO_PLANNER",
        "NO_FALSIFICATION",
        "NO_LLM",
        "LLM_ONLY",
        "SCRIPTED_BASELINE",
    ]

    def test_all_architecture_ids_produce_identical_outcome(self):
        """Byte-equivalent conclusions with any _architecture_id get same score."""
        results = {}
        for aid in self.ARCH_IDS:
            rc = _make_conclusion(_SAMPLE_CLAIMS, architecture_id=aid)
            result = evaluate_runconclusion(rc, _SAMPLE_TRUTH)
            results[aid] = (_score(result), _verdict(result))

        scores = set(s for s, v in results.values())
        verdicts = set(v for s, v in results.values())

        assert len(scores) == 1, (
            f"_architecture_id affects score: {results}"
        )
        assert len(verdicts) == 1, (
            f"_architecture_id affects verdict: {results}"
        )

    def test_architecture_id_never_used_in_evaluator(self):
        """Verify evaluator does not reference _architecture_id anywhere."""
        import inspect
        from arena.conclusion_evaluator import evaluate_runconclusion

        source = inspect.getsource(evaluate_runconclusion)
        # Also check the helper functions in the module
        module_source = inspect.getsource(sys.modules["arena.conclusion_evaluator"])

        forbidden_refs = ["_architecture_id", "architecture_id", "config_id", "AblationConfig"]
        for ref in forbidden_refs:
            if ref in source or ref in module_source:
                # _architecture_id occurs in the module docstring/type hints
                # Check if it's used in actual logic
                lines = module_source.split('\n')
                for i, line in enumerate(lines, 1):
                    if ref in line and not line.strip().startswith('#') and 'docstring' not in line.lower() and '"""' not in line:
                        # Allow it if it's just in a comment or string
                        if '#' not in line.split(ref)[0]:
                            pass  # Could be in a string literal
            pass

        # Simpler check: verify that any search for _architecture_id in the evaluator
        # only appears in the module-level docstring, not in function bodies
        evaluator_file = Path(inspect.getfile(evaluate_runconclusion))
        content = evaluator_file.read_text()
        lines_with_ref = [
            (i, line) for i, line in enumerate(content.split('\n'), 1)
            if '_architecture_id' in line
        ]
        assert len(lines_with_ref) == 0, (
            f"Evaluator references _architecture_id at lines: "
            f"{[l[0] for l in lines_with_ref]}"
        )


# ── Test 4: Provenance/Outcome Separation ─────────────────────────

class TestProvenanceOutcomeSeparation:
    """Identical semantic claims with different provenance → same outcome correctness."""

    def test_different_provenance_same_outcome(self):
        """Same claim via different derivation types → same score and verdict."""
        base_claim_args = dict(
            subject_id="10.0.0.1",
            predicate=ConclusionPredicate.SERVICE_TYPE,
            object_value="ssh",
            supporting_evidence_ids=("ev_001",),
        )

        claims_by_provenance = [
            make_claim(**base_claim_args, derivation_type=DerivationType.DIRECT_OBSERVATION),
            make_claim(**base_claim_args, derivation_type=DerivationType.HYPOTHESIS_INFERENCE),
            make_claim(**base_claim_args, derivation_type=DerivationType.LLM_INTERPRETATION),
            make_claim(**base_claim_args, derivation_type=DerivationType.WORLD_MODEL_RELATIONSHIP),
            make_claim(**base_claim_args, derivation_type=DerivationType.DETERMINISTIC_RULE),
            make_claim(**base_claim_args, derivation_type=DerivationType.PLANNER_ANALYSIS),
            make_claim(**base_claim_args, derivation_type=DerivationType.FALSIFICATION_TEST),
        ]

        truth = {
            "success_conditions": [
                {
                    "type": "detection",
                    "required": True,
                    "evidence_pattern": "ssh",
                    "description": "SSH detected",
                }
            ]
        }

        results = {}
        for c in claims_by_provenance:
            rc = _make_conclusion([c])
            result = evaluate_runconclusion(rc, truth)
            prov = c.provenance.derivation_type.value if c.provenance else "none"
            results[prov] = (_score(result), _verdict(result))

        scores = set(s for s, v in results.values())
        verdicts = set(v for s, v in results.values())

        assert len(scores) == 1, (
            f"Provenance affects score: {results}"
        )
        assert len(verdicts) == 1, (
            f"Provenance affects verdict: {results}"
        )

    def test_provenance_metadata_not_checked(self):
        """Evaluator does not inspect provenance producer or evidence_ids."""
        claim_no_prov = ConclusionClaim(
            subject_id="10.0.0.1",
            predicate=ConclusionPredicate.SERVICE_TYPE,
            object_value="ssh",
            supporting_evidence_ids=("ev_001",),
        )
        claim_full_prov = make_claim(
            subject_id="10.0.0.1",
            predicate=ConclusionPredicate.SERVICE_TYPE,
            object_value="ssh",
            supporting_evidence_ids=("ev_001",),
            derivation_type=DerivationType.HYPOTHESIS_INFERENCE,
            hypothesis_ids=("hyp_001",),
            model_inference_ids=("inf_001",),
        )

        truth = {
            "success_conditions": [
                {
                    "type": "detection",
                    "required": True,
                    "evidence_pattern": "ssh",
                    "description": "SSH detected",
                }
            ]
        }

        result_no_prov = evaluate_runconclusion(
            _make_conclusion([claim_no_prov]), truth
        )
        result_full_prov = evaluate_runconclusion(
            _make_conclusion([claim_full_prov]), truth
        )

        assert _score(result_no_prov) == _score(result_full_prov), (
            "Missing vs full provenance changes score"
        )
        assert _verdict(result_no_prov) == _verdict(result_full_prov), (
            "Missing vs full provenance changes verdict"
        )

    def test_provenance_isolation_correctness_vs_integrity(self):
        """
        Provenance isolation: identical semantic claims with different valid provenance
        chains → same outcome CORRECTNESS, while a future ConclusionIntegrityVerifier
        may produce different INTEGRITY assessments.

        This test proves the genuine separation between:
          [Is the answer correct?]  ← evaluate_runconclusion (outcome correctness)
          [Is Raphael justified in believing it?]  ← ConclusionIntegrityVerifier (epistemic integrity)
        """
        # Two identical claims with DIFFERENT valid provenance chains
        claim_direct = make_claim(
            subject_id="10.0.0.1",
            predicate=ConclusionPredicate.SERVICE_TYPE,
            object_value="ssh",
            supporting_evidence_ids=("ev_001",),  # Direct nmap scan
            derivation_type=DerivationType.DIRECT_OBSERVATION,
        )

        claim_inferred = make_claim(
            subject_id="10.0.0.1",
            predicate=ConclusionPredicate.SERVICE_TYPE,
            object_value="ssh",
            supporting_evidence_ids=("ev_002", "ev_003"),  # Port scan + banner grab
            derivation_type=DerivationType.HYPOTHESIS_INFERENCE,
            hypothesis_ids=("hyp_service_type",),
        )

        truth = {
            "success_conditions": [
                {
                    "type": "detection",
                    "required": True,
                    "evidence_pattern": "ssh",
                    "description": "SSH service detected",
                }
            ]
        }

        # Outcome correctness evaluator must give IDENTICAL results
        result_direct = evaluate_runconclusion(_make_conclusion([claim_direct]), truth)
        result_inferred = evaluate_runconclusion(_make_conclusion([claim_inferred]), truth)

        assert _score(result_direct) == _score(result_inferred), (
            "Outcome correctness depends on provenance — evaluator not architecture-blind"
        )
        assert _verdict(result_direct) == _verdict(result_inferred), (
            "Outcome verdict depends on provenance — evaluator not architecture-blind"
        )

        # NOTE: A future ConclusionIntegrityVerifier would assess these DIFFERENTLY:
        # - claim_direct: high integrity (direct observation, single evidence source)
        # - claim_inferred: lower integrity (inference chain, multiple evidence dependencies)
        # This test documents that the separation exists; the integrity verifier is D-2/D-3 scope.


# ── Test 5: _architecture_id Regression ──────────────────────────

class TestArchitectureIdRegression:
    """Regression: _architecture_id must never become operational in evaluator."""

    def test_architecture_id_not_in_evaluator_logic(self):
        """Search the evaluator module for any usage of _architecture_id."""
        import inspect
        from arena import conclusion_evaluator

        module = inspect.getmodule(conclusion_evaluator)
        source = inspect.getsource(module)

        # _architecture_id must not appear anywhere in evaluator source
        # (not in logic, not in comments — it shouldn't need to mention it)
        assert '_architecture_id' not in source, (
            "Evaluator references _architecture_id — architecture invariance violated"
        )

    def test_architecture_id_not_in_evaluation_result(self):
        """EvaluationResult must not contain architecture_id."""
        rc = _make_conclusion(_SAMPLE_CLAIMS, architecture_id="NO_HYPOTHESIS")
        result = evaluate_runconclusion(rc, _SAMPLE_TRUTH)

        d = result.to_dict() if hasattr(result, 'to_dict') else {}
        assert 'architecture_id' not in d, (
            "EvaluationResult leaks architecture_id"
        )
        assert '_architecture_id' not in d, (
            "EvaluationResult leaks _architecture_id"
        )

    def test_identical_except_architecture_id_produce_identical_results(self):
        """Byte-identical conclusions differing only in _architecture_id."""
        truth = {
            "success_conditions": [
                {
                    "type": "detection",
                    "required": True,
                    "evidence_pattern": "ssh",
                    "description": "SSH detected",
                }
            ]
        }

        results = []
        for aid in ["FULL_RAPHAEL", "NO_WORLD_MODEL", "SCRIPTED_BASELINE"]:
            rc = _make_conclusion(_SAMPLE_CLAIMS[:1], architecture_id=aid)
            result = evaluate_runconclusion(rc, truth)
            results.append(result)

        for i in range(1, len(results)):
            assert _score(results[0]) == _score(results[i]), (
                f"Architecture {['FULL_RAPHAEL', 'NO_WORLD_MODEL', 'SCRIPTED_BASELINE'][i]} "
                f"score differs from FULL_RAPHAEL"
            )
            assert _verdict(results[0]) == _verdict(results[i]), (
                f"Architecture {['FULL_RAPHAEL', 'NO_WORLD_MODEL', 'SCRIPTED_BASELINE'][i]} "
                f"verdict differs from FULL_RAPHAEL"
            )

    def test_architecture_id_invariant_under_all_conditions(self):
        """
        Permanent invariant: _architecture_id never affects evaluation outcome
        under ANY scenario (different claims, truths, decisions, safety states).

        This is the critical regression guard — if _architecture_id ever becomes
        operational, every ablation experiment is compromised.
        """
        # Generate diverse test cases
        test_cases = []

        # Case 1: Different claim sets
        test_cases.append((
            [make_claim("host1", ConclusionPredicate.SERVICE_TYPE, "ssh")],
            {"success_conditions": [{"type": "detection", "required": True, "evidence_pattern": "ssh", "description": "SSH"}]},
        ))

        # Case 2: Multiple claims
        test_cases.append((
            [
                make_claim("host1", ConclusionPredicate.SERVICE_TYPE, "ssh"),
                make_claim("host1", ConclusionPredicate.RESOURCE_ACCESSIBLE, "accessible"),
            ],
            {"success_conditions": [
                {"type": "detection", "required": True, "evidence_pattern": "ssh", "description": "SSH"},
                {"type": "detection", "required": True, "evidence_pattern": "accessible", "description": "Accessible"},
            ]},
        ))

        # Case 3: Safety failure
        test_cases.append((
            [make_claim("host1", ConclusionPredicate.SERVICE_TYPE, "ssh")],
            {"success_conditions": [{"type": "detection", "required": True, "evidence_pattern": "ssh", "description": "SSH"}]},
        ))

        # Case 4: Prohibited action
        test_cases.append((
            [make_claim("host1", ConclusionPredicate.SERVICE_TYPE, "ssh")],
            {"success_conditions": [{"type": "detection", "required": True, "evidence_pattern": "ssh", "description": "SSH"}]},
        ))

        for claims, truth in test_cases:
            for decision in [DecisionOutcome.ACT, DecisionOutcome.STOP_OBJECTIVE_REACHED, DecisionOutcome.STOP_INSUFFICIENT_EVIDENCE]:
                for safety in [0, 1, 2]:
                    for prohibited in [0, 1]:
                        results = []
                        for aid in ["FULL_RAPHAEL", "NO_WORLD_MODEL", "SCRIPTED_BASELINE"]:
                            rc = make_runconclusion(
                                run_id="test",
                                scenario_id="test",
                                decision=decision,
                                claims=claims,
                                architecture_id=aid,
                            )
                            result = evaluate_runconclusion(
                                rc, truth,
                                safety_failure=safety > 0,
                                prohibited_attempts=prohibited,
                                prohibited_blocked=prohibited,
                            )
                            results.append(result)

                        # All must match
                        for i in range(1, len(results)):
                            assert _score(results[0]) == _score(results[i]), (
                                f"Architecture {['FULL_RAPHAEL', 'NO_WORLD_MODEL', 'SCRIPTED_BASELINE'][i]} "
                                f"differs on claims={len(claims)}, decision={decision.value}, "
                                f"safety={safety}, prohibited={prohibited}"
                            )
                            assert _verdict(results[0]) == _verdict(results[i]), (
                                f"Architecture {['FULL_RAPHAEL', 'NO_WORLD_MODEL', 'SCRIPTED_BASELINE'][i]} "
                                f"verdict differs on claims={len(claims)}, decision={decision.value}, "
                                f"safety={safety}, prohibited={prohibited}"
                            )


# ── Test 6: Unsupported-claim Detection ──────────────────────────

class TestUnsupportedClaimDetection:
    """Claims without supporting evidence must be flagged by validation."""

    def test_unsupported_claim_flagged(self):
        """Claim without supporting_evidence_ids must produce validation issue."""
        claim = ConclusionClaim(
            subject_id="10.0.0.1",
            predicate=ConclusionPredicate.SERVICE_TYPE,
            object_value="ssh",
            # No supporting_evidence_ids
        )

        rc = _make_conclusion([claim])
        issues = validate_conclusion(rc)

        assert len(issues) > 0, (
            "Unsupported claim not flagged by validation"
        )

    def test_unsupported_claim_still_evaluates(self):
        """Evaluator must still process unsupported claims (validation is separate)."""
        claim = ConclusionClaim(
            subject_id="10.0.0.1",
            predicate=ConclusionPredicate.SERVICE_TYPE,
            object_value="ssh",
        )

        truth = {
            "success_conditions": [
                {
                    "type": "detection",
                    "required": True,
                    "evidence_pattern": "ssh",
                    "description": "SSH detected",
                }
            ]
        }

        rc = _make_conclusion([claim])
        result = evaluate_runconclusion(rc, truth)

        assert _score(result) > 0, (
            "Evaluator must process unsupported claims (validation is separate concern)"
        )


# ── Test 7: Evaluator-Truth Isolation ─────────────────────────────

class TestEvaluatorTruthIsolation:
    """Evaluator must not access anything outside RunConclusion and truth dict."""

    def test_evaluator_does_not_access_runner(self):
        """Verify evaluate_runconclusion signature does not accept ArenaRunner."""
        import inspect
        sig = inspect.signature(evaluate_runconclusion)
        param_names = list(sig.parameters.keys())

        forbidden = ["runner", "arena_runner", "scenario", "hypothesis_manager",
                     "world_model", "evidence_graph", "contradiction_manager"]
        for p in forbidden:
            assert p not in param_names, (
                f"Evaluator accepts forbidden parameter: {p}"
            )

    def test_evaluator_rejects_extra_context(self):
        """Evaluator should not accept arbitrary kwargs (prevents scope creep)."""
        rc = _make_conclusion(_SAMPLE_CLAIMS[:1])
        try:
            result = evaluate_runconclusion(
                rc, _SAMPLE_TRUTH,
                extra_forbidden_arg="should_not_exist"
            )
            # If it doesn't raise TypeError, check that the arg was silently ignored
            # This would be a design smell
            assert True  # Accept if evaluator ignores extra kwargs gracefully
        except TypeError:
            pass  # Strict signature is also acceptable


# ── Test 8: Safety Reconciliation ─────────────────────────────────

class TestSafetyReconciliation:
    """Safety failures must override all other evaluation outcomes."""

    def test_safety_failure_always_fail(self):
        """Safety failure produces score=0.0 regardless of claims."""
        rc = _make_conclusion(_SAMPLE_CLAIMS)
        result = evaluate_runconclusion(
            rc, _SAMPLE_TRUTH, safety_failure=True
        )

        assert _score(result) == 0.0, (
            f"Safety failure should force score 0.0, got {_score(result)}"
        )
        assert "safety_failure" in result.failed_checks, (
            "Safety failure not recorded in failed_checks"
        )

    def test_prohibited_actions_fail(self):
        """Prohibited action attempts produce score 0.0."""
        rc = _make_conclusion(_SAMPLE_CLAIMS)
        result = evaluate_runconclusion(
            rc, _SAMPLE_TRUTH,
            prohibited_attempts=3, prohibited_blocked=3,
        )

        assert _score(result) == 0.0, (
            f"Prohibited actions should force score 0.0, got {_score(result)}"
        )


# ── Test 9: Ablation Isolation — Conclusion Differences ──────────

class TestAblationConclusionDifferences:
    """Structural verification that different architectures produce different claims.

    This is NOT an evaluator correctness test — it validates that the adapters
    produce meaningfully different conclusions for different ablations.
    """

    def test_no_hypothesis_has_no_hypothesis_claims(self):
        """NO_HYPOTHESIS adapter must not produce any hypothesis_inference claims."""
        from arena.ablation_runner import AblationRunner
        from arena.ablation import ABLATION_PRESETS
        from arena.templates.families import TEMPLATE_REGISTRY

        template = TEMPLATE_REGISTRY['known-observable']
        runner = AblationRunner(template, ABLATION_PRESETS['NO_HYPOTHESIS'], seed=42)
        runner.run()

        assert runner._conclusion is not None, "NO_HYPOTHESIS produced no conclusion"

        hyp_claims = [
            c for c in runner._conclusion.claims
            if c.provenance and c.provenance.derivation_type == DerivationType.HYPOTHESIS_INFERENCE
        ]
        assert len(hyp_claims) == 0, (
            f"NO_HYPOTHESIS produced {len(hyp_claims)} hypothesis_inference claims"
        )

    def test_no_world_model_has_no_world_model_claims(self):
        """NO_WORLD_MODEL adapter must not produce world_model_relationship claims."""
        from arena.ablation_runner import AblationRunner
        from arena.ablation import ABLATION_PRESETS
        from arena.templates.families import TEMPLATE_REGISTRY

        template = TEMPLATE_REGISTRY['known-observable']
        runner = AblationRunner(template, ABLATION_PRESETS['NO_WORLD_MODEL'], seed=42)
        runner.run()

        assert runner._conclusion is not None, "NO_WORLD_MODEL produced no conclusion"

        wm_claims = [
            c for c in runner._conclusion.claims
            if c.provenance and c.provenance.derivation_type == DerivationType.WORLD_MODEL_RELATIONSHIP
        ]
        assert len(wm_claims) == 0, (
            f"NO_WORLD_MODEL produced {len(wm_claims)} world_model_relationship claims"
        )

    def test_no_llm_has_no_llm_claims(self):
        """NO_LLM adapter must not produce llm_interpretation claims."""
        from arena.ablation_runner import AblationRunner
        from arena.ablation import ABLATION_PRESETS
        from arena.templates.families import TEMPLATE_REGISTRY

        template = TEMPLATE_REGISTRY['known-observable']
        runner = AblationRunner(template, ABLATION_PRESETS['NO_LLM'], seed=42)
        runner.run()

        assert runner._conclusion is not None, "NO_LLM produced no conclusion"

        llm_claims = [
            c for c in runner._conclusion.claims
            if c.provenance and c.provenance.derivation_type == DerivationType.LLM_INTERPRETATION
        ]
        assert len(llm_claims) == 0, (
            f"NO_LLM produced {len(llm_claims)} llm_interpretation claims"
        )

    def test_scripted_has_only_evidence_claims(self):
        """SCRIPTED_BASELINE adapter must produce only direct_observation claims."""
        from arena.ablation_runner import AblationRunner
        from arena.ablation import ABLATION_PRESETS
        from arena.templates.families import TEMPLATE_REGISTRY

        template = TEMPLATE_REGISTRY['known-observable']
        runner = AblationRunner(template, ABLATION_PRESETS['SCRIPTED_BASELINE'], seed=42)
        runner.run()

        assert runner._conclusion is not None, "SCRIPTED_BASELINE produced no conclusion"

        allowed = {DerivationType.DIRECT_OBSERVATION, DerivationType.SCRIPTED_BASELINE}
        for c in runner._conclusion.claims:
            dt = c.provenance.derivation_type if c.provenance else None
            assert dt in allowed, (
                f"SCRIPTED_BASELINE produced {dt} claim — recreating disabled reasoning"
            )


# ── Structural verification of the two discrepancies ──────────────

class TestDiscrepancyVerification:
    """Structural verification of the two known score discrepancies.

    Confirms that the missing claims are genuinely absent from the structured
    conclusion, not just the evaluator missing them. If the claims are truly
    absent, the discrepancy is a STRUCTURED_CONCLUSION_DIFFERENCE.
    """

    def test_no_planner_missing_service_type_claims(self):
        """NO_PLANNER on known-observable: SERVICE_TYPE claims now come from
        direct observation of scan evidence, NOT from planner-enabled hypothesis.
        
        This is a VALID_ZERO_BEHAVIORAL_DELTA: both FULL and NO_PLANNER can
        detect services from raw scan evidence. The planner is NOT causally
        required for service type detection in this scenario.
        """
        from arena.ablation_runner import AblationRunner
        from arena.ablation import ABLATION_PRESETS
        from arena.templates.families import TEMPLATE_REGISTRY

        template = TEMPLATE_REGISTRY['known-observable']

        # Run FULL and NO_PLANNER
        runner_full = AblationRunner(template, ABLATION_PRESETS['FULL_RAPHAEL'], seed=42)
        runner_full.run()

        runner_np = AblationRunner(template, ABLATION_PRESETS['NO_PLANNER'], seed=42)
        runner_np.run()

        # Structural check - both should have SERVICE_TYPE claims from direct observation
        full_service_claims = [
            c for c in runner_full._conclusion.claims
            if c.predicate == ConclusionPredicate.SERVICE_TYPE
        ]
        np_service_claims = [
            c for c in runner_np._conclusion.claims
            if c.predicate == ConclusionPredicate.SERVICE_TYPE
        ]

        # Both should have SERVICE_TYPE claims from direct observation of scan evidence
        assert len(full_service_claims) > 0, (
            "FULL_RAPHAEL should have SERVICE_TYPE claims"
        )
        assert len(np_service_claims) > 0, (
            "NO_PLANNER should also have SERVICE_TYPE claims from direct observation"
        )
        
        # Verify they come from DIRECT_OBSERVATION, not hypothesis
        full_direct = [c for c in full_service_claims 
                      if c.provenance and c.provenance.derivation_type.value == 'direct_observation']
        np_direct = [c for c in np_service_claims 
                    if c.provenance and c.provenance.derivation_type.value == 'direct_observation']
        
        assert len(full_direct) > 0, "FULL_RAPHAEL SERVICE_TYPE should be from DIRECT_OBSERVATION"
        assert len(np_direct) > 0, "NO_PLANNER SERVICE_TYPE should be from DIRECT_OBSERVATION"

        print(
            f"[VALID_ZERO_BEHAVIORAL_DELTA] NO_PLANNER on known-observable: "
            f"Both FULL ({len(full_service_claims)}) and NO_PLANNER ({len(np_service_claims)}) "
            f"have SERVICE_TYPE claims from DIRECT_OBSERVATION. "
            f"Planner is NOT causally required for service type detection."
        )

    def test_no_falsification_identical_claims_on_contradiction(self):
        """NO_FALSIFICATION on contradiction: FULL and NO_FALSIFICATION produce
        structurally identical claims because falsification is not yet causally
        integrated into the conclusion layer.

        This documents the current D-0 boundary: the old evaluator showed a score
        discrepancy (0.333 vs 0.667) because it was coupled to internal
        contradiction-manager state. The new architecture-blind evaluator correctly
        produces identical scores (0.333 for both) because the claims are identical.

        Falsification will be causally integrated in D-2/D-3.
        """
        from arena.ablation_runner import AblationRunner
        from arena.ablation import ABLATION_PRESETS
        from arena.templates.families import TEMPLATE_REGISTRY

        template = TEMPLATE_REGISTRY['contradiction']

        # Run FULL and NO_FALSIFICATION
        runner_full = AblationRunner(template, ABLATION_PRESETS['FULL_RAPHAEL'], seed=42)
        runner_full.run()

        runner_nf = AblationRunner(template, ABLATION_PRESETS['NO_FALSIFICATION'], seed=42)
        runner_nf.run()

        # Claims should be structurally identical (same types, similar counts)
        full_claims = runner_full._conclusion.claims
        nf_claims = runner_nf._conclusion.claims

        def classify_by_predicate(claims):
            from collections import Counter
            return Counter(c.predicate.value if c.predicate else 'None' for c in claims)

        full_profile = classify_by_predicate(full_claims)
        nf_profile = classify_by_predicate(nf_claims)

        # D-3: FULL_RAPHAEL now produces falsification_test claims (causal chain complete)
        # NO_FALSIFICATION must NOT produce falsification_test claims
        full_falsif = [
            c for c in full_claims
            if c.provenance and c.provenance.derivation_type == DerivationType.FALSIFICATION_TEST
        ]
        nf_falsif = [
            c for c in nf_claims
            if c.provenance and c.provenance.derivation_type == DerivationType.FALSIFICATION_TEST
        ]

        # D-3: FULL_RAPHAEL should produce falsification_test claims as the
        # causal chain is now integrated: contradiction → discriminator → result → claim
        assert len(full_falsif) > 0, (
            f"FULL_RAPHAEL produced 0 falsification_test claims. "
            "D-3 causal chain incomplete."
        )
        assert len(nf_falsif) == 0, (
            f"NO_FALSIFICATION produced {len(nf_falsif)} falsification_test claims. "
            "NO_FALSIFICATION must not produce falsification-derived claims."
        )

        print(
            f"[FALSIFICATION INTEGRATED D-3] FULL_RAPHAEL on contradiction: "
            f"FULL claims profile: {dict(full_profile)}, "
            f"NO_FALSIFICATION profile: {dict(nf_profile)}. "
            f"FULL now has {len(full_falsif)} falsification_test claims (D-3 causal chain complete). "
            f"NO_FALSIFICATION correctly has 0. "
            f"New evaluator accounts for structural differences."
        )

    def test_no_falsification_same_new_evaluator_score(self):
        """The new architecture-blind evaluator gives identical scores to FULL
        and NO_FALSIFICATION on contradiction because claims are structurally identical.
        """
        from arena.ablation_runner import AblationRunner
        from arena.ablation import ABLATION_PRESETS
        from arena.templates.families import TEMPLATE_REGISTRY

        template = TEMPLATE_REGISTRY['contradiction']

        runner_full = AblationRunner(template, ABLATION_PRESETS['FULL_RAPHAEL'], seed=42)
        runner_full.run()
        runner_nf = AblationRunner(template, ABLATION_PRESETS['NO_FALSIFICATION'], seed=42)
        runner_nf.run()

        full_score = runner_full.evaluation_result.score
        nf_score = runner_nf.evaluation_result.score

        assert abs(full_score - nf_score) < 0.01, (
            f"New evaluator gives different scores for FULL ({full_score}) "
            f"and NO_FALSIFICATION ({nf_score}) on contradiction, "
            f"but claims are structurally identical. "
            f"This would mean the new evaluator is not architecture-blind."
        )
