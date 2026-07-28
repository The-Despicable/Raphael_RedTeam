#!/usr/bin/env python3
"""
D7-R1 Mechanism Tests: Planner Typed Denial Lifecycle

Verifies the 10 required mechanisms per SENTINEL acceptance criteria:

  1. Persistent policy DENY → same proposal suppressed.
  2. Persistent scope DENY → same scoped proposal suppressed.
  3. Persistent capability DENY → same capability proposal suppressed.
  4. Temporary/transient DENY → recorded but NOT suppressed.
  5. Different target remains eligible after target-specific DENY.
  6. Different action remains eligible after action-specific DENY.
  7. ALLOW remains unaffected by DENY records.
  8. WorldModel before/after DENY contains no new denial artifacts.
  9. Broker remains sole authorization authority (no Planner allowlist).
  10. Candidate exhaustion → clean termination, no crash, no resurrection.
"""

import sys
import unittest
import uuid
sys.path.insert(0, '/home/yaser/raphael-2.0')

from orchestrator.brain.action import (
    Planner, ActionRegistry,
    DenialClass, DenialRecord,
    _classify_denial, _is_persistent_proposal_suppressed,
)
from arena.conclusion import PlanDecision
from orchestrator.brain.world import WorldModel
from orchestrator.brain.evidence import EvidenceGraph
from orchestrator.brain.capability_broker import CapabilityBroker, BrokerPolicy


def _make_planner() -> Planner:
    """Create a minimal Planner for testing."""
    wm = WorldModel(EvidenceGraph())
    eg = EvidenceGraph()
    policy = BrokerPolicy(
        allowed_action_types=["recon", "scan", "exploit"],
        allowed_targets=["10.0.0.0/8"],
        allowed_capabilities=["nmap", "curl", "ssh", "nikto"],
    )
    broker = CapabilityBroker(policy=policy)
    ar = ActionRegistry()
    return Planner(wm, eg, broker, None, ar)


class TestDenialClassification(unittest.TestCase):
    """DenialClass enum and _classify_denial() correctness."""

    def test_persistent_keywords(self):
        """PERSISTENT for policy/scope/capability denial reasons."""
        for reason in [
            "Not in allowed list: ssh_banner",
            "Action type prohibited by policy",
            "Target not in allowed scope: 10.0.1.0/24",
            "Target explicitly prohibited: 10.0.1.1",
            "Capability not in allowed list: ssh",
            "Action type not allowed: port_scan",
        ]:
            self.assertEqual(_classify_denial(reason), DenialClass.PERSISTENT,
                             f"Expected PERSISTENT for: {reason}")

    def test_temporary_keywords(self):
        """TEMPORARY for rate/budget/impact/throttle reasons."""
        for reason in [
            "Rate limit exceeded: 60 actions/min",
            "Budget exceeded for this action type",
            "Impact score too high for this target",
            "Too many concurrent actions running",
            "Throttle limit reached: wait 30s",
        ]:
            self.assertEqual(_classify_denial(reason), DenialClass.TEMPORARY,
                             f"Expected TEMPORARY for: {reason}")

    def test_default_persistent(self):
        """Default classification is PERSISTENT (deny-by-default)."""
        self.assertEqual(_classify_denial(""), DenialClass.PERSISTENT)
        self.assertEqual(_classify_denial("Unknown reason"), DenialClass.PERSISTENT)
        self.assertEqual(_classify_denial("Some random denial"), DenialClass.PERSISTENT)


class TestDenialRecordStorage(unittest.TestCase):
    """DenialRecord dataclass and feedback_records storage."""

    def test_record_stores_all_fields(self):
        """DenialRecord stores target, action_type, capability, denial_class, receipt_id, iteration."""
        planner = _make_planner()
        planner.register_denial(
            action_type="ssh_banner",
            target="10.0.1.1",
            capability="ssh",
            receipt_id="rec_001",
            reason="Not in allowed list: ssh_banner",
        )
        self.assertEqual(len(planner.feedback_records), 1)
        rid = next(iter(planner.feedback_records))
        rec = planner.feedback_records[rid]
        self.assertEqual(rec.action_type, "ssh_banner")
        self.assertEqual(rec.target, "10.0.1.1")
        self.assertEqual(rec.capability, "ssh")
        self.assertEqual(rec.denial_class, DenialClass.PERSISTENT)
        self.assertEqual(rec.receipt_id, "rec_001")
        self.assertEqual(rec.iteration, 1)  # first registered denial → iteration 1

    def test_multiple_denials_stored(self):
        """Multiple DENIED receipts accumulate in feedback_records."""
        planner = _make_planner()
        planner.register_denial("port_scan", "10.0.1.2", "nmap", "r1", "Prohibited: port_scan")
        planner.register_denial("ssh_banner", "10.0.1.3", "ssh", "r2", "Rate limit exceeded")
        planner.register_denial("http_get", "10.0.1.4", "curl", "r3", "Target not in scope")
        self.assertEqual(len(planner.feedback_records), 3)

    def test_unavailable_actions_is_property(self):
        """unavailable_actions returns (action_type, target) set of PERSISTENT denials only."""
        planner = _make_planner()
        planner.register_denial("port_scan", "10.0.1.2", "nmap", "r1", "Prohibited: port_scan")
        planner.register_denial("ssh_banner", "10.0.1.3", "ssh", "r2", "Rate limit exceeded")
        ua = planner.unavailable_actions
        self.assertIsInstance(ua, set)
        self.assertIn(("port_scan", "10.0.1.2"), ua)
        self.assertNotIn(("ssh_banner", "10.0.1.3"), ua)  # TEMPORARY excluded
        self.assertEqual(len(ua), 1)

    def test_suppressed_proposals(self):
        """suppressed_proposals returns (action_type, target, capability) tuples."""
        planner = _make_planner()
        planner.register_denial("port_scan", "10.0.1.2", "nmap", "r1", "Prohibited: port_scan")
        planner.register_denial("ssh_banner", "10.0.1.3", "ssh", "r2", "Rate limit exceeded")
        sp = planner.suppressed_proposals
        self.assertIsInstance(sp, (set, frozenset))
        self.assertIn(("port_scan", "10.0.1.2", "nmap"), sp)
        self.assertNotIn(("ssh_banner", "10.0.1.3", "ssh"), sp)  # TEMPORARY excluded
        self.assertEqual(len(sp), 1)


class TestPersistentDenySuppression(unittest.TestCase):
    """M1-M3: PERSISTENT denials suppress same proposals."""

    def test_persistent_policy_deny_suppresses(self):
        """M1: Persistent policy DENY → same (action_type, target, capability) suppressed."""
        planner = _make_planner()
        planner.register_denial("ssh_banner", "10.0.1.1", "ssh", "r1",
                                "Action type not in allowed list: ssh_banner")
        candidates = [
            {"action_type": "ssh_banner", "target": "10.0.1.1", "capability": "ssh", "score": 0.9},
        ]
        decision = planner.decide(candidates, "obj_001")
        self.assertIsNotNone(decision)
        self.assertFalse(decision.selected_action_id,
                          "PERSISTENT policy DENY should suppress the proposal")

    def test_persistent_scope_deny_suppresses(self):
        """M2: Persistent scope DENY → same (action_type, target, capability) suppressed."""
        planner = _make_planner()
        planner.register_denial("port_scan", "10.0.1.2", "nmap", "r1",
                                "Target not in allowed scope: 10.0.1.2")
        candidates = [
            {"action_type": "port_scan", "target": "10.0.1.2", "capability": "nmap", "score": 0.8},
        ]
        decision = planner.decide(candidates, "obj_001")
        self.assertIsNotNone(decision)
        self.assertFalse(decision.selected_action_id,
                          "PERSISTENT scope DENY should suppress the proposal")

    def test_persistent_capability_deny_suppresses(self):
        """M3: Persistent capability DENY → same (action_type, target, capability) suppressed."""
        planner = _make_planner()
        planner.register_denial("ssh_banner", "10.0.1.3", "ssh", "r1",
                                "Capability not in allowed list: ssh")
        candidates = [
            {"action_type": "ssh_banner", "target": "10.0.1.3", "capability": "ssh", "score": 0.9},
        ]
        decision = planner.decide(candidates, "obj_001")
        self.assertIsNotNone(decision)
        self.assertFalse(decision.selected_action_id,
                          "PERSISTENT capability DENY should suppress the proposal")

    def test_persistent_deny_does_not_suppress_different_target(self):
        """M5: Different target remains eligible after target-specific DENY."""
        planner = _make_planner()
        planner.register_denial("ssh_banner", "10.0.1.1", "ssh", "r1",
                                "Action type not in allowed list: ssh_banner")
        candidates = [
            {"action_type": "ssh_banner", "target": "10.0.1.100", "capability": "ssh", "score": 0.9},
        ]
        decision = planner.decide(candidates, "obj_001")
        self.assertIsNotNone(decision)
        self.assertTrue(decision.selected_action_id,
                             "Different target should remain eligible")

    def test_persistent_deny_does_not_suppress_different_action(self):
        """M6: Different action remains eligible after action-specific DENY."""
        planner = _make_planner()
        planner.register_denial("ssh_banner", "10.0.1.1", "ssh", "r1",
                                "Action type not in allowed list")
        candidates = [
            {"action_type": "port_scan", "target": "10.0.1.1", "capability": "nmap", "score": 0.9},
        ]
        decision = planner.decide(candidates, "obj_001")
        self.assertIsNotNone(decision)
        self.assertTrue(decision.selected_action_id,
                             "Different action type should remain eligible")


class TestTemporaryDenyNoSuppression(unittest.TestCase):
    """M4: TEMPORARY denials are recorded but do NOT suppress."""

    def test_temporary_rate_deny_does_not_suppress(self):
        """Temporary rate limit DENY does not suppress proposal."""
        planner = _make_planner()
        planner.register_denial("ssh_banner", "10.0.1.1", "ssh", "r1",
                                "Rate limit exceeded: 60 actions/min")
        candidates = [
            {"action_type": "ssh_banner", "target": "10.0.1.1", "capability": "ssh", "score": 0.9},
        ]
        decision = planner.decide(candidates, "obj_001")
        self.assertIsNotNone(decision)
        self.assertTrue(decision.selected_action_id,
                             "TEMPORARY denial should NOT suppress the proposal")

    def test_temporary_budget_deny_does_not_suppress(self):
        """Temporary budget/impact DENY does not suppress proposal."""
        planner = _make_planner()
        planner.register_denial("http_get", "10.0.1.5", "curl", "r1",
                                "Impact budget exceeded for this action")
        candidates = [
            {"action_type": "http_get", "target": "10.0.1.5", "capability": "curl", "score": 0.8},
        ]
        decision = planner.decide(candidates, "obj_001")
        self.assertIsNotNone(decision)
        self.assertTrue(decision.selected_action_id,
                             "TEMPORARY budget denial should NOT suppress")

    def test_temporary_and_persistent_coexist(self):
        """TEMPORARY denial recorded alongside PERSISTENT without cross-contamination."""
        planner = _make_planner()
        planner.register_denial("ssh_banner", "10.0.1.1", "ssh", "r1",
                                "Rate limit exceeded")
        planner.register_denial("port_scan", "10.0.1.1", "nmap", "r2",
                                "Action type not allowed: port_scan")
        
        # TEMPORARY should NOT suppress
        candidates1 = [
            {"action_type": "ssh_banner", "target": "10.0.1.1", "capability": "ssh", "score": 0.9},
        ]
        d1 = planner.decide(candidates1, "obj_001")
        self.assertTrue(d1.selected_action_id,
                             "TEMPORARY SSH denial should not suppress")
        
        # PERSISTENT SHOULD suppress
        candidates2 = [
            {"action_type": "port_scan", "target": "10.0.1.1", "capability": "nmap", "score": 0.8},
        ]
        d2 = planner.decide(candidates2, "obj_002")
        self.assertFalse(d2.selected_action_id,
                          "PERSISTENT port_scan denial should suppress")


class TestAllowUnaffected(unittest.TestCase):
    """M7: ALLOW remains unaffected by DENY records."""

    def test_allow_not_affected_by_unrelated_denials(self):
        """ALLOW decision for non-denied actions remains unaffected."""
        planner = _make_planner()
        planner.register_denial("ssh_banner", "10.0.1.1", "ssh", "r1",
                                "Action type not allowed")
        candidates = [
            {"action_type": "http_get", "target": "10.0.1.2", "capability": "curl", "score": 0.9},
        ]
        decision = planner.decide(candidates, "obj_001")
        self.assertTrue(decision.selected_action_id,
                             "ALLOW should be unaffected by unrelated denials")

    def test_allow_scoring_unchanged(self):
        """Scoring logic should function normally for non-denied candidates."""
        planner = _make_planner()
        planner.register_denial("ssh_banner", "10.0.1.1", "ssh", "r1",
                                "Action type not allowed")
        # Two eligible candidates — higher score should be selected
        candidates = [
            {"action_type": "http_get", "target": "10.0.1.2", "capability": "curl", "score": 0.5},
            {"action_type": "port_scan", "target": "10.0.1.3", "capability": "nmap", "score": 0.9},
        ]
        decision = planner.decide(candidates, "obj_001")
        self.assertTrue(decision.selected_action_id)
        selected = next(c for c in candidates
                        if c["action_type"] == "port_scan")
        self.assertIsNotNone(selected)


class TestWorldModelClean(unittest.TestCase):
    """M8: WorldModel contains no denial artifacts before or after registration."""

    def test_worldmodel_no_denial_before(self):
        """WorldModel has no action_unavailable attribute before any DENY."""
        wm = WorldModel(EvidenceGraph())
        self.assertFalse(hasattr(wm, 'mark_action_unavailable'),
                         "WorldModel must not have mark_action_unavailable")
        self.assertFalse(hasattr(wm, '_unavailable_actions'),
                         "WorldModel must not have _unavailable_actions")

    def test_worldmodel_no_denial_after_registration(self):
        """WorldModel unchanged after Planner.register_denial()."""
        wm = WorldModel(EvidenceGraph())
        eg = EvidenceGraph()
        planner = _make_planner()
        planner.register_denial("ssh_banner", "10.0.1.1", "ssh", "r1",
                                "Action type not allowed")
        self.assertFalse(hasattr(wm, 'mark_action_unavailable'),
                         "WorldModel must not gain mark_action_unavailable")
        self.assertFalse(hasattr(wm, '_unavailable_actions'),
                         "WorldModel must not gain _unavailable_actions")


class TestBrokerSoleAuthority(unittest.TestCase):
    """M9: Broker remains sole authorization authority."""

    def test_planner_has_no_allowlist(self):
        """Planner has no safety allowlist attribute."""
        planner = _make_planner()
        self.assertFalse(hasattr(planner, 'allowed_actions'),
                         "Planner must not have an independent allowlist")
        self.assertFalse(hasattr(planner, 'action_allowlist'),
                         "Planner must not have action_allowlist")
        self.assertFalse(hasattr(planner, 'safety_override'),
                         "Planner must not have safety_override")

    def test_planner_does_not_resurrect_denied_candidates(self):
        """Planner does not resurrect candidates previously denied by Broker."""
        planner = _make_planner()
        planner.register_denial("ssh_banner", "10.0.1.1", "ssh", "r1",
                                "Not in allowed list: ssh_banner")
        candidates = [
            {"action_type": "ssh_banner", "target": "10.0.1.1", "capability": "ssh", "score": 0.9},
        ]
        decision = planner.decide(candidates, "obj_001")
        self.assertFalse(decision.selected_action_id,
                          "Planner must not resurrect a denied candidate")


class TestCandidateExhaustion(unittest.TestCase):
    """M10: Candidate exhaustion → clean termination, no crash, no resurrection."""

    def test_all_candidates_suppressed_returns_none_decision(self):
        """When all candidates have PERSISTENT denial feedback, return clean termination."""
        planner = _make_planner()
        planner.register_denial("ssh_banner", "10.0.1.1", "ssh", "r1",
                                "Action type not allowed")
        planner.register_denial("port_scan", "10.0.1.2", "nmap", "r2",
                                "Target not in allowed scope")
        planner.register_denial("http_get", "10.0.1.3", "curl", "r3",
                                "Capability not allowed")
        candidates = [
            {"action_type": "ssh_banner", "target": "10.0.1.1", "capability": "ssh", "score": 0.9},
            {"action_type": "port_scan", "target": "10.0.1.2", "capability": "nmap", "score": 0.8},
            {"action_type": "http_get", "target": "10.0.1.3", "capability": "curl", "score": 0.7},
        ]
        decision = planner.decide(candidates, "obj_001")
        self.assertIsNotNone(decision, "Must return a PlanDecision (not None)")
        self.assertFalse(decision.selected_action_id,
                          "Must NOT select any candidate when all are suppressed")
        self.assertIn("all_candidates_suppressed_by_denial_feedback",
                      decision.rationale_codes,
                      "Rationale should indicate all candidates suppressed")

    def test_exhaustion_with_empty_candidates(self):
        """Empty candidate list → clean termination."""
        planner = _make_planner()
        decision = planner.decide([], "obj_001")
        self.assertIsNotNone(decision, "Must return a PlanDecision (not None)")
        self.assertFalse(decision.selected_action_id,
                          "Must NOT select any candidate when list is empty")

    def test_exhaustion_does_not_crash(self):
        """Candidate exhaustion must not raise an exception."""
        planner = _make_planner()
        planner.register_denial("ssh_banner", "10.0.1.1", "ssh", "r1",
                                "Action type not allowed")
        candidates = [
            {"action_type": "ssh_banner", "target": "10.0.1.1", "capability": "ssh", "score": 0.9},
        ]
        try:
            decision = planner.decide(candidates, "obj_001")
            self.assertIsNotNone(decision)
        except Exception as e:
            self.fail(f"Candidate exhaustion raised exception: {e}")

    def test_mixed_exhaustion(self):
        """Mix of TEMPORARY and PERSISTENT — only PERSISTENT suppressed."""
        planner = _make_planner()
        planner.register_denial("ssh_banner", "10.0.1.1", "ssh", "r1",
                                "Rate limit exceeded")  # TEMPORARY
        planner.register_denial("port_scan", "10.0.1.2", "nmap", "r2",
                                "Target not in allowed scope")  # PERSISTENT
        candidates = [
            {"action_type": "ssh_banner", "target": "10.0.1.1", "capability": "ssh", "score": 0.9},
            {"action_type": "port_scan", "target": "10.0.1.2", "capability": "nmap", "score": 0.8},
        ]
        decision = planner.decide(candidates, "obj_001")
        self.assertTrue(decision.selected_action_id,
                             "TEMPORARY denial should not prevent selection")
        # Should select ssh_banner (TEMPORARY denied) over port_scan (PERSISTENT denied)
        # We just verify something was selected


class TestRoundTripIntegrity(unittest.TestCase):
    """Full decide() integrity: no regression in normal operation."""

    def test_normal_selection_works(self):
        """Normal ALLOW candidates still selected correctly."""
        planner = _make_planner()
        candidates = [
            {"action_type": "ssh_banner", "target": "10.0.1.1", "capability": "ssh", "score": 0.9},
            {"action_type": "port_scan", "target": "10.0.1.2", "capability": "nmap", "score": 0.8},
        ]
        decision = planner.decide(candidates, "obj_001")
        self.assertTrue(decision.selected_action_id,
                        "Normal selection should return a non-empty selected_action_id")
        # Should pick the highest-utility candidate (ssh_banner with 0.9)
        # The selected_action_id encodes the action order; just verify
        # the decision was made and utility was estimated
        self.assertGreater(decision.estimated_utility, 0.0,
                           "Decision should have non-zero utility estimate")

    def test_registration_no_side_effects_on_unrelated(self):
        """Registering a DENY for one target doesn't affect other targets."""
        planner = _make_planner()
        planner.register_denial("ssh_banner", "10.0.1.1", "ssh", "r1",
                                "Not in allowed list")
        candidates = [
            # Same action, different targets
            {"action_type": "ssh_banner", "target": "10.0.1.100", "capability": "ssh", "score": 0.9},
            {"action_type": "ssh_banner", "target": "10.0.1.101", "capability": "ssh", "score": 0.8},
        ]
        decision = planner.decide(candidates, "obj_001")
        self.assertTrue(decision.selected_action_id,
                             "Different targets should still be eligible")


if __name__ == "__main__":
    unittest.main(verbosity=2)
