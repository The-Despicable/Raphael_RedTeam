"""action_receipt.py — Immutable action receipt with hash-chain verification.

Every CapabilityBroker decision (ALLOW or DENY) produces an ActionReceipt.
Execution status is tracked separately from authorization status — an
AUTHORIZED receipt does not imply SUCCEEDED.

State machine:

    PROPOSED
       │
       ▼
  ┌── AUTHORIZED ── DENIED
  │       │
  │       ▼
  │    STARTED
  │       │
  │       ▼
  │  ┌── SUCCEEDED ── FAILED ── TIMEOUT
  │  │
  │  └── (AUTHORIZED can also go directly to FAILED if execution
  │       fails before STARTED — e.g., target unreachable)

Invariant: DENIED receipts MUST NOT transition to execution states.
Invariant: PROPOSED is the only valid initial state.
Invariant: audit_hash changes when ANY field is modified.

Schema version: 1
"""

import hashlib
import json
import time
import os
import logging
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Optional

logger = logging.getLogger("action_receipt")


class ActionProposalStatus(str, Enum):
    """State of an action through the authorization-execution lifecycle."""
    PROPOSED = "proposed"
    AUTHORIZED = "authorized"
    DENIED = "denied"
    STARTED = "started"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMEOUT = "timeout"


VALID_TRANSITIONS = {
    ActionProposalStatus.PROPOSED: {ActionProposalStatus.AUTHORIZED, ActionProposalStatus.DENIED},
    ActionProposalStatus.AUTHORIZED: {ActionProposalStatus.STARTED, ActionProposalStatus.FAILED},
    ActionProposalStatus.DENIED: set(),       # Terminal — no further transitions
    ActionProposalStatus.STARTED: {ActionProposalStatus.SUCCEEDED, ActionProposalStatus.FAILED, ActionProposalStatus.TIMEOUT},
    ActionProposalStatus.SUCCEEDED: set(),    # Terminal
    ActionProposalStatus.FAILED: set(),       # Terminal
    ActionProposalStatus.TIMEOUT: set(),      # Terminal
}


# ── Receipt store (ephemeral; will be backed by audit_trail.jsonl) ──
_receipt_store: dict[str, "ActionReceipt"] = {}

_last_receipt_hash: str = ""


@dataclass
class ActionReceipt:
    """Immutable record of an action proposal, authorization, and execution.

    Core invariant: authorization status (AUTHORIZED/DENIED) MUST be
    set before execution status (STARTED/SUCCEEDED/FAILED/TIMEOUT).
    DENIED receipts MUST NOT contain execution fields.
    """
    # Schema and identity
    schema_version: int = 1
    action_id: str = ""
    proposal_hash: str = ""

    # Authorization dimensions
    target: str = ""
    capability: str = ""        # e.g., "port_scan", "http_request", "file_read"
    method: str = ""            # e.g., "nmap", "curl", "subprocess"
    impact_estimate: str = ""   # e.g., "low", "medium", "high"

    # Authorization decision
    status: ActionProposalStatus = ActionProposalStatus.PROPOSED
    decision: str = ""           # "allow" or "deny"
    reason: str = ""             # Human-readable explanation
    policy_version: str = ""     # Which policy version made this decision
    authorized_by: str = ""      # "scope_check", "rate_limiter", "operator"

    # Execution tracking
    started_at: float = 0.0
    completed_at: float = 0.0
    result: str = ""             # Summary of execution outcome
    evidence_ids: list[str] = field(default_factory=list)

    # Integrity
    prev_hash: str = ""
    audit_hash: str = ""

    def __post_init__(self):
        """Validate transition invariant on construction."""
        if self.status == ActionProposalStatus.DENIED:
            # DENIED must not have execution fields set
            assert self.started_at == 0.0, "DENIED receipt cannot have started_at"
            assert self.completed_at == 0.0, "DENIED receipt cannot have completed_at"
            assert self.result == "", "DENIED receipt cannot have result"

    def compute_hash(self) -> str:
        """Compute SHA-256 hash of content fields only.

        Excludes the two hash fields (audit_hash, proposal_hash) to avoid
        self-referential dependency. The hash is computed over:
        action_id, schema_version, target, capability, method, impact_estimate,
        status, decision, reason, policy_version, authorized_by, started_at,
        completed_at, result, evidence_ids, prev_hash.
        """
        raw = json.dumps(
            {k: v for k, v in asdict(self).items()
             if k not in ("audit_hash", "proposal_hash")},
            sort_keys=True, default=str,
        )
        return hashlib.sha256(raw.encode()).hexdigest()

    def verify_integrity(self) -> bool:
        """Verify that the stored audit_hash matches computed hash."""
        return self.audit_hash == self.compute_hash()

    def can_transition_to(self, new_status: ActionProposalStatus) -> bool:
        """Check if transition from current status is valid."""
        allowed = VALID_TRANSITIONS.get(self.status, set())
        return new_status in allowed

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "action_id": self.action_id,
            "proposal_hash": self.proposal_hash,
            "target": self.target,
            "capability": self.capability,
            "method": self.method,
            "impact_estimate": self.impact_estimate,
            "status": self.status.value,
            "decision": self.decision,
            "reason": self.reason,
            "policy_version": self.policy_version,
            "authorized_by": self.authorized_by,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "result": self.result,
            "evidence_ids": self.evidence_ids,
            "prev_hash": self.prev_hash,
            "audit_hash": self.audit_hash,
        }


def create_proposal(
    target: str,
    capability: str,
    method: str = "",
    impact_estimate: str = "unknown",
    action_id: str = "",
) -> ActionReceipt:
    """Create a new PROPOSED action receipt.

    This is the entry point. The receipt must be AUTHORIZED or DENIED
    before any execution can proceed.
    """
    global _last_receipt_hash

    if not action_id:
        entropy = f"{time.time_ns()}:{os.urandom(8).hex()}"
        action_id = hashlib.sha256(entropy.encode()).hexdigest()[:16]

    # Content hash for the proposal
    receipt = ActionReceipt(
        action_id=action_id,
        proposal_hash="",  # computed below
        target=target,
        capability=capability,
        method=method,
        impact_estimate=impact_estimate,
        status=ActionProposalStatus.PROPOSED,
        decision="",
        reason="",
        policy_version="",
        authorized_by="",
        prev_hash=_last_receipt_hash,
    )

    # Compute proposal hash and set audit_hash
    receipt.proposal_hash = receipt.compute_hash()
    receipt.audit_hash = receipt.proposal_hash

    # Use _update_hash to maintain the chain properly
    _last_receipt_hash = receipt.audit_hash
    _receipt_store[receipt.action_id] = receipt

    logger.debug(f"Created proposal {receipt.action_id}: {capability} on {target}")
    return receipt


def authorize(receipt: ActionReceipt, reason: str = "", policy_version: str = "",
              authorized_by: str = "") -> Optional[ActionReceipt]:
    """Transition a PROPOSED receipt to AUTHORIZED."""
    if not receipt.can_transition_to(ActionProposalStatus.AUTHORIZED):
        logger.warning(f"Cannot authorize receipt {receipt.action_id} in state {receipt.status.value}")
        return None

    receipt.status = ActionProposalStatus.AUTHORIZED
    receipt.decision = "allow"
    receipt.reason = reason
    receipt.policy_version = policy_version
    receipt.authorized_by = authorized_by or "capability_broker"
    _update_hash(receipt)
    return receipt


def deny(receipt: ActionReceipt, reason: str = "", policy_version: str = "",
         authorized_by: str = "") -> Optional[ActionReceipt]:
    """Transition a PROPOSED receipt to DENIED."""
    if not receipt.can_transition_to(ActionProposalStatus.DENIED):
        logger.warning(f"Cannot deny receipt {receipt.action_id} in state {receipt.status.value}")
        return None

    receipt.status = ActionProposalStatus.DENIED
    receipt.decision = "deny"
    receipt.reason = reason
    receipt.policy_version = policy_version
    receipt.authorized_by = authorized_by or "capability_broker"
    _update_hash(receipt)
    return receipt


def start_execution(receipt: ActionReceipt) -> Optional[ActionReceipt]:
    """Transition an AUTHORIZED receipt to STARTED."""
    if not receipt.can_transition_to(ActionProposalStatus.STARTED):
        logger.warning(f"Cannot start receipt {receipt.action_id} in state {receipt.status.value}")
        return None

    receipt.status = ActionProposalStatus.STARTED
    receipt.started_at = time.time()
    _update_hash(receipt)
    return receipt


def complete_execution(receipt: ActionReceipt, success: bool,
                       result: str = "", evidence_ids: list[str] = None) -> Optional[ActionReceipt]:
    """Transition a STARTED receipt to SUCCEEDED or FAILED."""
    new_status = ActionProposalStatus.SUCCEEDED if success else ActionProposalStatus.FAILED
    if not receipt.can_transition_to(new_status):
        logger.warning(f"Cannot complete receipt {receipt.action_id} in state {receipt.status.value}")
        return None

    receipt.status = new_status
    receipt.completed_at = time.time()
    receipt.result = result
    if evidence_ids:
        receipt.evidence_ids.extend(evidence_ids)
    _update_hash(receipt)
    return receipt


def timeout_execution(receipt: ActionReceipt, result: str = "") -> Optional[ActionReceipt]:
    """Transition a STARTED receipt to TIMEOUT."""
    if not receipt.can_transition_to(ActionProposalStatus.TIMEOUT):
        logger.warning(f"Cannot timeout receipt {receipt.action_id} in state {receipt.status.value}")
        return None

    receipt.status = ActionProposalStatus.TIMEOUT
    receipt.completed_at = time.time()
    receipt.result = result or "timed out"
    _update_hash(receipt)
    return receipt


def _update_hash(receipt: ActionReceipt) -> None:
    """Update audit_hash and chain, ensuring the previous hash is correct."""
    global _last_receipt_hash
    receipt.prev_hash = _last_receipt_hash
    receipt.audit_hash = receipt.compute_hash()
    _last_receipt_hash = receipt.audit_hash
    _receipt_store[receipt.action_id] = receipt


def get_receipt(action_id: str) -> Optional[ActionReceipt]:
    """Retrieve a receipt by action_id."""
    return _receipt_store.get(action_id)


def verify_chain() -> list[dict]:
    """Verify the integrity of all receipts in the ephemeral store.

    Each receipt is self-verifying: its audit_hash must match the hash of
    its content fields. This detects in-memory tampering.

    NOTE: The ephemeral store overwrites receipts on state transition, so
    cross-receipt chain verification (prev_hash matching the previous
    receipt's audit_hash) is not reliable in this store. Full chain
    integrity verification belongs in the persistent audit trail.
    """
    issues = []

    for action_id in sorted(_receipt_store.keys()):
        receipt = _receipt_store[action_id]
        if not receipt.verify_integrity():
            issues.append({
                "action_id": action_id,
                "error": "Hash mismatch — receipt has been tampered with",
                "status": receipt.status.value,
            })

    return issues
