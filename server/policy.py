"""G5 policy kernel. The only place a payment can be ALLOW, HOLD, or DENY.

DENY wins over HOLD. A customer approval can clear P4 and P9.
Only a trusted contact can clear P5. P6, P3, P2, P7, and P1 still deny.
A crash denies. This module does not move money.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from server.sessions import Session
from shared.schemas import IntentName, PaymentProposal, PolicyId, RiskBand, Verdict

ATTEMPT_WINDOW_SECONDS = 300
LOCK_SECONDS = 600
NEW_PAYEE_HOLD = 250.0


@dataclass
class Decision:
    verdict: Verdict | None
    matched_policy: PolicyId | None
    reason: str
    requires_trusted_contact: bool = False


def decide(
    proposal: PaymentProposal,
    session: Session,
    accounts: dict,
    payees: dict,
    now: datetime,
    payee_changed: bool = False,
    approvals: frozenset[str] = frozenset(),
) -> Decision:
    """First matching hard rule. None means this was not a payment."""

    try:
        return _decide(proposal, session, accounts, payees, now, payee_changed, approvals)
    except Exception:
        return Decision(Verdict.DENY, PolicyId.P1_SCHEMA, "The policy check failed closed.")


def _decide(
    proposal: PaymentProposal,
    session: Session,
    accounts: dict,
    payees: dict,
    now: datetime,
    payee_changed: bool,
    approvals: frozenset[str],
) -> Decision:
    if proposal.payer_account != session.account_id or proposal.session_id != session.session_id:
        return Decision(Verdict.DENY, PolicyId.P2_OWNER, "This session does not own that account.")

    if proposal.intent != IntentName.PAY:
        if proposal.intent == IntentName.UNKNOWN:
            return Decision(Verdict.DENY, PolicyId.P1_SCHEMA, "The parser did not return a known intent.")
        return Decision(None, None, "No payment was requested.")

    stamp = _epoch(now)
    locked = _velocity(session, stamp)
    if locked is not None:
        return locked

    if proposal.amount is None or proposal.amount <= 0:
        return Decision(Verdict.DENY, PolicyId.P1_SCHEMA, "A payment needs an amount above zero.")

    record = payees.get(proposal.payee_id) if proposal.payee_id else None
    if record is not None and record.get("mule"):
        return Decision(Verdict.DENY, PolicyId.P6_MULE, "That payee is on the mule list.")

    account = accounts.get(proposal.payer_account)
    if account is None:
        return Decision(Verdict.DENY, PolicyId.P2_OWNER, "That account does not exist.")
    limit_reason = _over_limit(proposal.amount, account)
    if limit_reason is not None:
        return Decision(Verdict.DENY, PolicyId.P3_LIMIT, limit_reason)

    second = bool(approvals & {"customer", "trusted_contact"})
    if payee_changed and session.saw_payment and not second:
        return Decision(Verdict.HOLD, PolicyId.P9_PAYEE_CHANGE, "Payee details changed during this session.")

    if proposal.band == RiskBand.HIGH and "trusted_contact" not in approvals:
        return Decision(
            Verdict.HOLD,
            PolicyId.P5_HIGH_RISK,
            "Combined risk is HIGH. A trusted contact has to decide.",
            True,
        )

    if (
        not second
        and proposal.payee_id
        and _is_new(proposal.payee_id, session.account_id, payees)
        and proposal.amount > NEW_PAYEE_HOLD
    ):
        return Decision(Verdict.HOLD, PolicyId.P4_NEW_PAYEE, "A new payee above £250 is held.")

    if not proposal.payee_id:
        # A cited scam card is not a real payee. Hold it.
        # A plain payment with no destination still denies.
        if "trusted_contact" not in approvals and proposal.cited_card_id:
            return Decision(
                Verdict.HOLD,
                PolicyId.P5_HIGH_RISK,
                "There is no saved payee, and this message is not proven safe. A trusted contact has to decide.",
                True,
            )
        return Decision(Verdict.DENY, PolicyId.P1_SCHEMA, "A payment needs a known payee.")

    return Decision(Verdict.ALLOW, None, "No hard rule matched.")


def payee_fingerprint(payees: dict) -> dict[str, str]:
    return {
        payee_id: f"{record.get('name', '')}|{record.get('reference', '')}"
        for payee_id, record in payees.items()
    }


def payees_changed(session: Session, payees: dict) -> bool:
    """Remember the first snapshot. A later difference is P9."""

    current = payee_fingerprint(payees)
    if session.payee_fingerprint is None:
        session.payee_fingerprint = current
        return False
    return session.payee_fingerprint != current


def _velocity(session: Session, stamp: float) -> Decision | None:
    if session.locked_until is not None and stamp < session.locked_until:
        return Decision(Verdict.DENY, PolicyId.P7_VELOCITY, "This session is locked after too many attempts.")
    session.attempts = [item for item in session.attempts if stamp - item < ATTEMPT_WINDOW_SECONDS]
    session.attempts.append(stamp)
    if len(session.attempts) > 3:
        session.locked_until = stamp + LOCK_SECONDS
        return Decision(Verdict.DENY, PolicyId.P7_VELOCITY, "More than three payment attempts in five minutes.")
    return None


def _over_limit(amount: float, account: dict) -> str | None:
    balance = float(account["balance"])
    limit = float(account["daily_limit"])
    spent = float(account.get("daily_spent") or 0)
    if amount > balance:
        return "The amount is over the balance."
    if amount > limit or spent + amount > limit:
        return "The amount is over the daily limit."
    return None


def _is_new(payee_id: str, account_id: str, payees: dict) -> bool:
    record = payees.get(payee_id) or {}
    return account_id not in (record.get("known_by") or [])


def _epoch(now: datetime) -> float:
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    return now.timestamp()
