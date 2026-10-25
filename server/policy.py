"""Policy kernel: deterministic, no LLM, no I/O. Strictest applicable rule wins: DENY > HOLD > ALLOW.

Rules: P1 invalid | P2 not your account | P3 funds/daily limit | P4 new payee > GBP 250 |
P5 HIGH risk | P6 mule payee | P7 too many attempts | P8 token (enforced in the ledger) |
P9 payee changed this session.
"""
import threading
import time
from dataclasses import dataclass
from typing import FrozenSet

from .schemas import DecisionType, PaymentProposal, PolicyDecision, RiskBand

NEW_PAYEE_LIMIT_PENCE = 25_000   # GBP 250
MAX_ATTEMPTS = 3
ATTEMPT_WINDOW_SECONDS = 300
LOCK_SECONDS = 600
SECOND_APPROVERS = {"customer", "trusted_contact"}


@dataclass(frozen=True)
class PolicyContext:
    owned_accounts: FrozenSet[str]
    account_exists: bool
    balance_pence: int
    daily_limit_pence: int
    daily_total_pence: int
    payee_exists: bool
    payee_known: bool
    payee_is_mule: bool
    attempts_in_window: int
    session_locked: bool
    payee_changed_in_session: bool
    risk_band: RiskBand
    approvals: FrozenSet[str] = frozenset()


def _deny(rule, reason, triggered, lock=False):
    return PolicyDecision(decision=DecisionType.DENY, rule_id=rule, reason=reason,
                          lock_session=lock, triggered=triggered)


def _evaluate(proposal, ctx):
    # P1 - invalid input: nothing else can be trusted, stop here.
    if not isinstance(proposal, PaymentProposal) or not isinstance(ctx, PolicyContext):
        return _deny("P1", "INVALID_PROPOSAL", ["P1"])
    amount = proposal.amount_pence
    if isinstance(amount, bool) or not isinstance(amount, int) or amount <= 0:
        return _deny("P1", "INVALID_AMOUNT", ["P1"])
    if not proposal.account_id or not proposal.payee_id or not ctx.payee_exists:
        return _deny("P1", "UNKNOWN_PAYEE_OR_ACCOUNT", ["P1"])
    try:
        band = RiskBand(ctx.risk_band)
    except ValueError:
        band = RiskBand.HIGH   # fail closed

    # DENY rules, in priority order
    denies = []
    if not ctx.account_exists or proposal.account_id not in ctx.owned_accounts:
        denies.append(("P2", "ACCOUNT_NOT_OWNED"))
    if amount > ctx.balance_pence:
        denies.append(("P3", "INSUFFICIENT_FUNDS"))
    elif ctx.daily_total_pence + amount > ctx.daily_limit_pence:
        denies.append(("P3", "DAILY_LIMIT_EXCEEDED"))
    if ctx.payee_is_mule:
        denies.append(("P6", "MULE_PAYEE"))
    if ctx.session_locked:
        denies.append(("P7", "SESSION_LOCKED"))
    elif ctx.attempts_in_window > MAX_ATTEMPTS:
        denies.append(("P7", "TOO_MANY_ATTEMPTS"))
    if denies:
        rule, reason = denies[0]
        return _deny(rule, reason, [r for r, _ in denies], lock=any(r == "P7" for r, _ in denies))

    # HOLD rules (cleared only by the right approvals)
    holds = []
    second_ok = bool(ctx.approvals & SECOND_APPROVERS)
    if ctx.payee_changed_in_session and not second_ok:
        holds.append(("P9", "PAYEE_CHANGED_SAME_SESSION", False))
    if (not ctx.payee_known) and amount > NEW_PAYEE_LIMIT_PENCE and not second_ok:
        holds.append(("P4", "NEW_PAYEE_OVER_LIMIT", False))
    if band == RiskBand.HIGH and "trusted_contact" not in ctx.approvals:
        holds.append(("P5", "HIGH_RISK", True))
    if holds:
        needs_tc = any(h[2] for h in holds)
        pick = next((h for h in holds if h[2]), holds[0])   # P5 wins: it needs the trusted contact
        return PolicyDecision(decision=DecisionType.HOLD, rule_id=pick[0], reason=pick[1],
                              requires_trusted_contact=needs_tc, triggered=[h[0] for h in holds])

    return PolicyDecision(decision=DecisionType.ALLOW, rule_id="NONE", reason="NO_RESTRICTIONS")


def evaluate(proposal, ctx):
    """Fail closed: any crash becomes DENY."""
    try:
        return _evaluate(proposal, ctx)
    except Exception:
        return _deny("P0", "POLICY_ERROR", ["P0"])


class SessionTracker:
    """Per-session attempt counting, 10-minute locks and payee-change flag."""

    def __init__(self, clock=time.time):
        self._clock = clock
        self._attempts = {}
        self._locked_until = {}
        self._payee_changed = set()
        self._lock = threading.Lock()

    def _prune(self, session_id):
        cutoff = self._clock() - ATTEMPT_WINDOW_SECONDS
        self._attempts[session_id] = [t for t in self._attempts.get(session_id, []) if t > cutoff]

    def record_attempt(self, session_id):
        with self._lock:
            self._prune(session_id)
            self._attempts[session_id].append(self._clock())
            return len(self._attempts[session_id])

    def count(self, session_id):
        with self._lock:
            self._prune(session_id)
            return len(self._attempts[session_id])

    def lock(self, session_id):
        with self._lock:
            self._locked_until[session_id] = self._clock() + LOCK_SECONDS

    def is_locked(self, session_id):
        with self._lock:
            return self._locked_until.get(session_id, 0) > self._clock()

    def mark_payee_changed(self, session_id):
        with self._lock:
            self._payee_changed.add(session_id)

    def payee_changed(self, session_id):
        with self._lock:
            return session_id in self._payee_changed
