import random

import pytest

from server.policy import PolicyContext, SessionTracker, evaluate
from server.schemas import DecisionType, RiskBand
from tests.helpers import Clock, make_proposal


def ctx(**kw):
    base = dict(owned_accounts=frozenset({"A001"}), account_exists=True, balance_pence=500_000,
                daily_limit_pence=400_000, daily_total_pence=0, payee_exists=True, payee_known=True,
                payee_is_mule=False, attempts_in_window=1, session_locked=False,
                payee_changed_in_session=False, risk_band=RiskBand.LOW)
    base.update(kw)
    return PolicyContext(**base)


def check(decision, rule):
    assert decision.decision == decision_for[rule[0]], decision
    assert decision.rule_id == rule[1], decision


decision_for = {"A": DecisionType.ALLOW, "H": DecisionType.HOLD, "D": DecisionType.DENY}


def test_usual_payment_low_risk_allowed():
    check(evaluate(make_proposal(), ctx()), ("A", "NONE"))


def test_new_payee_over_250_holds():
    d = evaluate(make_proposal(amount_pence=50_000), ctx(payee_known=False))
    check(d, ("H", "P4"))
    assert not d.requires_trusted_contact


def test_new_payee_at_or_under_250_allowed():
    check(evaluate(make_proposal(amount_pence=25_000), ctx(payee_known=False)), ("A", "NONE"))


def test_high_risk_holds_with_trusted_contact():
    d = evaluate(make_proposal(), ctx(risk_band=RiskBand.HIGH))
    check(d, ("H", "P5"))
    assert d.requires_trusted_contact


def test_mule_denied():
    check(evaluate(make_proposal(), ctx(payee_is_mule=True)), ("D", "P6"))


def test_mule_beats_high_risk():
    check(evaluate(make_proposal(), ctx(payee_is_mule=True, risk_band=RiskBand.HIGH)), ("D", "P6"))


def test_over_balance_denied():
    check(evaluate(make_proposal(amount_pence=600_000), ctx()), ("D", "P3"))


def test_over_daily_limit_denied():
    check(evaluate(make_proposal(amount_pence=100_000), ctx(daily_total_pence=350_000)), ("D", "P3"))


def test_wrong_account_owner_denied():
    check(evaluate(make_proposal(account_id="A900"), ctx()), ("D", "P2"))


def test_fourth_attempt_denied_and_locks():
    check(evaluate(make_proposal(), ctx(attempts_in_window=3)), ("A", "NONE"))
    d = evaluate(make_proposal(), ctx(attempts_in_window=4))
    check(d, ("D", "P7"))
    assert d.lock_session


def test_locked_session_denied():
    check(evaluate(make_proposal(), ctx(session_locked=True)), ("D", "P7"))


def test_payee_changed_same_session_holds():
    check(evaluate(make_proposal(), ctx(payee_changed_in_session=True)), ("H", "P9"))


def test_invalid_proposals_denied():
    for bad in (None, "x", {}, 5):
        check(evaluate(bad, ctx()), ("D", "P1"))
    check(evaluate(make_proposal(amount_pence=0), ctx()), ("D", "P1"))
    check(evaluate(make_proposal(amount_pence=-5), ctx()), ("D", "P1"))
    check(evaluate(make_proposal(), ctx(payee_exists=False)), ("D", "P1"))
    check(evaluate(make_proposal(), None), ("D", "P1"))


def test_approvals_clear_the_right_holds():
    p = make_proposal(amount_pence=50_000)
    c = dict(payee_known=False, risk_band=RiskBand.HIGH)
    check(evaluate(p, ctx(**c, approvals=frozenset({"customer"}))), ("H", "P5"))   # customer can't clear P5
    check(evaluate(p, ctx(**c, approvals=frozenset({"trusted_contact"}))), ("A", "NONE"))
    check(evaluate(p, ctx(payee_known=False, approvals=frozenset({"customer"}))), ("A", "NONE"))


def test_unknown_risk_band_fails_closed():
    check(evaluate(make_proposal(), ctx(risk_band="WAT")), ("H", "P5"))


def test_random_proposals_never_beat_ownership_or_mule_rules():
    rng = random.Random(1234)
    for _ in range(3000):
        p = make_proposal(account_id=rng.choice(["A001", "A900", "X"]), amount_pence=rng.randint(-10, 900_000))
        c = ctx(owned_accounts=frozenset({"A001"}), payee_is_mule=rng.random() < 0.3,
                risk_band=rng.choice(list(RiskBand)), payee_known=rng.random() < 0.5,
                approvals=frozenset(rng.sample(["customer", "trusted_contact"], rng.randint(0, 2))),
                attempts_in_window=rng.randint(0, 6))
        d = evaluate(p, c)
        if p.account_id != "A001" or p.amount_pence <= 0 or c.payee_is_mule:
            assert d.decision == DecisionType.DENY
        if c.attempts_in_window > 3:
            assert d.decision == DecisionType.DENY


def test_session_tracker_window_and_lock():
    clock = Clock()
    t = SessionTracker(clock)
    assert [t.record_attempt("S") for _ in range(4)] == [1, 2, 3, 4]
    clock.t += 301
    assert t.count("S") == 0
    t.lock("S")
    assert t.is_locked("S")
    clock.t += 601
    assert not t.is_locked("S")
