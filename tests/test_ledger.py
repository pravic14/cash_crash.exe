import threading

import pytest

from server.ledger import LedgerError
from tests.helpers import make_proposal


def pay(ledger, authority, **kw):
    p = make_proposal(**kw)
    return p, authority.mint(p)


def test_correct_balances(ledger, authority):
    p, t = pay(ledger, authority)
    ledger.execute(p, t)
    assert ledger.balance("A001") == 425_000 and ledger.balance("A900") == 75_000


def test_no_token_fails(ledger):
    with pytest.raises(LedgerError) as e:
        ledger.execute(make_proposal(), None)
    assert e.value.rule_id == "P8" and ledger.balance("A001") == 500_000


def test_invalid_tokens_fail(ledger, authority):
    p = make_proposal()
    for bad in ("abc", {}, {"claims": {}, "sig": ""}):
        with pytest.raises(LedgerError):
            ledger.execute(p, bad)
    assert ledger.balance("A001") == 500_000


def test_token_for_other_amount_fails(ledger, authority):
    t = authority.mint(make_proposal(amount_pence=1_000))
    with pytest.raises(LedgerError):
        ledger.execute(make_proposal(amount_pence=100_000), t)


def test_insufficient_funds(ledger, authority):
    p, t = pay(ledger, authority, amount_pence=600_000)
    with pytest.raises(LedgerError) as e:
        ledger.execute(p, t)
    assert e.value.reason == "INSUFFICIENT_FUNDS"


def test_daily_limit(ledger, authority):
    p, t = pay(ledger, authority, amount_pence=450_000)
    with pytest.raises(LedgerError):
        ledger.execute(p, t)


@pytest.mark.parametrize("amount", [0, -5])
def test_non_positive_amounts_fail(ledger, authority, amount):
    p = make_proposal(amount_pence=amount)
    with pytest.raises(LedgerError):
        ledger.execute(p, {"claims": {}, "sig": ""})


def test_unknown_account_and_payee(ledger, authority):
    for kw in (dict(account_id="NOPE"), dict(payee_id="NOPE001")):
        p, t = pay(ledger, authority, **kw)
        with pytest.raises(LedgerError):
            ledger.execute(p, t)


def test_cannot_execute_twice(ledger, authority):
    p, t = pay(ledger, authority)
    ledger.execute(p, t)
    with pytest.raises(LedgerError):
        ledger.execute(p, t)
    assert ledger.balance("A001") == 425_000


def test_failed_payment_changes_nothing(ledger, authority):
    p, t = pay(ledger, authority, payee_id="MULE001")
    with pytest.raises(LedgerError):
        ledger.execute(p, t)
    assert ledger.balance("A001") == 500_000 and ledger.balance("A901") == 0 and ledger.history() == []


def test_concurrent_use_of_one_token_pays_once(ledger, authority):
    p, t = pay(ledger, authority)
    out, barrier = [], threading.Barrier(10)

    def worker():
        barrier.wait()
        try:
            ledger.execute(p, t)
            out.append("ok")
        except LedgerError:
            out.append("fail")

    ths = [threading.Thread(target=worker) for _ in range(10)]
    [x.start() for x in ths]
    [x.join() for x in ths]
    assert out.count("ok") == 1 and ledger.balance("A001") == 425_000


def test_no_other_file_mutates_balances():
    """Acceptance check: only ledger.py may change balances."""
    import pathlib
    import re
    pattern = re.compile(r"\[[\"']balance_pence[\"']\]\s*[-+*/]?=(?!=)")
    for f in pathlib.Path("server").glob("*.py"):
        if f.name != "ledger.py":
            assert not pattern.search(f.read_text()), f"{f} modifies balances"


# ----------------------------------------------------------------------------- SQLite persistence
def test_ledger_persists_across_restart(tmp_path, authority, clock):
    from server.seed import make_demo_ledger
    path = str(tmp_path / "ledger.db")
    L1 = make_demo_ledger(authority, clock=clock, db_path=path)
    p = make_proposal()
    L1.execute(p, authority.mint(p))
    acct = L1.open_account("bob", 1_000, 5_000, ("RENT001",))

    L2 = make_demo_ledger(authority, clock=clock, db_path=path)         # simulate a server restart
    assert L2.balance("A001") == 425_000 and L2.balance("A900") == 75_000
    assert L2.daily_total("A001") == 75_000                              # history reloaded for the daily limit
    assert L2.accounts_owned_by("bob") == [acct] and L2.payee_known(acct, "RENT001")
    assert len(L2.history()) == 1


def test_same_proposal_cannot_be_paid_twice_even_with_a_fresh_token(tmp_path, authority, clock):
    from server.seed import make_demo_ledger
    L = make_demo_ledger(authority, clock=clock, db_path=str(tmp_path / "l.db"))
    p = make_proposal()
    L.execute(p, authority.mint(p))
    with pytest.raises(LedgerError):
        L.execute(p, authority.mint(p))          # DB UNIQUE(proposal_id) stops it; memory state stays correct
    assert L.balance("A001") == 425_000 and len(L.history()) == 1
