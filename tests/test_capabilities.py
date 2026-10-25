import threading

import pytest

from server.capabilities import TokenAuthority, TokenError
from tests.helpers import make_proposal


def test_valid_token_validates(authority):
    p = make_proposal()
    authority.validate(authority.mint(p), p)


def test_expired_token_fails(authority, clock):
    p = make_proposal()
    t = authority.mint(p)
    clock.t += 31
    with pytest.raises(TokenError, match="EXPIRED"):
        authority.validate(t, p)


def test_modified_token_fails(authority):
    p = make_proposal()
    t = authority.mint(p)
    t["claims"]["amount"] = 750_000
    with pytest.raises(TokenError, match="BAD_SIGNATURE"):
        authority.validate(t, make_proposal(amount_pence=750_000))


@pytest.mark.parametrize("change", [dict(account_id="A900"), dict(payee_id="SAFE999"),
                                    dict(amount_pence=750_000), dict(proposal_id="TXN999"),
                                    dict(session_id="S2")])
def test_token_bound_to_exact_payment(authority, change):
    t = authority.mint(make_proposal())
    with pytest.raises(TokenError, match="ARGUMENT_MISMATCH"):
        authority.validate(t, make_proposal(**change))


def test_reused_token_fails(authority):
    p = make_proposal()
    t = authority.mint(p)
    authority.consume(t)
    with pytest.raises(TokenError, match="ALREADY_USED"):
        authority.validate(t, p)
    with pytest.raises(TokenError):
        authority.consume(t)


def test_forged_and_garbage_tokens_fail(authority):
    p = make_proposal()
    forged = TokenAuthority(secret=b"y" * 32, clock=authority._clock).mint(p)
    for bad in (forged, None, "abc", {}, {"claims": {}, "sig": "x"}, {"claims": 1, "sig": 2}):
        with pytest.raises(TokenError):
            authority.validate(bad, p)


def test_two_simultaneous_consumes_only_one_wins(authority):
    t = authority.mint(make_proposal())
    results, barrier = [], threading.Barrier(20)

    def worker():
        barrier.wait()
        try:
            authority.consume(t)
            results.append("ok")
        except TokenError:
            results.append("fail")

    threads = [threading.Thread(target=worker) for _ in range(20)]
    [th.start() for th in threads]
    [th.join() for th in threads]
    assert results.count("ok") == 1
