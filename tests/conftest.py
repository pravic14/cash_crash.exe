import pytest

from server.audit import AuditLog
from server.capabilities import TokenAuthority
from server.orchestrator import Orchestrator
from server.seed import make_demo_ledger
from tests.helpers import Clock


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def authority(clock):
    return TokenAuthority(secret=b"x" * 32, clock=clock)


@pytest.fixture
def ledger(authority, clock):
    return make_demo_ledger(authority, clock=clock)


@pytest.fixture
def system(authority, ledger, clock):
    audit = AuditLog(clock=clock)
    orch = Orchestrator(ledger, authority, audit, session_owners={"S1": "margaret"},
                        trusted_contacts={"A001": {"trusted_contact_1"}}, clock=clock)
    return orch, ledger, audit, authority
