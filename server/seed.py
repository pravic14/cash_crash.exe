"""Fictional demo data. Margaret has a usual rent payee, plus a scam payee and a mule payee."""
from .ledger import Ledger


def make_demo_ledger(authority, clock=None, db_path=None):
    accounts = {
        "A001": {"owner": "margaret", "balance_pence": 500_000, "daily_limit_pence": 400_000},
        "A900": {"owner": "landlord", "balance_pence": 0, "daily_limit_pence": 0},
        "A901": {"owner": "scammer", "balance_pence": 0, "daily_limit_pence": 0},
    }
    payees = {
        "RENT001": {"name": "Landlord", "account_id": "A900", "mule": False},
        "SAFE999": {"name": "HMRC Safe Account", "account_id": "A901", "mule": False},
        "MULE001": {"name": "Known mule", "account_id": "A901", "mule": True},
    }
    known = {"A001": {"RENT001"}}
    kwargs = {"db_path": db_path}
    if clock:
        kwargs["clock"] = clock
    return Ledger(accounts, payees, known, authority, **kwargs)
