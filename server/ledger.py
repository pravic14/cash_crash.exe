"""Fictional balances. `execute` is the only function that changes one.

A bad token raises LedgerDenied and leaves the balance as it was.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from server.tokens import TokenBook
from shared.schemas import PaymentProposal, PolicyId

ROOT = Path(__file__).resolve().parents[1]
ACCOUNTS_PATH = ROOT / "server" / "data" / "accounts.json"
PAYEES_PATH = ROOT / "server" / "data" / "payees.json"


class LedgerDenied(Exception):
    def __init__(self, policy: PolicyId, reason: str) -> None:
        self.policy = policy
        self.reason = reason
        super().__init__(reason)


class Ledger:
    def __init__(self, accounts: dict, tokens: TokenBook) -> None:
        self.accounts = accounts
        self.tokens = tokens

    def balance(self, account_id: str) -> float:
        return round(float(self.accounts[account_id]["balance"]), 2)

    def execute(self, proposal: PaymentProposal, token: str, now: datetime) -> float:
        """Debit only when the token matches this proposal and the funds are still there."""

        account = self.accounts.get(proposal.payer_account)
        if account is None or proposal.amount is None or proposal.payee_id is None:
            raise LedgerDenied(PolicyId.P8_TOKEN, "The ledger will not move money for this proposal.")
        amount = round(float(proposal.amount), 2)
        balance = round(float(account["balance"]), 2)
        spent = round(float(account.get("daily_spent") or 0), 2)
        limit = round(float(account["daily_limit"]), 2)
        if amount > balance or spent + amount > limit:
            raise LedgerDenied(PolicyId.P3_LIMIT, "The balance or the daily limit changed before execution.")
        if not self.tokens.consume(token, proposal, now):
            raise LedgerDenied(PolicyId.P8_TOKEN, "The capability token is missing, expired, reused, or for a different payment.")
        account["balance"] = round(balance - amount, 2)
        account["daily_spent"] = round(spent + amount, 2)
        return account["balance"]


def load_accounts(path: Path | None = None) -> dict:
    source = path or ACCOUNTS_PATH
    return json.loads(source.read_text(encoding="utf-8"))


def load_payees(path: Path | None = None) -> dict:
    source = path or PAYEES_PATH
    return json.loads(source.read_text(encoding="utf-8"))
