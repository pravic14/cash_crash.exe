"""
Storage: pass db_path to persist in SQLite (accounts, payees, known payees, payment history). Memory stays the
working copy; every change is written to SQLite in one transaction before execute() returns.
"""
import copy
import datetime
import sqlite3
import threading
import time

from .capabilities import TokenAuthority, TokenError
from .schemas import PaymentProposal

LEDGER_SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY, owner TEXT NOT NULL,
    balance_pence INTEGER NOT NULL CHECK (balance_pence >= 0),
    daily_limit_pence INTEGER NOT NULL CHECK (daily_limit_pence >= 0));
CREATE TABLE IF NOT EXISTS payees (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, account_id TEXT NOT NULL, mule INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS known_payees (
    account_id TEXT NOT NULL, payee_id TEXT NOT NULL, PRIMARY KEY (account_id, payee_id));
CREATE TABLE IF NOT EXISTS payments (
    id INTEGER PRIMARY KEY AUTOINCREMENT, proposal_id TEXT NOT NULL UNIQUE, session_id TEXT NOT NULL,
    account_id TEXT NOT NULL, payee_id TEXT NOT NULL,
    amount_pence INTEGER NOT NULL CHECK (amount_pence > 0), day TEXT NOT NULL, created_at REAL NOT NULL);
"""


class LedgerError(Exception):
    def __init__(self, rule_id, reason):
        super().__init__(f"{rule_id}:{reason}")
        self.rule_id = rule_id
        self.reason = reason


class Ledger:
    def __init__(self, accounts, payees, known_payees, authority, clock=time.time, db_path=None):
        self._authority = authority
        self._clock = clock
        self._history = []
        self._lock = threading.RLock()
        self._db = None
        if db_path:
            self._db = sqlite3.connect(db_path, check_same_thread=False)
            self._db.executescript(LEDGER_SCHEMA)
            self._db.commit()
        if self._db and self._db.execute("SELECT COUNT(*) FROM accounts").fetchone()[0] > 0:
            self._load()
        else:
            self._accounts = copy.deepcopy(accounts)   # {id: {owner, balance_pence, daily_limit_pence}}
            self._payees = copy.deepcopy(payees)       # {id: {name, account_id, mule}}
            self._known = {k: set(v) for k, v in known_payees.items()}
            if self._db:
                self._persist_seed()

    # ---------- persistence ----------
    def _persist_seed(self):
        with self._db:
            self._db.executemany("INSERT INTO accounts VALUES (?,?,?,?)",
                                 [(i, a["owner"], a["balance_pence"], a["daily_limit_pence"])
                                  for i, a in self._accounts.items()])
            self._db.executemany("INSERT INTO payees VALUES (?,?,?,?)",
                                 [(i, p["name"], p["account_id"], int(bool(p.get("mule")))) for i, p in self._payees.items()])
            self._db.executemany("INSERT INTO known_payees VALUES (?,?)",
                                 [(a, p) for a, ps in self._known.items() for p in ps])

    def _load(self):
        self._accounts = {r[0]: {"owner": r[1], "balance_pence": r[2], "daily_limit_pence": r[3]}
                          for r in self._db.execute("SELECT id, owner, balance_pence, daily_limit_pence FROM accounts")}
        self._payees = {r[0]: {"name": r[1], "account_id": r[2], "mule": bool(r[3])}
                        for r in self._db.execute("SELECT id, name, account_id, mule FROM payees")}
        self._known = {}
        for a, p in self._db.execute("SELECT account_id, payee_id FROM known_payees"):
            self._known.setdefault(a, set()).add(p)
        self._history = [{"proposal_id": r[0], "session_id": r[1], "account_id": r[2], "payee_id": r[3],
                          "amount_pence": r[4], "day": datetime.date.fromisoformat(r[5])}
                         for r in self._db.execute("SELECT proposal_id, session_id, account_id, payee_id, "
                                                   "amount_pence, day FROM payments ORDER BY id")]

    def demo_signup_funding(self, owner, balance_pence, daily_limit_pence, known_payees):
        """Demo signup funding. Lives in the ledger so balances are still only ever written here."""
        with self._lock:
            n = len(self._accounts) + 1
            while f"A{n:03d}" in self._accounts:
                n += 1
            account_id = f"A{n:03d}"
            if self._db:
                with self._db:
                    self._db.execute("INSERT INTO accounts VALUES (?,?,?,?)",
                                     (account_id, owner, int(balance_pence), int(daily_limit_pence)))
                    self._db.executemany("INSERT INTO known_payees VALUES (?,?)",
                                         [(account_id, p) for p in known_payees])
            self._accounts[account_id] = {"owner": owner, "balance_pence": int(balance_pence),
                                          "daily_limit_pence": int(daily_limit_pence)}
            self._known[account_id] = set(known_payees)
            return account_id

    # ---------- read-only helpers (used by the policy context) ----------
    def account_exists(self, account_id):
        return account_id in self._accounts

    def accounts_owned_by(self, owner):
        return [a for a, v in self._accounts.items() if v["owner"] == owner]

    def owner_of(self, account_id):
        acct = self._accounts.get(account_id)
        return acct["owner"] if acct else None

    def balance(self, account_id):
        return self._accounts[account_id]["balance_pence"]

    def daily_limit(self, account_id):
        return self._accounts[account_id]["daily_limit_pence"]

    def _today(self):
        return datetime.datetime.fromtimestamp(self._clock(), datetime.timezone.utc).date()

    def daily_total(self, account_id):
        today = self._today()
        with self._lock:
            return sum(h["amount_pence"] for h in self._history
                       if h["account_id"] == account_id and h["day"] == today)

    def payee_exists(self, payee_id):
        return payee_id in self._payees

    def payee_known(self, account_id, payee_id):
        return payee_id in self._known.get(account_id, set())

    def is_mule(self, payee_id):
        return bool(self._payees.get(payee_id, {}).get("mule", False))

    def history(self):
        with self._lock:
            return [dict(h) for h in self._history]

    # ---------- the ONLY payment mutation path ----------
    def execute(self, proposal, token):
        with self._lock:
            if token is None:
                raise LedgerError("P8", "MISSING_TOKEN")
            if not isinstance(proposal, PaymentProposal):
                raise LedgerError("P1", "INVALID_PROPOSAL")
            amount = proposal.amount_pence
            if isinstance(amount, bool) or not isinstance(amount, int) or amount <= 0:
                raise LedgerError("P1", "INVALID_AMOUNT")
            try:
                self._authority.validate(token, proposal)
            except TokenError as exc:
                raise LedgerError("P8", str(exc))

            payer = self._accounts.get(proposal.account_id)
            if payer is None:
                raise LedgerError("P2", "UNKNOWN_ACCOUNT")
            payee = self._payees.get(proposal.payee_id)
            if payee is None:
                raise LedgerError("P1", "UNKNOWN_PAYEE")
            if payee.get("mule"):
                raise LedgerError("P6", "MULE_PAYEE")
            dest = self._accounts.get(payee["account_id"])
            if dest is None:
                raise LedgerError("P1", "UNKNOWN_DESTINATION")
            if payer["balance_pence"] < amount:
                raise LedgerError("P3", "INSUFFICIENT_FUNDS")
            if self.daily_total(proposal.account_id) + amount > payer["daily_limit_pence"]:
                raise LedgerError("P3", "DAILY_LIMIT_EXCEEDED")

            try:
                self._authority.consume(token)   # single-use, atomic
            except TokenError as exc:
                raise LedgerError("P8", str(exc))

            payer["balance_pence"] -= amount
            dest["balance_pence"] += amount
            day = self._today()
            if self._db:
                try:
                    with self._db:   # one SQLite transaction: balances + payment row + known payee
                        self._db.execute("UPDATE accounts SET balance_pence=? WHERE id=?",
                                         (payer["balance_pence"], proposal.account_id))
                        self._db.execute("UPDATE accounts SET balance_pence=? WHERE id=?",
                                         (dest["balance_pence"], payee["account_id"]))
                        self._db.execute("INSERT OR IGNORE INTO known_payees VALUES (?,?)",
                                         (proposal.account_id, proposal.payee_id))
                        self._db.execute("INSERT INTO payments (proposal_id, session_id, account_id, payee_id, "
                                         "amount_pence, day, created_at) VALUES (?,?,?,?,?,?,?)",
                                         (proposal.proposal_id, proposal.session_id, proposal.account_id,
                                          proposal.payee_id, amount, str(day), self._clock()))
                except sqlite3.Error:
                    payer["balance_pence"] += amount      # roll the in-memory copy back: nothing moved
                    dest["balance_pence"] -= amount
                    raise LedgerError("P0", "LEDGER_WRITE_FAILED")
            self._known.setdefault(proposal.account_id, set()).add(proposal.payee_id)
            self._history.append({
                "proposal_id": proposal.proposal_id,
                "session_id": proposal.session_id,
                "account_id": proposal.account_id,
                "payee_id": proposal.payee_id,
                "amount_pence": amount,
                "day": day,
            })
            return {
                "proposal_id": proposal.proposal_id,
                "account_id": proposal.account_id,
                "payee_id": proposal.payee_id,
                "amount_pence": amount,
                "new_balance_pence": payer["balance_pence"],
            }
