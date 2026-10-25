"""Live SQLite store. JSON is only the seed.

`accounts.json` is copied in once. After that, balances, users, sessions,
holds, and the chat transcript live in `guardian.sqlite`.

The transcript is for the screen. The parser is never handed those rows.
What a resumed session gives the policy kernel is the columns on `sessions`:
attempts, lock, payee fingerprint, and the last intent, amount, payee, and card.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

from server.ledger import ACCOUNTS_PATH, load_accounts
from server.sessions import Session
from shared.schemas import PaymentProposal

DEMO_EMAIL = "margaret@cashcrash.test"
DEMO_PASSWORD = "margaret-demo"
_HASH_ROUNDS = 200_000


class Store:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path
        self._lock = threading.Lock()
        if path is None:
            self._db = sqlite3.connect(":memory:", check_same_thread=False)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._accounts: dict = {}
        with self._lock:
            self._migrate()
            self._seed_accounts()
            self._seed_demo_user()
            self._load_accounts()

    @property
    def accounts(self) -> dict:
        return self._accounts

    def signup(self, display_name: str, email: str, password: str) -> dict:
        name = display_name.strip()
        if not name:
            raise ValueError("A display name is required.")
        if len(password) < 8:
            raise ValueError("Use at least 8 characters.")
        cleaned = _email(email)
        with self._lock:
            taken = self._db.execute("SELECT 1 FROM users WHERE email = ?", (cleaned,)).fetchone()
            if taken is not None:
                raise ValueError("That email is already registered.")
            account_id = self._new_account_id()
            self._insert_account(account_id, name[:40], 4200.0, 3000.0, 0.0)
            self._insert_user(cleaned, name[:40], password, account_id)
            self._remember_account(account_id, name[:40], 4200.0, 3000.0, 0.0)
        return {"email": cleaned, "display_name": name[:40], "account_id": account_id}

    def login(self, email: str, password: str) -> dict | None:
        try:
            cleaned = _email(email)
        except ValueError:
            return None
        with self._lock:
            row = self._db.execute("SELECT * FROM users WHERE email = ?", (cleaned,)).fetchone()
            if row is None or not _password_ok(password, row["salt"], row["password_hash"]):
                return None
            return {
                "email": row["email"],
                "display_name": row["display_name"],
                "account_id": row["account_id"],
            }

    def insert_session(self, session: Session) -> None:
        with self._lock:
            self._write_session(session, inserting=True)

    def save_session(self, session: Session) -> None:
        with self._lock:
            self._write_session(session, inserting=False)

    def load_session(self, session_id: str) -> Session | None:
        with self._lock:
            row = self._db.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,)).fetchone()
        return None if row is None else _session_from(row)

    def latest_session(self, account_id: str) -> Session | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM sessions WHERE account_id = ? ORDER BY created_at DESC LIMIT 1",
                (account_id,),
            ).fetchone()
        return None if row is None else _session_from(row)

    def save_context(self, session_id: str, proposal: PaymentProposal, verdict: str | None, policy: str | None) -> None:
        with self._lock:
            self._db.execute(
                """
                UPDATE sessions
                SET last_intent = ?, last_amount = ?, last_payee_id = ?, last_reference = ?,
                    cited_card_id = ?, last_verdict = ?, last_policy = ?
                WHERE session_id = ?
                """,
                (
                    proposal.intent.value,
                    proposal.amount,
                    proposal.payee_id,
                    proposal.reference,
                    proposal.cited_card_id,
                    verdict,
                    policy,
                    session_id,
                ),
            )
            self._db.commit()

    def context(self, session_id: str) -> dict:
        with self._lock:
            row = self._db.execute(
                """
                SELECT last_intent, last_amount, last_payee_id, last_reference,
                       cited_card_id, last_verdict, last_policy
                FROM sessions WHERE session_id = ?
                """,
                (session_id,),
            ).fetchone()
        if row is None:
            return {}
        return {key: row[key] for key in row.keys()}

    def add_message(self, session_id: str, role: str, body: str, verdict: str | None) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO messages (session_id, role, body, verdict, created_at) VALUES (?, ?, ?, ?, ?)",
                (session_id, role, body, verdict, _now()),
            )
            self._db.commit()

    def messages(self, session_id: str) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT role, body, verdict FROM messages WHERE session_id = ? ORDER BY id",
                (session_id,),
            ).fetchall()
        return [{"role": row["role"], "body": row["body"], "verdict": row["verdict"]} for row in rows]

    def save_accounts(self) -> None:
        with self._lock:
            for account_id, record in self._accounts.items():
                self._db.execute(
                    """
                    UPDATE accounts
                    SET customer_name = ?, balance = ?, daily_limit = ?, daily_spent = ?
                    WHERE account_id = ?
                    """,
                    (
                        record["customer_name"],
                        round(float(record["balance"]), 2),
                        round(float(record["daily_limit"]), 2),
                        round(float(record.get("daily_spent") or 0), 2),
                        account_id,
                    ),
                )
            self._db.commit()

    def save_hold(self, proposal: PaymentProposal, created: datetime, approvals: set[str], requires_trusted_contact: bool) -> None:
        with self._lock:
            self._db.execute(
                """
                INSERT INTO holds (proposal_id, session_id, proposal_json, created, approvals, requires_trusted_contact)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(proposal_id) DO UPDATE SET
                    proposal_json = excluded.proposal_json,
                    approvals = excluded.approvals,
                    requires_trusted_contact = excluded.requires_trusted_contact
                """,
                (
                    proposal.proposal_id,
                    proposal.session_id,
                    json.dumps(proposal.model_dump(mode="json")),
                    created.isoformat(),
                    json.dumps(sorted(approvals)),
                    int(requires_trusted_contact),
                ),
            )
            self._db.commit()

    def delete_hold(self, proposal_id: str) -> None:
        with self._lock:
            self._db.execute("DELETE FROM holds WHERE proposal_id = ?", (proposal_id,))
            self._db.commit()

    def load_holds(self) -> list[dict]:
        with self._lock:
            rows = self._db.execute("SELECT * FROM holds").fetchall()
        loaded = []
        for row in rows:
            try:
                proposal = PaymentProposal.model_validate(json.loads(row["proposal_json"]))
            except (ValueError, json.JSONDecodeError):
                continue
            loaded.append(
                {
                    "proposal": proposal,
                    "created": datetime.fromisoformat(row["created"]),
                    "approvals": set(json.loads(row["approvals"])),
                    "requires_trusted_contact": bool(row["requires_trusted_contact"]),
                }
            )
        return loaded

    def scores(self) -> dict:
        with self._lock:
            row = self._db.execute("SELECT hold_points, evasion_points, bounties FROM scoreboard WHERE id = 1").fetchone()
        if row is None:
            return {"hold_points": 0, "evasion_points": 0, "bounties": 0}
        return {"hold_points": row["hold_points"], "evasion_points": row["evasion_points"], "bounties": row["bounties"]}

    def save_scores(self, board: dict) -> None:
        with self._lock:
            self._db.execute(
                """
                UPDATE scoreboard
                SET hold_points = ?, evasion_points = ?, bounties = ?
                WHERE id = 1
                """,
                (int(board["hold_points"]), int(board["evasion_points"]), int(board["bounties"])),
            )
            self._db.commit()

    def _migrate(self) -> None:
        self._db.executescript(
            """
            CREATE TABLE IF NOT EXISTS accounts (
                account_id TEXT PRIMARY KEY,
                customer_name TEXT NOT NULL,
                balance REAL NOT NULL,
                daily_limit REAL NOT NULL,
                daily_spent REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS users (
                email TEXT PRIMARY KEY,
                display_name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                account_id TEXT NOT NULL UNIQUE
            );
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                account_id TEXT NOT NULL,
                attempts TEXT NOT NULL,
                locked_until REAL,
                payee_fingerprint TEXT,
                saw_payment INTEGER NOT NULL,
                last_intent TEXT,
                last_amount REAL,
                last_payee_id TEXT,
                last_reference TEXT,
                cited_card_id TEXT,
                last_verdict TEXT,
                last_policy TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                role TEXT NOT NULL,
                body TEXT NOT NULL,
                verdict TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS holds (
                proposal_id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                proposal_json TEXT NOT NULL,
                created TEXT NOT NULL,
                approvals TEXT NOT NULL,
                requires_trusted_contact INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS scoreboard (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                hold_points INTEGER NOT NULL,
                evasion_points INTEGER NOT NULL,
                bounties INTEGER NOT NULL
            );
            """
        )
        existing = self._db.execute("SELECT 1 FROM scoreboard WHERE id = 1").fetchone()
        if existing is None:
            self._db.execute("INSERT INTO scoreboard (id, hold_points, evasion_points, bounties) VALUES (1, 0, 0, 0)")
        self._db.commit()

    def _seed_accounts(self) -> None:
        count = self._db.execute("SELECT COUNT(*) AS n FROM accounts").fetchone()["n"]
        if count:
            return
        for account_id, record in load_accounts(ACCOUNTS_PATH).items():
            self._insert_account(
                account_id,
                record["customer_name"],
                float(record["balance"]),
                float(record["daily_limit"]),
                float(record.get("daily_spent") or 0),
            )

    def _seed_demo_user(self) -> None:
        row = self._db.execute("SELECT 1 FROM users WHERE email = ?", (DEMO_EMAIL,)).fetchone()
        if row is None:
            self._insert_user(DEMO_EMAIL, "Margaret", DEMO_PASSWORD, "acc-margaret")

    def _load_accounts(self) -> None:
        self._accounts.clear()
        for row in self._db.execute("SELECT * FROM accounts"):
            self._remember_account(
                row["account_id"],
                row["customer_name"],
                row["balance"],
                row["daily_limit"],
                row["daily_spent"],
            )

    def _remember_account(self, account_id: str, name: str, balance: float, limit: float, spent: float) -> None:
        self._accounts[account_id] = {
            "customer_name": name,
            "balance": round(float(balance), 2),
            "daily_limit": round(float(limit), 2),
            "daily_spent": round(float(spent), 2),
        }

    def _insert_account(self, account_id: str, name: str, balance: float, limit: float, spent: float) -> None:
        self._db.execute(
            "INSERT INTO accounts (account_id, customer_name, balance, daily_limit, daily_spent) VALUES (?, ?, ?, ?, ?)",
            (account_id, name, balance, limit, spent),
        )
        self._db.commit()

    def _insert_user(self, email: str, name: str, password: str, account_id: str) -> None:
        salt = secrets.token_bytes(16)
        self._db.execute(
            "INSERT INTO users (email, display_name, password_hash, salt, account_id) VALUES (?, ?, ?, ?, ?)",
            (email, name, _hash(password, salt), salt.hex(), account_id),
        )
        self._db.commit()

    def _new_account_id(self) -> str:
        while True:
            account_id = "acc-" + uuid.uuid4().hex[:8]
            taken = self._db.execute("SELECT 1 FROM accounts WHERE account_id = ?", (account_id,)).fetchone()
            if taken is None:
                return account_id

    def _write_session(self, session: Session, inserting: bool) -> None:
        fingerprint = None if session.payee_fingerprint is None else json.dumps(session.payee_fingerprint)
        attempts = json.dumps(session.attempts)
        if inserting:
            self._db.execute(
                """
                INSERT INTO sessions (
                    session_id, account_id, attempts, locked_until, payee_fingerprint, saw_payment, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session.session_id,
                    session.account_id,
                    attempts,
                    session.locked_until,
                    fingerprint,
                    int(session.saw_payment),
                    _now(),
                ),
            )
        else:
            self._db.execute(
                """
                UPDATE sessions
                SET attempts = ?, locked_until = ?, payee_fingerprint = ?, saw_payment = ?
                WHERE session_id = ?
                """,
                (attempts, session.locked_until, fingerprint, int(session.saw_payment), session.session_id),
            )
        self._db.commit()


def _session_from(row: sqlite3.Row) -> Session:
    fingerprint = None if row["payee_fingerprint"] is None else json.loads(row["payee_fingerprint"])
    return Session(
        session_id=row["session_id"],
        account_id=row["account_id"],
        attempts=json.loads(row["attempts"]),
        locked_until=row["locked_until"],
        payee_fingerprint=fingerprint,
        saw_payment=bool(row["saw_payment"]),
    )


def _email(value: str) -> str:
    cleaned = value.strip().lower()
    domain = cleaned.split("@")[-1] if "@" in cleaned else ""
    if not cleaned or "@" not in cleaned or "." not in domain:
        raise ValueError("Enter a real email address.")
    return cleaned


def _hash(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _HASH_ROUNDS).hex()


def _password_ok(password: str, salt_hex: str, expected: str) -> bool:
    try:
        actual = _hash(password, bytes.fromhex(salt_hex))
    except ValueError:
        return False
    return hmac.compare_digest(actual, expected)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
