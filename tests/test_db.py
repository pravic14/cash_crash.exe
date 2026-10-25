import os
import sqlite3

import init_db
from server.audit import AuditLog
from server.auth import UserStore
from server.capabilities import TokenAuthority
from server.seed import make_demo_ledger


def columns(path):
    con = sqlite3.connect(path)
    out = {}
    for (name,) in con.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"):
        out[name] = [r[1] for r in con.execute(f"PRAGMA table_info({name})")]
    return out


def test_init_creates_all_three_databases(tmp_path):
    p = init_db.init(str(tmp_path), demo_user=True)
    assert all(os.path.exists(f) for f in p.values())
    assert {"users", "sessions"} <= set(columns(p["users.db"]))
    assert {"accounts", "payees", "known_payees", "payments"} <= set(columns(p["ledger.db"]))
    assert set(columns(p["audit.db"])) == {"events"}
    u = UserStore(p["users.db"])
    assert u.authenticate("demo@example.com", "demo-password-123")["display_name"] == "Demo User"


def test_init_is_idempotent_and_reset_wipes(tmp_path):
    init_db.init(str(tmp_path), demo_user=True)
    p = init_db.init(str(tmp_path), demo_user=True)                      # second run: no crash, no duplicates
    assert sqlite3.connect(p["users.db"]).execute("SELECT COUNT(*) FROM users").fetchone()[0] == 1
    p = init_db.init(str(tmp_path), reset=True)
    assert sqlite3.connect(p["users.db"]).execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0


def test_schema_sql_matches_the_code(tmp_path):
    ref = str(tmp_path / "ref.db")
    sqlite3.connect(ref).executescript(open("db/schema.sql").read())
    expected = columns(ref)
    p = init_db.init(str(tmp_path / "real"))
    actual = {}
    for f in p.values():
        actual.update(columns(f))
    assert actual == expected


def test_audit_chain_persists(tmp_path):
    path = str(tmp_path / "a.db")
    a = AuditLog(path)
    a.log_event("S", "ONE")
    a.log_event("S", "TWO")
    b = AuditLog(path)                                                   # reopened
    b.log_event("S", "THREE")
    assert b.verify_chain() == (True, None) and len(b.get_session_events("S")) == 3
