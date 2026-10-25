"""Create the SQLite databases in ./data (or $DATA_DIR):   python init_db.py [--reset] [--demo-user]

  --reset      delete users.db, ledger.db and audit.db first (a clean slate; the audit chain restarts)
  --demo-user  also create demo@example.com / demo-password-123 with a funded demo account (DEMO ONLY)
"""
import os
import sqlite3
import sys

from server.audit import AuditLog
from server.auth import UserStore
from server.capabilities import TokenAuthority
from server.seed import make_demo_ledger

DATA_DIR = os.environ.get("DATA_DIR", "data")
FILES = ("users.db", "ledger.db", "audit.db")


def paths(data_dir=DATA_DIR):
    return {name: os.path.join(data_dir, name) for name in FILES}


def init(data_dir=DATA_DIR, reset=False, demo_user=False):
    os.makedirs(data_dir, exist_ok=True)
    p = paths(data_dir)
    if reset:
        for f in p.values():
            if os.path.exists(f):
                os.remove(f)
    users = UserStore(p["users.db"])
    ledger = make_demo_ledger(TokenAuthority(), db_path=p["ledger.db"])
    audit = AuditLog(p["audit.db"])
    if demo_user:
        try:
            user = users.create_user("Demo User", "demo@example.com", "demo-password-123")
            ledger.open_account(user["id"], 500_000, 400_000, ("RENT001",))
        except Exception:
            print("demo user already exists, skipped")
    return p


if __name__ == "__main__":
    made = init(reset="--reset" in sys.argv, demo_user="--demo-user" in sys.argv)
    for name, path in made.items():
        con = sqlite3.connect(path)
        tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
        print(f"{path}: tables = {', '.join(tables)}")
