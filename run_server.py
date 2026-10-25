"""Start the API:  uvicorn run_server:app --reload      (interactive docs: http://127.0.0.1:8000/docs)

Env vars: TRUSTED_CONTACT_KEY (shared with the Pi/ops UI), COOKIE_SECURE=1 (when served over HTTPS),
ALLOWED_ORIGINS=http://localhost:5173,... (extra browser origins, e.g. a dev server), COOLOFF_SECONDS,
DATA_DIR (where the SQLite files live, default ./data; create them first with: python init_db.py).
"""
import os

from init_db import DATA_DIR, paths
from server.api import create_app
from server.audit import AuditLog
from server.auth import UserStore
from server.capabilities import TokenAuthority
from server.orchestrator import Orchestrator
from server.seed import make_demo_ledger

os.makedirs(DATA_DIR, exist_ok=True)
DB = paths()
authority = TokenAuthority()
audit = AuditLog(DB["audit.db"])
ledger = make_demo_ledger(authority, db_path=DB["ledger.db"])
users = UserStore(DB["users.db"])
orch = Orchestrator(ledger, authority, audit, cooloff_seconds=int(os.environ.get("COOLOFF_SECONDS", "60")))
app = create_app(orch, audit, ledger, users,
                 allowed_origins=[o for o in os.environ.get("ALLOWED_ORIGINS", "").split(",") if o])
print("Trusted-contact key:", app.state.trusted_key)
