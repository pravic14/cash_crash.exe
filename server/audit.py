"""Tamper-evident audit log: SQLite + SHA-256 hash chain.
Detects edits to old rows. It cannot stop someone with DB access rewriting the WHOLE chain."""
import datetime
import hashlib
import json
import sqlite3
import threading
import time

GENESIS_HASH = "0" * 64
_SENSITIVE_KEYS = {"secret", "sig", "signature", "password", "hmac", "key", "authorization", "token", "claims"}


def _redact(value):
    if isinstance(value, dict):
        return {k: ("[REDACTED]" if str(k).lower() in _SENSITIVE_KEYS else _redact(v)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact(v) for v in value]
    return value


def _hash(event_id, timestamp, session_id, event_type, details_json, previous_hash):
    raw = "|".join([event_id, timestamp, session_id, event_type, details_json, previous_hash])
    return hashlib.sha256(raw.encode()).hexdigest()


class AuditLog:
    def __init__(self, path=":memory:", clock=time.time):
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._lock = threading.Lock()
        self._clock = clock
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS events ("
            "seq INTEGER PRIMARY KEY, event_id TEXT, timestamp TEXT, session_id TEXT, "
            "event_type TEXT, details TEXT, previous_hash TEXT, event_hash TEXT)")
        self._conn.commit()

    def log_event(self, session_id, event_type, details=None):
        details_json = json.dumps(_redact(details or {}), sort_keys=True, separators=(",", ":"), default=str)
        with self._lock:
            row = self._conn.execute("SELECT seq, event_hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()
            seq, prev = (row[0] + 1, row[1]) if row else (1, GENESIS_HASH)
            event_id = f"EVT{seq:06d}"
            ts = datetime.datetime.fromtimestamp(self._clock(), datetime.timezone.utc).isoformat()
            h = _hash(event_id, ts, session_id, event_type, details_json, prev)
            self._conn.execute("INSERT INTO events VALUES (?,?,?,?,?,?,?,?)",
                               (seq, event_id, ts, session_id, event_type, details_json, prev, h))
            self._conn.commit()
        return {"event_id": event_id, "timestamp": ts, "session_id": session_id,
                "event_type": event_type, "details": json.loads(details_json),
                "previous_hash": prev, "event_hash": h}

    def verify_chain(self):
        """Returns (True, None) if intact, else (False, seq_of_first_bad_row)."""
        with self._lock:
            rows = self._conn.execute("SELECT * FROM events ORDER BY seq").fetchall()
        prev = GENESIS_HASH
        for i, (seq, eid, ts, sid, etype, details, prev_hash, ehash) in enumerate(rows, start=1):
            if seq != i or prev_hash != prev or _hash(eid, ts, sid, etype, details, prev_hash) != ehash:
                return False, seq
            prev = ehash
        return True, None

    def get_session_events(self, session_id):
        with self._lock:
            rows = self._conn.execute("SELECT * FROM events WHERE session_id=? ORDER BY seq", (session_id,)).fetchall()
        return [{"event_id": r[1], "timestamp": r[2], "session_id": r[3], "event_type": r[4],
                 "details": json.loads(r[5]), "previous_hash": r[6], "event_hash": r[7]} for r in rows]

    def all_events(self):
        with self._lock:
            rows = self._conn.execute("SELECT event_type FROM events ORDER BY seq").fetchall()
        return [r[0] for r in rows]
