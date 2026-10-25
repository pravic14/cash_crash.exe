"""Hash-chained audit log. Detail never stores the customer message."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from shared.schemas import Verdict


class AuditLog:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(self.path, check_same_thread=False)
        self._db.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                session_id TEXT NOT NULL,
                step TEXT NOT NULL,
                verdict TEXT NOT NULL,
                detail TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                event_hash TEXT NOT NULL
            )
            """
        )
        self._db.commit()

    def append(self, session_id: str, step: str, verdict: Verdict | None, detail: dict) -> str:
        clean = {key: value for key, value in detail.items() if key != "text"}
        previous = self._latest_hash()
        ts = datetime.now(timezone.utc).isoformat()
        verdict_name = verdict.value if verdict is not None else ""
        payload = {
            "ts": ts,
            "session_id": session_id,
            "step": step,
            "verdict": verdict_name,
            "detail": clean,
            "prev_hash": previous,
        }
        event_hash = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        self._db.execute(
            """
            INSERT INTO events (ts, session_id, step, verdict, detail, prev_hash, event_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (ts, session_id, step, verdict_name, json.dumps(clean, sort_keys=True), previous, event_hash),
        )
        self._db.commit()
        return event_hash

    def verify_chain(self) -> bool:
        previous = ""
        for ts, session_id, step, verdict, detail, prev_hash, event_hash in self._rows():
            if prev_hash != previous:
                return False
            payload = {
                "ts": ts,
                "session_id": session_id,
                "step": step,
                "verdict": verdict,
                "detail": json.loads(detail),
                "prev_hash": prev_hash,
            }
            expected = hashlib.sha256(
                json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            if expected != event_hash:
                return False
            previous = event_hash
        return True

    def replay(self, session_id: str) -> list[dict]:
        rows = []
        for ts, row_session, step, verdict, detail, prev_hash, event_hash in self._rows():
            if row_session != session_id:
                continue
            rows.append(
                {
                    "ts": ts,
                    "session_id": row_session,
                    "step": step,
                    "verdict": verdict,
                    "detail": json.loads(detail),
                    "prev_hash": prev_hash,
                    "event_hash": event_hash,
                }
            )
        return rows

    def close(self) -> None:
        self._db.close()

    def _latest_hash(self) -> str:
        row = self._db.execute("SELECT event_hash FROM events ORDER BY id DESC LIMIT 1").fetchone()
        return "" if row is None else str(row[0])

    def _rows(self) -> list[tuple]:
        return list(
            self._db.execute(
                "SELECT ts, session_id, step, verdict, detail, prev_hash, event_hash FROM events ORDER BY id"
            )
        )
