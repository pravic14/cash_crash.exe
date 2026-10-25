"""One chat session owns one account. Policy reads this. It does not move money."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field


@dataclass
class Session:
    session_id: str
    account_id: str
    attempts: list[float] = field(default_factory=list)
    locked_until: float | None = None
    payee_fingerprint: dict[str, str] | None = None
    saw_payment: bool = False


class SessionBook:
    def __init__(self, store=None) -> None:
        self._sessions: dict[str, Session] = {}
        self.store = store

    def open(self, account_id: str, resume: bool = False) -> Session:
        if resume and self.store is not None:
            found = self.store.latest_session(account_id)
            if found is not None:
                self._sessions[found.session_id] = found
                return found
        session = Session(session_id=uuid.uuid4().hex[:12], account_id=account_id)
        self._sessions[session.session_id] = session
        if self.store is not None:
            self.store.insert_session(session)
        return session

    def get(self, session_id: str) -> Session:
        found = self._sessions.get(session_id)
        if found is None and self.store is not None:
            found = self.store.load_session(session_id)
            if found is not None:
                self._sessions[session_id] = found
        if found is None:
            raise KeyError(f"Unknown session {session_id}")
        return found

    def save(self, session: Session) -> None:
        self._sessions[session.session_id] = session
        if self.store is not None:
            self.store.save_session(session)
