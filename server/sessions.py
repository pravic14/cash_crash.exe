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
    def __init__(self) -> None:
        self._sessions: dict[str, Session] = {}

    def open(self, account_id: str) -> Session:
        session = Session(session_id=uuid.uuid4().hex[:12], account_id=account_id)
        self._sessions[session.session_id] = session
        return session

    def get(self, session_id: str) -> Session:
        try:
            return self._sessions[session_id]
        except KeyError as exc:
            raise KeyError(f"Unknown session {session_id}") from exc
