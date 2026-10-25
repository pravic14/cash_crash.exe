"""Capability tokens. HMAC, bound to the payment arguments, 30 seconds, single use."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import uuid
from datetime import datetime, timedelta, timezone

from shared.schemas import PaymentProposal

TOKEN_SECONDS = 30


class TokenBook:
    def __init__(self, secret: str) -> None:
        self._secret = secret.encode("utf-8")
        self.used: set[str] = set()

    def mint(self, proposal: PaymentProposal, now: datetime) -> str:
        payload = _payload(proposal, now + timedelta(seconds=TOKEN_SECONDS), uuid.uuid4().hex)
        return _pack(payload, self._secret)

    def consume(self, token: str, proposal: PaymentProposal, now: datetime) -> bool:
        """True only the first time a current token matches this exact payment."""

        try:
            payload = _unpack(token, self._secret)
        except (ValueError, json.JSONDecodeError, KeyError):
            return False
        if payload["jti"] in self.used:
            return False
        if _epoch(now) > float(payload["exp"]):
            return False
        if payload["args"] != _args(proposal):
            return False
        self.used.add(payload["jti"])
        return True


def _payload(proposal: PaymentProposal, expiry: datetime, jti: str) -> dict:
    return {"jti": jti, "exp": _epoch(expiry), "args": _args(proposal)}


def _args(proposal: PaymentProposal) -> dict:
    amount = None if proposal.amount is None else round(float(proposal.amount), 2)
    return {
        "proposal_id": proposal.proposal_id,
        "session_id": proposal.session_id,
        "payer_account": proposal.payer_account,
        "payee_id": proposal.payee_id,
        "amount": amount,
        "reference": proposal.reference,
    }


def _pack(payload: dict, secret: bytes) -> str:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature = hmac.new(secret, body, hashlib.sha256).hexdigest()
    encoded = base64.urlsafe_b64encode(body).decode("ascii")
    return f"{encoded}.{signature}"


def _unpack(token: str, secret: bytes) -> dict:
    encoded, _, signature = token.partition(".")
    if not encoded or not signature:
        raise ValueError("token shape")
    body = base64.urlsafe_b64decode(encoded.encode("ascii"))
    expected = hmac.new(secret, body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise ValueError("token signature")
    return json.loads(body.decode("utf-8"))


def _epoch(now: datetime) -> float:
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    return now.timestamp()
