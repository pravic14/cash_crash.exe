
import hashlib
import hmac
import json
import secrets
import threading
import time

from .schemas import PaymentProposal

CLAIM_KEYS = {
    "token_id", "session_id", "account_id", "payee_id", "amount",
    "proposal_id", "issued_at", "expires_at", "nonce",
}


class TokenError(Exception):
    """Raised for any token problem. The message is a short reason code."""


class TokenAuthority:
    def __init__(self, secret=None, ttl_seconds=30, clock=time.time):
        # Secret lives in memory only. Never log it, never put it in the repo.
        self._secret = secret or secrets.token_bytes(32)
        self._ttl = ttl_seconds
        self._clock = clock
        self._used = set()
        self._lock = threading.Lock()

    def _sign(self, claims):
        body = json.dumps(claims, sort_keys=True, separators=(",", ":")).encode()
        return hmac.new(self._secret, body, hashlib.sha256).hexdigest()

    def mint(self, proposal):
        """Only the orchestrator calls this, and ONLY after the policy kernel said ALLOW."""
        if not isinstance(proposal, PaymentProposal):
            raise TokenError("INVALID_PROPOSAL")
        now = self._clock()
        claims = {
            "token_id": secrets.token_hex(8),
            "session_id": proposal.session_id,
            "account_id": proposal.account_id,
            "payee_id": proposal.payee_id,
            "amount": proposal.amount_pence,
            "proposal_id": proposal.proposal_id,
            "issued_at": now,
            "expires_at": now + self._ttl,
            "nonce": secrets.token_hex(16),
        }
        return {"claims": claims, "sig": self._sign(claims)}

    def validate(self, token, proposal):
        """Checks signature, expiry, exact-argument match and not-yet-used. Does NOT consume."""
        if not isinstance(token, dict) or set(token) != {"claims", "sig"}:
            raise TokenError("MALFORMED")
        claims, sig = token["claims"], token["sig"]
        if not isinstance(claims, dict) or set(claims) != CLAIM_KEYS or not isinstance(sig, str):
            raise TokenError("MALFORMED")
        try:
            expected = self._sign(claims)
        except (TypeError, ValueError):
            raise TokenError("MALFORMED")
        if not hmac.compare_digest(expected.encode(), sig.encode()):
            raise TokenError("BAD_SIGNATURE")
        if self._clock() >= claims["expires_at"]:
            raise TokenError("EXPIRED")
        if not isinstance(proposal, PaymentProposal):
            raise TokenError("INVALID_PROPOSAL")
        if (claims["session_id"] != proposal.session_id
                or claims["account_id"] != proposal.account_id
                or claims["payee_id"] != proposal.payee_id
                or claims["amount"] != proposal.amount_pence
                or claims["proposal_id"] != proposal.proposal_id):
            raise TokenError("ARGUMENT_MISMATCH")
        with self._lock:
            if claims["token_id"] in self._used:
                raise TokenError("ALREADY_USED")

    def consume(self, token):
        """Atomic single-use: exactly one caller can ever succeed for a given token."""
        token_id = token["claims"]["token_id"]
        with self._lock:
            if token_id in self._used:
                raise TokenError("ALREADY_USED")
            self._used.add(token_id)
