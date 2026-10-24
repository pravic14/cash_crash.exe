"""Kickoff schemas: intent, proposal, event.

The quarantined LLM may only produce ParsedIntent. The orchestrator builds a
PaymentProposal. The ledger moves money only after the policy kernel returns
Verdict.ALLOW and a capability token. AuditEvent is one row of the hash chain.
"""

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class IntentName(str, Enum):
    PAY = "pay"
    BALANCE = "balance"
    CHAT = "chat"
    UNKNOWN = "unknown"


class RiskBand(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class Verdict(str, Enum):
    ALLOW = "ALLOW"
    HOLD = "HOLD"
    DENY = "DENY"


class PolicyId(str, Enum):
    """Hard rules. Any match can block. None of these can be overridden by a model."""

    P1_SCHEMA = "P1"  # schema invalid / unknown intent -> DENY
    P2_OWNER = "P2"  # payer account not owned by session -> DENY
    P3_LIMIT = "P3"  # amount > balance or > daily limit -> DENY
    P4_NEW_PAYEE = "P4"  # new payee and amount > £250 -> HOLD
    P5_HIGH_RISK = "P5"  # final_risk HIGH -> HOLD + trusted contact
    P6_MULE = "P6"  # payee on the mule list -> DENY
    P7_VELOCITY = "P7"  # > 3 payment attempts in 5 min -> DENY + lock 10 min
    P8_TOKEN = "P8"  # no valid capability token -> DENY
    P9_PAYEE_CHANGE = "P9"  # payee details changed and a payment in the same session -> HOLD


class ParsedIntent(BaseModel):
    """Typed output of the quarantined parser. Free text never crosses this boundary."""

    intent: IntentName
    payee_id: str | None = None
    amount: float | None = None
    reference: str = Field(default="", max_length=18)
    urgency_claimed: bool = False
    claims_authority: bool = False


class PaymentProposal(BaseModel):
    """The only object the policy kernel reads. Scores are filled in as guards run."""

    proposal_id: str
    session_id: str
    payer_account: str
    payee_id: str | None = None
    amount: float | None = None
    reference: str = Field(default="", max_length=18)
    intent: IntentName
    urgency_claimed: bool = False
    claims_authority: bool = False
    text_risk: float = Field(default=0.0, ge=0.0, le=1.0)
    txn_risk: float = Field(default=0.0, ge=0.0, le=1.0)
    rag_sim: float = Field(default=0.0, ge=0.0, le=1.0)
    final_risk: float | None = Field(default=None, ge=0.0, le=1.0)
    band: RiskBand | None = None
    cited_card_id: str | None = None
    matched_policy: PolicyId | None = None


class AuditEvent(BaseModel):
    """One step in the hash chain. audit.py fills prev_hash and event_hash."""

    ts: str
    session_id: str
    step: str
    verdict: Verdict | None = None
    detail: dict[str, Any] = Field(default_factory=dict)
    prev_hash: str = ""
    event_hash: str = ""
