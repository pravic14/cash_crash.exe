from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, ConfigDict


class Intent(str, Enum):
    PAY = "PAY"
    BALANCE = "BALANCE"
    CHANGE_PAYEE = "CHANGE_PAYEE"
    UNKNOWN = "UNKNOWN"


class DecisionType(str, Enum):
    ALLOW = "ALLOW"
    HOLD = "HOLD"
    DENY = "DENY"


class RiskBand(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class ParsedIntent(BaseModel):
    """What the quarantined LLM (or the rule parser) is allowed to output. Nothing else."""
    model_config = ConfigDict(extra="forbid")

    intent: Intent
    payee_id: Optional[str] = None
    amount: Optional[float] = None  # pounds, converted to pence ONCE in the orchestrator
    reference: str = ""
    urgency_claimed: bool = False
    claims_authority: bool = False


class PaymentProposal(BaseModel):
    """Built by CODE from validated fields + server-side session data. Never from raw text."""
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    proposal_id: str
    session_id: str
    account_id: str
    payee_id: str
    amount_pence: int
    reference: str = ""


class RiskResult(BaseModel):
    """What the ML/RAG teammates return to the orchestrator."""
    model_config = ConfigDict(extra="ignore")

    injection_risk: float = 0.0
    scam_risk: float = 0.0
    transaction_risk: float = 0.0
    rag_similarity: float = 0.0
    final_risk: float = 0.0
    risk_band: RiskBand = RiskBand.LOW
    reasons: List[str] = []


class PolicyDecision(BaseModel):
    decision: DecisionType
    rule_id: str
    reason: str
    requires_trusted_contact: bool = False
    lock_session: bool = False
    triggered: List[str] = []
