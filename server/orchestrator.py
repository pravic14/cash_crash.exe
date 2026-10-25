"""Join a scored payment to the policy kernel.

`server.assess` fills the proposal from the retriever, the parser, and M1–M4.
This module seals that proposal, asks `decide`, and writes the matched rule
onto it. Raw customer text is not a field. This module does not move money.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from rag.retriever import Retrieval
from server.llm import Explanation, explain_hits
from server.policy import Decision, decide, payees_changed
from server.sessions import Session
from shared.schemas import IntentName, PaymentProposal, Verdict


@dataclass
class Orchestrated:
    proposal: PaymentProposal
    decision: Decision
    explanation: Explanation | None


def seal(proposal: PaymentProposal) -> PaymentProposal:
    data = proposal.model_dump()
    data.pop("text", None)
    data.pop("raw_text", None)
    data.pop("message", None)
    return PaymentProposal.model_validate(data)


def orchestrate(
    proposal: PaymentProposal,
    explanation: Explanation | None,
    session: Session,
    accounts: dict,
    payees: dict,
    now: datetime,
    trusted_override: bool = False,
    decision: Decision | None = None,
) -> Orchestrated:
    """Policy reads the sealed proposal. A HOLD with no warning gets the template."""

    proposal = seal(proposal)
    if decision is None:
        changed = payees_changed(session, payees) if proposal.intent == IntentName.PAY else False
        decision = decide(
            proposal,
            session,
            accounts,
            payees,
            now,
            payee_changed=changed,
            trusted_override=trusted_override,
        )
        if proposal.intent == IntentName.PAY:
            session.saw_payment = True
    proposal = proposal.model_copy(update={"matched_policy": decision.matched_policy})
    if decision.verdict == Verdict.HOLD and explanation is None:
        explanation = explain_hits(
            Retrieval(proposal.rag_sim, proposal.cited_card_id, [], "policy"),
            proposal,
        )
    return Orchestrated(proposal, decision, explanation)
