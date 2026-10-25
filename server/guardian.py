"""One pasted message: sanitiser, assessor, policy, then the ledger.

ALLOW mints a token and debits. HOLD waits for approve or decline.
DENY changes nothing. The HTTP routes and the Pi both call this.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

from rag.retriever import cite_policy
from server.assess import assess_message
from server.audit import AuditLog
from server.ledger import Ledger, LedgerDenied, load_accounts, load_payees
from server.llm import Explanation
from server.orchestrator import Orchestrated, orchestrate
from server.policy import Decision
from server.scoring import RedTeam
from server.sessions import Session, SessionBook
from server.sanitiser import sanitise
from server.tokens import TokenBook
from shared.schemas import IntentName, PaymentProposal, PolicyId, Verdict

ROOT = Path(__file__).resolve().parents[1]


class Guardian:
    def __init__(self, audit_path: Path | None = None, secret: str | None = None) -> None:
        self.accounts = load_accounts()
        self.payees = load_payees()
        self.tokens = TokenBook(secret or os.environ.get("POLICY_SECRET") or "hacknotts-demo-policy")
        self.ledger = Ledger(self.accounts, self.tokens)
        path = audit_path or (ROOT / "server" / "data" / "audit.sqlite")
        self.audit = AuditLog(path)
        self.sessions = SessionBook()
        self.scoring = RedTeam()
        self.holds: dict[str, PaymentProposal] = {}

    def open_session(self, account_id: str = "acc-margaret") -> str:
        if account_id not in self.accounts:
            raise KeyError(account_id)
        return self.sessions.open(account_id).session_id

    def apply(self, session_id: str, proposal: PaymentProposal, now: datetime | None = None) -> dict:
        """Policy and ledger only. Tests use this so a crafted proposal cannot skip the kernel."""

        session = self.sessions.get(session_id)
        now = _clock(now)
        outcome = orchestrate(proposal, None, session, self.accounts, self.payees, now)
        return self._execute(session, outcome, now, trusted_override=False)

    def submit(self, session_id: str, text: str, now: datetime | None = None) -> dict:
        now = _clock(now)
        session = self.sessions.get(session_id)
        clean = sanitise(text)
        self.audit.append(session.session_id, "sanitise", None, {"rejected": clean.rejected, "stripped_encoded": clean.stripped_encoded})
        if clean.rejected:
            outcome = orchestrate(
                _blank(session),
                None,
                session,
                self.accounts,
                self.payees,
                now,
                decision=Decision(Verdict.DENY, PolicyId.P1_SCHEMA, clean.rejected),
            )
            return self._execute(session, outcome, now, trusted_override=False)
        assessment = assess_message(
            clean.text,
            customer_id=session.account_id,
            session_id=session.session_id,
        )
        outcome = orchestrate(
            assessment.proposal,
            assessment.explanation,
            session,
            self.accounts,
            self.payees,
            now,
        )
        return self._execute(session, outcome, now, trusted_override=False)

    def resolve(self, proposal_id: str, approve: bool, now: datetime | None = None) -> dict:
        """Trusted-contact decision for a payment already on HOLD."""

        now = _clock(now)
        proposal = self.holds.get(proposal_id)
        if proposal is None:
            raise KeyError(proposal_id)
        session = self.sessions.get(proposal.session_id)
        self.holds.pop(proposal_id, None)
        if not approve:
            outcome = orchestrate(
                proposal,
                None,
                session,
                self.accounts,
                self.payees,
                now,
                decision=Decision(Verdict.DENY, proposal.matched_policy, "The trusted contact declined."),
            )
            return self._execute(session, outcome, now, trusted_override=False)
        outcome = orchestrate(
            proposal,
            None,
            session,
            self.accounts,
            self.payees,
            now,
            trusted_override=True,
        )
        return self._execute(session, outcome, now, trusted_override=True)

    def _execute(self, session, outcome: Orchestrated, now: datetime, trusted_override: bool) -> dict:
        proposal = outcome.proposal
        decision = outcome.decision
        explanation = outcome.explanation
        executed = False
        if decision.verdict == Verdict.ALLOW and proposal.intent == IntentName.PAY:
            token = self.tokens.mint(proposal, now)
            try:
                self.ledger.execute(proposal, token, now)
                executed = True
            except LedgerDenied as exc:
                decision = Decision(Verdict.DENY, exc.policy, exc.reason)
                proposal = proposal.model_copy(update={"matched_policy": exc.policy})
        elif decision.verdict == Verdict.HOLD:
            self.holds[proposal.proposal_id] = proposal
        self.scoring.note(decision.verdict, proposal.band, trusted_override, executed, executed)
        self.audit.append(
            session.session_id,
            "ledger" if executed else "policy",
            decision.verdict,
            {
                "proposal_id": proposal.proposal_id,
                "matched_policy": decision.matched_policy.value if decision.matched_policy else None,
                "amount": proposal.amount,
                "payee_id": proposal.payee_id,
                "executed": executed,
            },
        )
        return _body(session, proposal, decision, explanation, self.ledger, executed, self.scoring)


def _blank(session: Session) -> PaymentProposal:
    return PaymentProposal(
        proposal_id=f"rejected-{session.session_id}",
        session_id=session.session_id,
        payer_account=session.account_id,
        intent=IntentName.UNKNOWN,
    )


def _body(
    session: Session,
    proposal: PaymentProposal,
    decision: Decision,
    explanation: Explanation | None,
    ledger: Ledger,
    executed: bool,
    scoring: RedTeam,
) -> dict:
    warning = None
    if explanation is not None and (decision.verdict == Verdict.HOLD or explanation.card_ids):
        warning = {
            "text": explanation.text,
            "card_ids": list(explanation.card_ids),
            "source": explanation.source,
        }
    clause = None
    if decision.matched_policy is not None:
        clause = cite_policy(decision.matched_policy)
    return {
        "proposal_id": proposal.proposal_id,
        "session_id": session.session_id,
        "verdict": decision.verdict.value if decision.verdict else None,
        "matched_policy": decision.matched_policy.value if decision.matched_policy else None,
        "reason": decision.reason,
        "executed": executed,
        "balance": ledger.balance(session.account_id),
        "proposal": proposal.model_dump(mode="json"),
        "explanation": warning,
        "policy": clause,
        "scoring": scoring.snapshot(),
    }


def _clock(now: datetime | None) -> datetime:
    if now is None:
        return datetime.now(timezone.utc)
    if now.tzinfo is None:
        return now.replace(tzinfo=timezone.utc)
    return now
