"""One pasted message: sanitiser, assessor, policy, then the ledger.

ALLOW mints a token and debits. HOLD waits for approve or decline.
DENY changes nothing. The HTTP routes and the Pi both call this.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from rag.retriever import cite_policy
from server.assess import assess_message
from server.audit import AuditLog
from server.ledger import Ledger, LedgerDenied, load_payees
from server.llm import Explanation
from server.orchestrator import Orchestrated, orchestrate
from server.policy import Decision
from server.scoring import RedTeam
from server.sessions import Session, SessionBook
from server.sanitiser import sanitise
from server.store import Store
from server.tokens import TokenBook
from shared.schemas import IntentName, PaymentProposal, PolicyId, Verdict

ROOT = Path(__file__).resolve().parents[1]
COOLOFF_SECONDS = 60
HOLD_TTL_SECONDS = 600
_MARKUP = re.compile(r"[<>]")


@dataclass
class Hold:
    proposal: PaymentProposal
    created: datetime
    approvals: set[str] = field(default_factory=set)
    requires_trusted_contact: bool = False


class Guardian:
    def __init__(
        self,
        audit_path: Path | None = None,
        secret: str | None = None,
        cooloff_seconds: int = COOLOFF_SECONDS,
        hold_ttl_seconds: int = HOLD_TTL_SECONDS,
        store_path: Path | None = None,
    ) -> None:
        self.store = Store(store_path)
        self.accounts = self.store.accounts
        self.payees = load_payees()
        self.tokens = TokenBook(secret or os.environ.get("POLICY_SECRET") or "hacknotts-demo-policy")
        self.ledger = Ledger(self.accounts, self.tokens)
        path = audit_path or (ROOT / "server" / "data" / "audit.sqlite")
        self.audit = AuditLog(path)
        self.sessions = SessionBook(self.store)
        self.scoring = RedTeam(**self.store.scores())
        self.cooloff_seconds = cooloff_seconds
        self.hold_ttl_seconds = hold_ttl_seconds
        self.holds = {
            item["proposal"].proposal_id: Hold(
                item["proposal"],
                item["created"],
                item["approvals"],
                item["requires_trusted_contact"],
            )
            for item in self.store.load_holds()
        }

    def open_session(self, account_id: str = "acc-margaret", resume: bool = False) -> str:
        if account_id not in self.accounts:
            raise KeyError(account_id)
        return self.sessions.open(account_id, resume=resume).session_id

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
        self.audit.append(session.session_id, "sanitise", None, {"rejected": clean.rejected, "stripped_encoded": clean.stripped_encoded, "suspicious_instruction": "suspicious_instruction" in (clean.flags or [])})
        if clean.rejected or "suspicious_instruction" in (clean.flags or []):
            reason = clean.rejected or "That message tries to override the guardian. The payment is refused."
            outcome = orchestrate(
                _blank(session),
                None,
                session,
                self.accounts,
                self.payees,
                now,
                decision=Decision(Verdict.DENY, PolicyId.P1_SCHEMA, reason),
            )
        else:
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
        result = self._execute(session, outcome, now, trusted_override=False)
        self.store.add_message(session.session_id, "you", text, None)
        self.store.add_message(session.session_id, "guardian", _screen_text(result), result.get("verdict"))
        return result

    def resolve(
        self,
        proposal_id: str,
        approve: bool,
        now: datetime | None = None,
        channel: str = "trusted_contact",
    ) -> dict:
        """A customer can confirm P4 or P9. Only a trusted contact can release P5."""

        now = _clock(now)
        hold = self.holds.get(proposal_id)
        if hold is None:
            raise KeyError(proposal_id)
        session = self.sessions.get(hold.proposal.session_id)
        age = (now - hold.created).total_seconds()
        if age > self.hold_ttl_seconds:
            self.holds.pop(proposal_id, None)
            outcome = orchestrate(
                hold.proposal,
                None,
                session,
                self.accounts,
                self.payees,
                now,
                decision=Decision(Verdict.DENY, hold.proposal.matched_policy, "The hold expired."),
            )
            return self._execute(session, outcome, now, trusted_override=False)
        if not approve:
            self.holds.pop(proposal_id, None)
            who = "The customer declined." if channel == "customer" else "The trusted contact declined."
            outcome = orchestrate(
                hold.proposal,
                None,
                session,
                self.accounts,
                self.payees,
                now,
                decision=Decision(Verdict.DENY, hold.proposal.matched_policy, who),
            )
            return self._execute(session, outcome, now, trusted_override=False)
        if channel not in {"customer", "trusted_contact"}:
            return self._hold_reply(session, hold, now, "That approval channel is not recognised.")
        if age < self.cooloff_seconds:
            return self._hold_reply(session, hold, now, "This payment is still in the cooling-off period.")
        hold.approvals.add(channel)
        outcome = orchestrate(
            hold.proposal,
            None,
            session,
            self.accounts,
            self.payees,
            now,
            approvals=frozenset(hold.approvals),
        )
        return self._execute(session, outcome, now, trusted_override=channel == "trusted_contact")

    def _execute(self, session, outcome: Orchestrated, now: datetime, trusted_override: bool) -> dict:
        proposal = outcome.proposal
        decision = outcome.decision
        explanation = outcome.explanation
        executed = False
        if decision.verdict == Verdict.ALLOW and proposal.intent == IntentName.PAY:
            self.holds.pop(proposal.proposal_id, None)
            token = self.tokens.mint(proposal, now)
            try:
                self.ledger.execute(proposal, token, now)
                executed = True
            except LedgerDenied as exc:
                decision = Decision(Verdict.DENY, exc.policy, exc.reason)
                proposal = proposal.model_copy(update={"matched_policy": exc.policy})
        elif decision.verdict == Verdict.HOLD:
            current = self.holds.get(proposal.proposal_id)
            if current is None:
                self.holds[proposal.proposal_id] = Hold(
                    proposal,
                    now,
                    set(),
                    decision.requires_trusted_contact,
                )
            else:
                current.proposal = proposal
                current.requires_trusted_contact = decision.requires_trusted_contact
        else:
            self.holds.pop(proposal.proposal_id, None)
        self.scoring.note(decision.verdict, proposal.band, trusted_override, executed, executed)
        self.store.save_scores(self.scoring.snapshot())
        self.sessions.save(session)
        self.store.save_accounts()
        self.store.save_context(
            session.session_id,
            proposal,
            decision.verdict.value if decision.verdict else None,
            decision.matched_policy.value if decision.matched_policy else None,
        )
        self._sync_hold(proposal.proposal_id)
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
        body = _body(session, proposal, decision, explanation, self.ledger, executed, self.scoring, self._cooloff_left(proposal.proposal_id, now))
        body["context"] = self.store.context(session.session_id)
        return body

    def _hold_reply(self, session: Session, hold: Hold, now: datetime, reason: str) -> dict:
        decision = Decision(
            Verdict.HOLD,
            hold.proposal.matched_policy,
            reason,
            hold.requires_trusted_contact,
        )
        body = _body(
            session,
            hold.proposal,
            decision,
            None,
            self.ledger,
            False,
            self.scoring,
            self._cooloff_left(hold.proposal.proposal_id, now),
        )
        body["context"] = self.store.context(session.session_id)
        return body

    def _sync_hold(self, proposal_id: str) -> None:
        hold = self.holds.get(proposal_id)
        if hold is None:
            self.store.delete_hold(proposal_id)
            return
        self.store.save_hold(hold.proposal, hold.created, hold.approvals, hold.requires_trusted_contact)

    def open_hold(self, session_id: str) -> dict | None:
        now = _clock(None)
        for hold in self.holds.values():
            if hold.proposal.session_id != session_id:
                continue
            return {
                "proposal_id": hold.proposal.proposal_id,
                "requires_trusted_contact": hold.requires_trusted_contact,
                "cooloff_remaining_seconds": self._cooloff_left(hold.proposal.proposal_id, now),
            }
        return None

    def _cooloff_left(self, proposal_id: str, now: datetime) -> int:
        hold = self.holds.get(proposal_id)
        if hold is None:
            return 0
        remaining = self.cooloff_seconds - (now - hold.created).total_seconds()
        return max(0, int(remaining + 0.999))


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
    cooloff_remaining_seconds: int = 0,
) -> dict:
    warning = None
    if explanation is not None and (decision.verdict == Verdict.HOLD or explanation.card_ids):
        warning = {
            "text": _MARKUP.sub("", explanation.text),
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
        "requires_trusted_contact": decision.requires_trusted_contact,
        "cooloff_remaining_seconds": cooloff_remaining_seconds,
        "scoring": scoring.snapshot(),
    }


def _screen_text(result: dict) -> str:
    explanation = result.get("explanation") or {}
    if explanation.get("text"):
        return explanation["text"]
    parts = []
    if result.get("verdict"):
        policy = result.get("matched_policy")
        parts.append(result["verdict"] + (f" ({policy})" if policy else ""))
    if result.get("reason"):
        parts.append(result["reason"])
    if isinstance(result.get("balance"), (int, float)):
        parts.append(f"Balance £{float(result['balance']):.2f}")
    return ". ".join(parts) or "No payment was requested."


def _clock(now: datetime | None) -> datetime:
    if now is None:
        return datetime.now(timezone.utc)
    if now.tzinfo is None:
        return now.replace(tzinfo=timezone.utc)
    return now
