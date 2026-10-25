"""Orchestrator: wires everything together. It NEVER moves money itself and NEVER trusts an LLM approval.
Only ledger.execute(proposal, token) moves money, and a token is minted only after policy says ALLOW."""
import math
import re
import time
import uuid
from decimal import ROUND_HALF_UP, Decimal

from pydantic import ValidationError

from .ledger import LedgerError
from .policy import PolicyContext, SessionTracker, evaluate
from .sanitiser import sanitise
from .schemas import DecisionType, Intent, ParsedIntent, PaymentProposal, RiskBand, RiskResult


# ---- TEMPORARY stand-ins so you are never blocked. Replace with teammates' real modules. ----
_PAYEE_RE = re.compile(r"\b([A-Z]{3,}\d{3})\b")
_AMOUNT_RE = re.compile(r"£\s?([0-9][0-9,]*(?:\.[0-9]{1,2})?)")


def stub_parser(text):
    low = text.lower()
    payee = _PAYEE_RE.search(text)
    amount = _AMOUNT_RE.search(text)
    if "change payee" in low:
        return ParsedIntent(intent=Intent.CHANGE_PAYEE)
    if payee and amount and "pay" in low:
        return ParsedIntent(intent=Intent.PAY, payee_id=payee.group(1),
                            amount=float(amount.group(1).replace(",", "")))
    return ParsedIntent(intent=Intent.UNKNOWN)


def stub_scorer(text, flags):
    """Reasons are RAG card ids (same convention the real RAG/ML code should follow)."""
    low = text.lower()
    reasons = []
    if "safe account" in low:
        reasons.append("safe-account")
    if "hmrc" in low:
        reasons.append("hmrc-impersonation")
    if "suspicious_instruction" in flags:
        reasons.append("prompt-injection")
    if "immediately" in low or "urgent" in low:
        reasons.append("urgency-pressure")
    if reasons:
        return RiskResult(injection_risk=0.9, scam_risk=0.9, final_risk=0.9,
                          risk_band=RiskBand.HIGH, reasons=reasons)
    return RiskResult(final_risk=0.05, risk_band=RiskBand.LOW)
# ---------------------------------------------------------------------------------------------


def pounds_to_pence(amount):
    """Convert once, at the boundary. Rejects None/NaN/inf."""
    if amount is None or isinstance(amount, bool) or not math.isfinite(amount):
        raise ValueError("BAD_AMOUNT")
    return int((Decimal(str(amount)) * 100).to_integral_value(rounding=ROUND_HALF_UP))


class Orchestrator:
    def __init__(self, ledger, authority, audit, tracker=None, parser=stub_parser, scorer=stub_scorer,
                 session_owners=None, trusted_contacts=None, cooloff_seconds=0, pending_ttl=600,
                 clock=time.time):
        self._ledger, self._authority, self._audit = ledger, authority, audit
        self._tracker = tracker or SessionTracker(clock)
        self._parser, self._scorer = parser, scorer
        self._owners = dict(session_owners or {})          # session_id -> owner
        self._trusted = {k: set(v) for k, v in (trusted_contacts or {}).items()}  # account_id -> approvers
        self._cooloff, self._pending_ttl, self._clock = cooloff_seconds, pending_ttl, clock
        self._pending = {}

    def register_session(self, session_id, owner):
        self._owners[session_id] = owner

    def register_trusted_contact(self, account_id, approver):
        self._trusted.setdefault(account_id, set()).add(approver)

    def record_payee_change(self, session_id):
        """Call this from whatever endpoint changes payee details (feeds rule P9)."""
        self._tracker.mark_payee_changed(session_id)
        self._audit.log_event(session_id, "PAYEE_CHANGE_RECORDED")

    # ------------------------------------------------------------------ analyse only (never moves money)
    def analyse(self, sid, raw_text):
        self._audit.log_event(sid, "ANALYSE_REQUEST", {"length": len(raw_text) if isinstance(raw_text, str) else None})
        clean = sanitise(raw_text)
        if clean["blocked"]:
            out = {"risk_band": "LOW", "flags": clean["flags"], "reasons": [], "intent": "UNKNOWN", "blocked": True}
        else:
            try:
                intent = self._parser(clean["cleaned_text"])
                intent = (intent if isinstance(intent, ParsedIntent) else ParsedIntent.model_validate(intent)).intent.value
            except Exception:
                intent = "UNKNOWN"
            try:
                risk = self._scorer(clean["cleaned_text"], clean["flags"])
                risk = risk if isinstance(risk, RiskResult) else RiskResult.model_validate(risk)
            except Exception:
                risk = RiskResult(final_risk=1.0, risk_band=RiskBand.HIGH, reasons=["GUARD_FAILURE"])
            out = {"risk_band": risk.risk_band.value, "flags": clean["flags"], "reasons": list(risk.reasons),
                   "intent": intent, "blocked": False}
        self._audit.log_event(sid, "ANALYSE_RESULT", {"band": out["risk_band"], "flags": out["flags"],
                                                      "reasons": out["reasons"]})
        return out

    # ------------------------------------------------------------------ main entry point
    def handle_message(self, session_id, raw_text):
        try:
            return self._handle(session_id, raw_text)
        except Exception as exc:   # fail closed: an error is never an ALLOW
            self._audit.log_event(session_id, "ORCHESTRATOR_ERROR", {"error": type(exc).__name__})
            return self._result("DENIED", rule_id="P0", reason="INTERNAL_ERROR")

    def _handle(self, sid, raw_text):
        self._audit.log_event(sid, "REQUEST_RECEIVED",
                              {"length": len(raw_text) if isinstance(raw_text, str) else None})
        clean = sanitise(raw_text)
        self._audit.log_event(sid, "SANITISER_RESULT", {"flags": clean["flags"], "blocked": clean["blocked"]})
        if clean["blocked"]:
            return self._deny(sid, "P1", "INPUT_BLOCKED")

        try:
            parsed = self._parser(clean["cleaned_text"])
            if not isinstance(parsed, ParsedIntent):
                parsed = ParsedIntent.model_validate(parsed)
        except Exception:
            return self._deny(sid, "P1", "PARSER_FAILED")

        try:
            risk = self._scorer(clean["cleaned_text"], clean["flags"])
            if not isinstance(risk, RiskResult):
                risk = RiskResult.model_validate(risk)
        except Exception:
            risk = RiskResult(final_risk=1.0, risk_band=RiskBand.HIGH, reasons=["GUARD_FAILURE"])
        self._audit.log_event(sid, "RISK_RESULT", {"band": risk.risk_band.value, "final_risk": risk.final_risk,
                                                   "reasons": risk.reasons})

        if parsed.intent == Intent.CHANGE_PAYEE:
            self.record_payee_change(sid)
            return self._result("PAYEE_CHANGE_RECORDED", risk=risk)
        if parsed.intent != Intent.PAY:
            return self._deny(sid, "P1", "UNSUPPORTED_INTENT", risk)

        owner = self._owners.get(sid)
        accounts = self._ledger.accounts_owned_by(owner) if owner else []
        if not accounts:
            return self._deny(sid, "P2", "NO_ACCOUNT_FOR_SESSION", risk)
        try:
            proposal = PaymentProposal(
                proposal_id="TXN-" + uuid.uuid4().hex[:16], session_id=sid,
                account_id=accounts[0],                      # from the SESSION, never from the message
                payee_id=parsed.payee_id or "", amount_pence=pounds_to_pence(parsed.amount),
                reference=parsed.reference)
        except (ValueError, ValidationError):
            return self._deny(sid, "P1", "INVALID_PROPOSAL", risk)

        attempts = self._tracker.record_attempt(sid)
        ctx = self._build_ctx(sid, proposal, risk.risk_band, frozenset(), attempts)
        decision = evaluate(proposal, ctx)
        self._audit.log_event(sid, "POLICY_DECISION", {"proposal_id": proposal.proposal_id,
                              **decision.model_dump(mode="json")})

        if decision.decision == DecisionType.DENY:
            if decision.lock_session:
                self._tracker.lock(sid)
            return self._result("DENIED", proposal, decision, risk=risk)
        if decision.decision == DecisionType.HOLD:
            self._pending[proposal.proposal_id] = {
                "proposal": proposal, "band": risk.risk_band, "risk": risk, "approvals": set(),
                "status": "PENDING", "created": self._clock(), "receipt": None,
                "requires_tc": decision.requires_trusted_contact,
                "rule_ids": list(decision.triggered), "reason": decision.reason}
            self._audit.log_event(sid, "HOLD_CREATED", {"proposal_id": proposal.proposal_id,
                                  "rule_id": decision.rule_id})
            return self._result("HOLD", proposal, decision, risk=risk)
        return self._execute(sid, proposal, decision, risk)

    # ------------------------------------------------------------------ approvals
    def _expire_if_needed(self, pend):
        if pend["status"] == "PENDING" and self._clock() - pend["created"] > self._pending_ttl:
            pend["status"] = "EXPIRED"
            self._audit.log_event(pend["proposal"].session_id, "HOLD_EXPIRED",
                                  {"proposal_id": pend["proposal"].proposal_id})

    def resolve_hold(self, proposal_id, approval, channel):
        """channel is set by YOUR BACKEND ENDPOINT ('customer' or 'trusted_contact'), never by the client."""
        pend = self._pending.get(proposal_id)
        if pend is None:
            return self._result("DENIED", reason="UNKNOWN_PROPOSAL")
        proposal, sid = pend["proposal"], pend["proposal"].session_id
        self._expire_if_needed(pend)
        if pend["status"] == "EXPIRED":
            return self._result("EXPIRED", proposal)
        if pend["status"] != "PENDING":
            return self._result(pend["status"], proposal, reason="ALREADY_RESOLVED")

        approval = approval if isinstance(approval, dict) else {}
        approver = approval.get("approved_by")
        valid = (approval.get("proposal_id") == proposal_id and (
            (channel == "trusted_contact" and approver in self._trusted.get(proposal.account_id, set())) or
            (channel == "customer" and approver == self._owners.get(sid))))
        if not valid:
            self._audit.log_event(sid, "APPROVAL_REJECTED", {"proposal_id": proposal_id, "channel": channel})
            return self._result("HOLD", proposal, reason="INVALID_APPROVAL")

        if approval.get("approval_status") == "DECLINED":
            pend["status"] = "DECLINED"
            self._audit.log_event(sid, "HOLD_DECLINED", {"proposal_id": proposal_id, "channel": channel})
            return self._result("DECLINED", proposal)
        if approval.get("approval_status") != "APPROVED":
            return self._result("HOLD", proposal, reason="INVALID_APPROVAL")
        if self._clock() - pend["created"] < self._cooloff:
            return self._result("COOLING_OFF", proposal)

        pend["approvals"].add(channel)
        self._audit.log_event(sid, "HOLD_APPROVED", {"proposal_id": proposal_id, "channel": channel})
        ctx = self._build_ctx(sid, proposal, pend["band"], frozenset(pend["approvals"]),
                              self._tracker.count(sid))
        decision = evaluate(proposal, ctx)                  # policy is re-checked after every approval
        self._audit.log_event(sid, "POLICY_RECHECK", {"proposal_id": proposal_id,
                              **decision.model_dump(mode="json")})
        if decision.decision == DecisionType.DENY:
            pend["status"] = "DENIED"
            return self._result("DENIED", proposal, decision)
        if decision.decision == DecisionType.HOLD:
            pend.update(requires_tc=decision.requires_trusted_contact, rule_ids=list(decision.triggered),
                        reason=decision.reason)
            return self._result("HOLD", proposal, decision)
        pend["status"] = "EXECUTED"
        return self._execute(sid, proposal, decision, pend["risk"])

    def get_hold(self, proposal_id):
        """Read-only snapshot used by the API (ownership checks, GET /holds, explanations)."""
        pend = self._pending.get(proposal_id)
        if pend is None:
            return None
        self._expire_if_needed(pend)
        p = pend["proposal"]
        pending = pend["status"] == "PENDING"
        now = self._clock()
        return {"status": pend["status"], "owner": self._owners.get(p.session_id), "account_id": p.account_id,
                "requires_trusted_contact": pend["requires_tc"], "approvals": sorted(pend["approvals"]),
                "cooloff_remaining_seconds": max(0, math.ceil(pend["created"] + self._cooloff - now)) if pending else 0,
                "expires_in_seconds": max(0, math.ceil(pend["created"] + self._pending_ttl - now)) if pending else 0,
                "rule_ids": list(pend["rule_ids"]), "reason": pend["reason"],
                "risk_band": pend["risk"].risk_band.value, "risk_reasons": list(pend["risk"].reasons),
                "receipt": pend["receipt"]}

    # ------------------------------------------------------------------ internals
    def _build_ctx(self, sid, proposal, band, approvals, attempts):
        L, acct, payee = self._ledger, proposal.account_id, proposal.payee_id
        exists = L.account_exists(acct)
        return PolicyContext(
            owned_accounts=frozenset(L.accounts_owned_by(self._owners.get(sid))) if self._owners.get(sid) else frozenset(),
            account_exists=exists,
            balance_pence=L.balance(acct) if exists else 0,
            daily_limit_pence=L.daily_limit(acct) if exists else 0,
            daily_total_pence=L.daily_total(acct) if exists else 0,
            payee_exists=L.payee_exists(payee), payee_known=L.payee_known(acct, payee),
            payee_is_mule=L.is_mule(payee), attempts_in_window=attempts,
            session_locked=self._tracker.is_locked(sid),
            payee_changed_in_session=self._tracker.payee_changed(sid),
            risk_band=band, approvals=approvals)

    def _execute(self, sid, proposal, decision, risk=None):
        token = self._authority.mint(proposal)
        self._audit.log_event(sid, "TOKEN_MINTED", {"proposal_id": proposal.proposal_id,
                              "token_id": token["claims"]["token_id"]})
        try:
            receipt = self._ledger.execute(proposal, token)
        except LedgerError as exc:
            self._audit.log_event(sid, "PAYMENT_FAILED", {"proposal_id": proposal.proposal_id,
                                  "rule_id": exc.rule_id, "reason": exc.reason})
            return self._result("FAILED", proposal, reason=exc.reason, rule_id=exc.rule_id, risk=risk)
        self._audit.log_event(sid, "PAYMENT_EXECUTED", receipt)
        return self._result("EXECUTED", proposal, decision, receipt=receipt, risk=risk)

    def _deny(self, sid, rule_id, reason, risk=None):
        self._audit.log_event(sid, "PAYMENT_DENIED", {"rule_id": rule_id, "reason": reason})
        return self._result("DENIED", rule_id=rule_id, reason=reason, risk=risk)

    def _result(self, status, proposal=None, decision=None, reason=None, rule_id=None, receipt=None, risk=None):
        pend = self._pending.get(proposal.proposal_id) if proposal else None
        if risk is None and pend:
            risk = pend["risk"]
        rid = rule_id or (decision.rule_id if decision else None)
        rule_ids = list(decision.triggered) if decision and decision.triggered else []
        if not rule_ids and rid and rid != "NONE":
            rule_ids = [rid]
        if not rule_ids and pend:
            rule_ids = list(pend["rule_ids"])
        if status == "EXECUTED" and pend:
            pend["receipt"] = receipt
        return {"status": status,
                "proposal_id": proposal.proposal_id if proposal else None,
                "rule_id": rid,
                "rule_ids": rule_ids,
                "reason": reason or (decision.reason if decision else None) or (pend["reason"] if pend else None),
                "requires_trusted_contact": bool(decision and decision.requires_trusted_contact)
                                            or bool(pend and pend["requires_tc"] and status in ("HOLD", "COOLING_OFF")),
                "risk_band": risk.risk_band.value if risk else None,
                "risk_reasons": list(risk.reasons) if risk else [],
                "receipt": receipt}
