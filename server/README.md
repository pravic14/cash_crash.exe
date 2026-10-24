# server/ — A, Security core

You own this folder except `llm.py`, which C adds here (quarantined parser, explainer, offline fallback). Leave that file to C.

## Files to add

| File | Role |
| --- | --- |
| `main.py` | App entry. Wires the pipeline. |
| `sanitiser.py` | G0. Unicode normalise, strip zero-width, detect base64/hex, length limits. |
| `orchestrator.py` | Builds a `PaymentProposal` from a `ParsedIntent`. Never forwards raw text. |
| `policy.py` | G5. Final veto. ALLOW / HOLD / DENY from P1–P9 in `shared.schemas.PolicyId`. ALLOW mints a capability token (HMAC, args-bound, 30s, single use). |
| `ledger.py` | Fictional accounts. `execute(proposal, token)` is the only mutation. Enforces P8. |
| `audit.py` | SQLite hash chain (SHA-256), `verify_chain()`, per-session replay. |
| `scoring.py` | Red Team points. HOLD escalation and a model evasion score; a bounty only if an unauthorised payment actually executes. |
| `ws.py` | WebSocket the Pi connects to as a client. Dashboard buttons must work if the Pi is dead. |
| `llm.py` | **C owns this file.** |
| `data/` | Seed accounts and payees. IDs are already frozen for the demo. |

## Pipeline you sit in the middle of

Sanitiser → sentinel (B's models + C's retriever) → C's parser → your orchestrator → B's transaction guard and fusion → your policy kernel → ledger, or maker-checker (hold, cooling-off, customer re-confirm, Pi approve on HIGH) → policy checked again → ledger.

## Demo accounts

See `data/accounts.json` and `data/payees.json`. Margaret's rent to `payee-landlord` is the instant ALLOW. A new payee over £250 is a HOLD (P4). `payee-mule` is a DENY (P6).
