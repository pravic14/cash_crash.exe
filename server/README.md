# server/ — A, Security core

You own this folder except `llm.py` and `assess.py`, which C adds here. Leave those two files to C. They are already called by this pipeline.

## What runs

`POST /payments` calls `Guardian.submit`:

1. `sanitiser.sanitise`
2. `assess.assess_message` — retriever, quarantined parser, M1–M4
3. `orchestrator.orchestrate` — seals the proposal and calls `policy.decide`
4. ALLOW mints a token and `ledger.execute`. HOLD waits 60 seconds. A customer can confirm P4 or P9 after that. Only a trusted contact can release P5, and the HTTP route accepts that channel only with the `X-Trusted-Contact` header. A hold expires after 10 minutes. DENY changes nothing. The balance, the session, the hold, and the chat lines are written to `data/guardian.sqlite`. The JSON files are the seed.

## Files

| File | Role |
| --- | --- |
| `main.py` | App entry. Wires the pipeline. |
| `sanitiser.py` | G0. Unicode normalise, strip zero-width, detect base64/hex, length limits. |
| `orchestrator.py` | Seals the scored proposal and calls `policy.decide`. Never forwards raw text. |
| `policy.py` | G5. Final veto. ALLOW / HOLD / DENY from P1–P9 in `shared.schemas.PolicyId`. ALLOW mints a capability token (HMAC, args-bound, 30s, single use). |
| `ledger.py` | Fictional accounts. `execute(proposal, token)` is the only balance mutation. Enforces P8. The new balance is saved by `store.py`. |
| `store.py` | SQLite. Users, balances, session facts, chat transcript, holds, scoreboard. |
| `audit.py` | Separate SQLite hash chain (SHA-256), `verify_chain()`, per-session replay. Never stores the customer message. |
| `scoring.py` | Red Team points. HOLD escalation and a model evasion score; a bounty only if an unauthorised payment actually executes. |
| `ws.py` | WebSocket the Pi connects to as a client. Dashboard buttons must work if the Pi is dead. |
| `llm.py` | **C owns this file.** |
| `assess.py` | **C owns this file.** Call `assess_message` for retrieval, the parser, and M1–M4. You still own the verdict. |
| `data/` | `accounts.json` and `payees.json` are the seed. `guardian.sqlite` is the live database. `audit.sqlite` is the hash chain. |

A trusted-contact approve runs policy again. The customer can release P4 and P9 after the cooling-off period. P5 needs `X-Trusted-Contact`. P6, P3, P2, P7, and P1 still deny. The Pi listens on `/ws`. The HTTP decision route works when the Pi is unplugged.

## Demo accounts

See `data/accounts.json` and `data/payees.json`. Margaret's rent to `payee-landlord` is the instant ALLOW. A new payee over £250 is a HOLD (P4). `payee-mule` is a DENY (P6).
