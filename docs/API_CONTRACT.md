# BreakMyAgent Security Core - API contract for Role D (frontend)

Implemented in `server/api.py` and covered by `tests/test_api.py`. All paths are under `/api`, JSON in and out, snake_case.

## Rules the browser follows
1. The browser never decides ALLOW / HOLD / DENY. It displays `verdict`, `rule_id` / `rule_ids`, `hold_id`, `execution` exactly as received.
2. If a request fails at the network level, or the response is a 5xx or `SECURITY_SERVICE_UNAVAILABLE`, show **"security service unavailable"**. Never show a mock approval.
3. Render every received string with `textContent` (never `innerHTML`). All server strings are plain text.
4. No tokens in `localStorage`. Auth is the HttpOnly cookie `bma_session` (`SameSite=Lax`; `Secure` when `COOKIE_SECURE=1` on HTTPS). Use same-origin requests (serve the pages from this server, or use your dev server's `/api` proxy). CORS is intentionally NOT enabled. If you fetch cross-origin, tell me the exact origin and use `credentials: "include"`.

## Error envelope (every non-2xx JSON response)
```json
{ "error": { "code": "VALIDATION_ERROR", "message": "Some fields are invalid.",
             "request_id": "req_a1b2c3d4e5f6", "fields": { "password": "too_short" } } }
```
`fields` is present only for validation errors. Values are codes (`required`, `too_short`, `too_long`, `invalid`, `in_use`), never echoed user input. `message` is fixed plain text. The same id is in the `X-Request-ID` header.

| HTTP | code | when |
|---|---|---|
| 401 | `UNAUTHENTICATED` | no/expired session cookie |
| 401 | `INVALID_CREDENTIALS` | bad email or password (same message for unknown email) |
| 403 | `CSRF_ORIGIN` | request carries a foreign `Origin` header |
| 403 | `FORBIDDEN` | bad or missing trusted key on ops/trusted routes |
| 403 | `APPROVAL_NOT_PERMITTED` | trusted approver id not allowed for this hold |
| 404 | `NOT_FOUND` | unknown route, unknown hold, or hold that is not yours (same answer) |
| 409 | `EMAIL_IN_USE` | signup with an existing email |
| 413 | `PAYLOAD_TOO_LARGE` | body over 64 KB |
| 422 | `VALIDATION_ERROR` | bad body (also malformed JSON) |
| 429 | `RATE_LIMITED` | too many requests; `Retry-After` header in seconds |
| 503 | `SECURITY_SERVICE_UNAVAILABLE` | security pipeline failed or crashed |

## Auth
| Call | Request | Success |
|---|---|---|
| `POST /api/auth/signup` | `{display_name 1-50 chars no < >, email, password 10-128}` | `201 {"profile":{"id","display_name"}}` + sets cookie (you are logged in) |
| `POST /api/auth/login` | `{email, password}` | `200 {"profile":{"id","display_name"}}` + sets a NEW cookie |
| `POST /api/auth/logout` | none | `204`, cookie cleared, live sockets closed (idempotent) |
| `GET /api/me` | none | `200 {"profile":{"id","display_name","account_summary":{"currency":"GBP","balance_pence","daily_limit_pence","daily_spent_pence","daily_remaining_pence"}}}` or `401` |

Money is always integer pence. Sessions last 8 hours. Signup gives a fictional demo account with a funded balance and `RENT001` as a known payee.

## Analyse (never moves money)
`POST /api/analyse` `{ "message": string 1-4000 }` -> `200`
```json
{ "analysis": { "risk_band": "LOW|MEDIUM|HIGH", "intent": "PAY|BALANCE|CHANGE_PAYEE|UNKNOWN",
                "flags": ["suspicious_instruction"], "reasons": ["safe-account"],
                "explanation": { "text": "...", "card_ids": ["safe-account"], "source": "template" } } }
```
`explanation` is `null` when `risk_band` is `LOW`.

## Propose a payment
`POST /api/payments/propose` `{ "message": string 1-4000 }`. Always `200` when the pipeline ran; the answer is in the body.
```json
{ "verdict": "ALLOW|HOLD|DENY", "status": "EXECUTED|HOLD|COOLING_OFF|DENIED|FAILED|PAYEE_CHANGE_RECORDED",
  "message": "Payment held for additional approval.",
  "proposal_id": "TXN-...", "hold_id": "TXN-... or null", "rule_id": "P5 or null", "rule_ids": ["P5"],
  "reason": "HIGH_RISK", "risk_band": "HIGH",
  "hold": { "state": "PENDING", "requires_trusted_contact": true, "approvals_received": [],
            "cooloff_remaining_seconds": 0, "expires_in_seconds": 600 },
  "execution": { "executed": true, "payee_id": "RENT001", "amount_pence": 75000, "new_balance_pence": 425000 },
  "explanation": { "text": "plain text", "card_ids": ["safe-account"], "source": "template" } }
```
- `hold` is non-null only for holds. `execution` is non-null only for `EXECUTED` (`executed:true`) or `FAILED` (`executed:false`, other fields null).
- **`explanation` is non-null exactly when `verdict` is `HOLD`.** `text` plain, no HTML, never contains the customer's message; `card_ids` has at most 2 ids; `source` is exactly `"template"` or `"llm"`. The server forces this shape on every explanation, including LLM-written ones, and the explainer never sees the raw message.
- `reason` and `rule_id` values are server codes (for example `HIGH_RISK`, `P6`). Map them to nicer wording on your side if you like, and show unknown codes as-is.

## Holds
- `GET /api/holds/{hold_id}` -> same envelope as above (current state). Use it for polling or page reloads. `404` for unknown or not yours.
- `POST /api/holds/{hold_id}/decision` `{ "decision": "APPROVE|DECLINE", "approver"?: string }` -> `200` envelope.
  - **Customer (cookie session):** `approver` is ignored. A customer APPROVE clears second-approval holds (new payee, payee changed) but **cannot** clear a HIGH-risk (P5) hold: the response stays `HOLD` with `approvals_received:["customer"]` until a trusted contact approves.
  - **Trusted contact (Pi box / ops page):** send header `X-Trusted-Key: <shared key>` and `approver` (for example `"trusted_contact_1"`). This key must never be in the customer's browser.
  - Policy is re-checked after every approval. `status` can be `EXECUTED` (verdict ALLOW), `DECLINED`, `EXPIRED`, `DENIED` (verdict DENY), `HOLD` / `COOLING_OFF` (verdict HOLD, still waiting).

## Live status WebSocket: `GET /api/ws` (browser connects to `ws(s)://<same host>/api/ws`)
Server -> browser only. Event shape (the `data` is exactly the REST envelope above, so one renderer handles both):
```json
{ "type": "hold.created|hold.updated|hold.declined|hold.expired|payment.executed|payment.denied",
  "hold_id": "TXN-... or null", "data": { "...envelope..." }, "ts": "2026-10-24T14:00:00+00:00" }
```
Also `{"type":"connected"}` on open, `{"type":"heartbeat"}` every 25 s, and `{"type":"pong"}` in reply to the text message `ping`. Anything else the browser sends is ignored. Events go only to the owner of the hold.

## Answers to the three questions
1. **WebSocket auth:** the browser's same-origin handshake automatically carries the HttpOnly session cookie, so there is no token in the URL or in messages. The server validates the cookie and the `Origin` header (a foreign origin is refused: handshake closes with code 1008). With a missing or invalid session the socket is accepted and immediately closed with **code 4401**; treat 4401 as "signed out" and call `GET /api/me`. Logout or session expiry closes the socket with 4401. After any reconnect, call `GET /api/holds/{id}` to resync.
2. **Trusted-contact decisions** come ONLY through `POST /api/holds/{id}/decision` (with the trusted key). The WebSocket is read-only, so a socket can never approve or decline anything. The result of a trusted decision is pushed to the customer's WebSocket as an event.
3. **Error envelope:** see "Error envelope" above, the same shape for login/signup, payments, holds and WebSocket-adjacent HTTP errors.
