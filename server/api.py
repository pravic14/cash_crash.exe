"""HTTP + WebSocket API for the customer UI. The browser NEVER decides ALLOW/HOLD/DENY: it only renders what
this layer returns from the policy kernel / ledger. See docs/API_CONTRACT.md for the full contract."""
import asyncio
import datetime
import hmac
import os
import re
import secrets
import threading
import time
from typing import Literal, Optional

from fastapi import FastAPI, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.concurrency import run_in_threadpool
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator
from starlette.exceptions import HTTPException as StarletteHTTPException

from .auth import EmailTaken
from .explainer import build_explanation, normalise_explanation

COOKIE = "bma_session"
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
MAX_BODY_BYTES = 65_536
_EMAIL_RE = re.compile(r"^[^@\s<>]{1,64}@[^@\s<>]{1,190}\.[^@\s<>]{2,}$")
_HOLD_RE = re.compile(r"^TXN-[0-9a-f]{16}$")
_CODE_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

_VERDICT = {"EXECUTED": "ALLOW", "HOLD": "HOLD", "COOLING_OFF": "HOLD"}
_MESSAGES = {"ALLOW": "Payment completed.", "HOLD": "Payment held for additional approval.",
             "DENY": "Payment blocked by security rules."}
_FIELD_ERRORS = {"missing": "required", "string_too_short": "too_short", "string_too_long": "too_long"}


class ApiError(Exception):
    def __init__(self, status, code, message, fields=None, headers=None):
        self.status, self.code, self.message, self.fields, self.headers = status, code, message, fields, headers or {}


def error_body(code, message, request_id, fields=None):
    err = {"code": code, "message": message, "request_id": request_id}
    if fields:
        err["fields"] = fields
    return {"error": err}


def error_response(status, code, message, request_id, fields=None, headers=None):
    return JSONResponse(error_body(code, message, request_id, fields), status_code=status, headers=headers)


# ----------------------------------------------------------------------------- request models
class _Req(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SignupIn(_Req):
    display_name: str = Field(min_length=1, max_length=50)
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=10, max_length=128)

    @field_validator("display_name")
    @classmethod
    def _name(cls, v):
        v = v.strip()
        if not v or any(c in v for c in "<>") or any(ord(c) < 32 for c in v):
            raise ValueError("invalid")
        return v

    @field_validator("email")
    @classmethod
    def _email(cls, v):
        v = v.strip().lower()
        if not _EMAIL_RE.match(v):
            raise ValueError("invalid")
        return v


class LoginIn(_Req):
    email: str = Field(min_length=1, max_length=254)
    password: str = Field(min_length=1, max_length=128)

    @field_validator("email")
    @classmethod
    def _email(cls, v):
        return v.strip().lower()


class MessageIn(_Req):
    message: str = Field(min_length=1, max_length=4000)


class DecisionIn(_Req):
    decision: Literal["APPROVE", "DECLINE"]
    approver: Optional[str] = Field(default=None, max_length=64)


# ----------------------------------------------------------------------------- helpers
class RateLimiter:
    def __init__(self, clock=time.time):
        self._clock, self._events, self._lock = clock, {}, threading.Lock()

    def hit(self, key, limit, window):
        now = self._clock()
        with self._lock:
            q = [t for t in self._events.get(key, []) if t > now - window]
            if len(q) >= limit:
                self._events[key] = q
                return False, int(q[0] + window - now) + 1
            q.append(now)
            self._events[key] = q
            return True, 0

    def clear(self, key):
        with self._lock:
            self._events.pop(key, None)


class Hub:
    """Live status push (server -> browser only). Events go only to the owning user's sockets."""

    def __init__(self):
        self._conns = {}

    def add(self, user_id, ws):
        self._conns.setdefault(user_id, set()).add(ws)

    def remove(self, user_id, ws):
        self._conns.get(user_id, set()).discard(ws)

    async def send(self, user_id, event):
        for ws in list(self._conns.get(user_id, ())):
            try:
                await ws.send_json(event)
            except Exception:
                self.remove(user_id, ws)

    async def close_user(self, user_id, code=4401):
        for ws in list(self._conns.get(user_id, ())):
            try:
                await ws.close(code=code)
            except Exception:
                pass
            self.remove(user_id, ws)


def _codes(values):
    return [v for v in values if isinstance(v, str) and _CODE_RE.match(v)][:8]


def create_app(orch, audit, ledger, users, *, trusted_key=None, allowed_origins=(), cookie_secure=None,
               signup_balance_pence=500_000, signup_daily_limit_pence=400_000, default_known_payees=("RENT001",),
               trusted_approver="trusted_contact_1", heartbeat_seconds=25, explainer=None, clock=time.time):
    key = trusted_key or os.environ.get("TRUSTED_CONTACT_KEY") or secrets.token_hex(16)
    secure = (os.environ.get("COOKIE_SECURE") == "1") if cookie_secure is None else cookie_secure
    origins = {o.rstrip("/") for o in allowed_origins}
    app = FastAPI(title="BreakMyAgent Security Core", docs_url="/docs")
    app.state.trusted_key = key
    limiter, hub = RateLimiter(clock), Hub()

    # ------------------------------------------------------------------ middleware + errors
    def origin_ok(origin, host, scheme):
        return origin.rstrip("/") in origins or origin.rstrip("/") == f"{scheme}://{host}"

    @app.middleware("http")
    async def guard(request: Request, call_next):
        rid = "req_" + secrets.token_hex(6)
        request.state.request_id = rid
        api = request.url.path.startswith("/api/")
        if api and request.method in UNSAFE_METHODS:
            origin = request.headers.get("origin")
            if origin and not origin_ok(origin, request.headers.get("host", ""), request.url.scheme):
                return error_response(403, "CSRF_ORIGIN", "Cross-origin request blocked.", rid)
            length = request.headers.get("content-length", "")
            if length.isdigit() and int(length) > MAX_BODY_BYTES:
                return error_response(413, "PAYLOAD_TOO_LARGE", "Request too large.", rid)
        response = await call_next(request)
        response.headers["X-Request-ID"] = rid
        if api:
            response.headers["Cache-Control"] = "no-store"
            response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    def rid_of(request):
        return getattr(request.state, "request_id", "req_unknown")

    @app.exception_handler(ApiError)
    async def _api_error(request, exc):
        return error_response(exc.status, exc.code, exc.message, rid_of(request), exc.fields, exc.headers)

    @app.exception_handler(RequestValidationError)
    async def _validation(request, exc):
        fields = {}
        for err in exc.errors():
            loc = [p for p in err.get("loc", ()) if p != "body" and isinstance(p, str)]
            if loc:
                fields[loc[-1]] = _FIELD_ERRORS.get(err.get("type"), "invalid")
        msg = "Some fields are invalid." if fields else "Request could not be understood."
        return error_response(422, "VALIDATION_ERROR", msg, rid_of(request), fields or None)

    @app.exception_handler(StarletteHTTPException)
    async def _http(request, exc):
        code = {404: "NOT_FOUND", 405: "METHOD_NOT_ALLOWED"}.get(exc.status_code, "HTTP_ERROR")
        return error_response(exc.status_code, code, "Not found." if exc.status_code == 404 else "Request failed.",
                              rid_of(request))

    @app.exception_handler(Exception)
    async def _unhandled(request, exc):
        return error_response(503, "SECURITY_SERVICE_UNAVAILABLE", "Security service unavailable.", rid_of(request))

    # ------------------------------------------------------------------ small helpers
    def client_ip(request):
        return request.client.host if request.client else "unknown"

    def throttle(k, limit, window):
        ok, retry = limiter.hit(k, limit, window)
        if not ok:
            raise ApiError(429, "RATE_LIMITED", "Too many requests. Please try again later.",
                           headers={"Retry-After": str(retry)})

    def require_user(request):
        user = users.session_user(request.cookies.get(COOKIE))
        if not user:
            raise ApiError(401, "UNAUTHENTICATED", "Please sign in.")
        orch.register_session(sid_of(user), user["id"])
        for acct in ledger.accounts_owned_by(user["id"]):      # rebuilt on every request, so restarts are safe
            orch.register_trusted_contact(acct, trusted_approver)
        return user

    def sid_of(user):
        return "user-" + user["id"]      # internal; never sent to the browser

    def trusted_ok(request):
        supplied = request.headers.get("x-trusted-key")
        if supplied is None:
            return False
        throttle("trusted:" + client_ip(request), 30, 60)
        if not hmac.compare_digest(supplied.encode(), key.encode()):
            audit.log_event("ops", "TRUSTED_KEY_REJECTED", {})
            raise ApiError(403, "FORBIDDEN", "Not permitted.")
        return True

    def set_cookie(resp, value):
        resp.set_cookie(COOKIE, value, max_age=users.session_ttl, httponly=True, samesite="lax",
                        secure=secure, path="/")

    def make_envelope(res):
        status = res["status"]
        verdict = _VERDICT.get(status, "DENY")
        pid = res.get("proposal_id")
        hold = orch.get_hold(pid) if pid else None
        rule_ids = _codes(res.get("rule_ids") or [])
        rule_id = res.get("rule_id")
        env = {"verdict": verdict, "status": status, "message": _MESSAGES[verdict],
               "proposal_id": pid, "hold_id": pid if hold else None,
               "rule_id": rule_id if rule_id and rule_id != "NONE" else None, "rule_ids": rule_ids,
               "reason": res.get("reason"), "risk_band": res.get("risk_band"),
               "hold": None, "execution": None, "explanation": None}
        if hold:
            env["hold"] = {"state": hold["status"], "requires_trusted_contact": hold["requires_trusted_contact"],
                           "approvals_received": hold["approvals"],
                           "cooloff_remaining_seconds": hold["cooloff_remaining_seconds"],
                           "expires_in_seconds": hold["expires_in_seconds"]}
        receipt = res.get("receipt")
        if status == "EXECUTED" and receipt:
            env["execution"] = {"executed": True, "payee_id": receipt["payee_id"],
                                "amount_pence": receipt["amount_pence"],
                                "new_balance_pence": receipt["new_balance_pence"]}
        elif status == "FAILED":
            env["execution"] = {"executed": False, "payee_id": None, "amount_pence": None, "new_balance_pence": None}
        if verdict == "HOLD":
            reasons = res.get("risk_reasons") or (hold["risk_reasons"] if hold else [])
            env["explanation"] = normalise_explanation(build_explanation(rule_ids, reasons, explainer))
        return env

    async def push(user_id, event_type, env):
        await hub.send(user_id, {"type": event_type, "hold_id": env.get("hold_id"), "data": env,
                                 "ts": datetime.datetime.fromtimestamp(clock(), datetime.timezone.utc).isoformat()})

    # ------------------------------------------------------------------ auth
    @app.post("/api/auth/signup", status_code=201)
    async def signup(body: SignupIn, request: Request, response: Response):
        throttle("signup:" + client_ip(request), 30, 3600)
        try:
            user = await run_in_threadpool(users.create_user, body.display_name, body.email, body.password)
        except EmailTaken:
            raise ApiError(409, "EMAIL_IN_USE", "An account with this email already exists.", {"email": "in_use"})
        account_id = ledger.open_account(user["id"], signup_balance_pence, signup_daily_limit_pence,
                                         default_known_payees)
        orch.register_trusted_contact(account_id, trusted_approver)
        set_cookie(response, users.create_session(user["id"]))
        audit.log_event("auth", "AUTH_SIGNUP", {"user_id": user["id"]})
        return {"profile": {"id": user["id"], "display_name": user["display_name"]}}

    @app.post("/api/auth/login")
    async def login(body: LoginIn, request: Request, response: Response):
        user_key = "login-user:" + body.email
        throttle("login-ip:" + client_ip(request), 60, 300)
        throttle(user_key, 8, 300)
        user = await run_in_threadpool(users.authenticate, body.email, body.password)
        if not user:
            audit.log_event("auth", "AUTH_LOGIN_FAILED", {})
            raise ApiError(401, "INVALID_CREDENTIALS", "Invalid email or password.")
        limiter.clear(user_key)
        users.delete_session(request.cookies.get(COOKIE))       # never reuse a session id across logins
        set_cookie(response, users.create_session(user["id"]))
        audit.log_event("auth", "AUTH_LOGIN_OK", {"user_id": user["id"]})
        return {"profile": {"id": user["id"], "display_name": user["display_name"]}}

    @app.post("/api/auth/logout", status_code=204)
    async def logout(request: Request):
        cookie = request.cookies.get(COOKIE)
        user = users.session_user(cookie)
        users.delete_session(cookie)
        if user:
            await hub.close_user(user["id"])
            audit.log_event("auth", "AUTH_LOGOUT", {"user_id": user["id"]})
        resp = Response(status_code=204)
        resp.delete_cookie(COOKIE, path="/", secure=secure, httponly=True, samesite="lax")
        return resp

    @app.get("/api/me")
    async def me(request: Request):
        user = require_user(request)
        profile = {"id": user["id"], "display_name": user["display_name"]}
        accounts = ledger.accounts_owned_by(user["id"])
        if accounts:
            a = accounts[0]
            limit, spent = ledger.daily_limit(a), ledger.daily_total(a)
            profile["account_summary"] = {"currency": "GBP", "balance_pence": ledger.balance(a),
                                          "daily_limit_pence": limit, "daily_spent_pence": spent,
                                          "daily_remaining_pence": max(0, limit - spent)}
        return {"profile": profile}

    # ------------------------------------------------------------------ analyse / propose / holds
    @app.post("/api/analyse")
    async def analyse(body: MessageIn, request: Request):
        user = require_user(request)
        throttle("analyse:" + user["id"], 30, 60)
        try:
            res = await run_in_threadpool(orch.analyse, sid_of(user), body.message)
        except Exception:
            raise ApiError(503, "SECURITY_SERVICE_UNAVAILABLE", "Security service unavailable.")
        reasons = _codes(res["reasons"])
        explanation = None
        if res["risk_band"] != "LOW":
            explanation = normalise_explanation(build_explanation([], reasons, explainer))
        return {"analysis": {"risk_band": res["risk_band"], "intent": res["intent"], "flags": _codes(res["flags"]),
                             "reasons": reasons, "explanation": explanation}}

    @app.post("/api/payments/propose")
    async def propose(body: MessageIn, request: Request):
        user = require_user(request)
        throttle("propose:" + user["id"], 20, 60)
        try:
            res = await run_in_threadpool(orch.handle_message, sid_of(user), body.message)
        except Exception:
            raise ApiError(503, "SECURITY_SERVICE_UNAVAILABLE", "Security service unavailable.")
        env = make_envelope(res)
        event = {"ALLOW": "payment.executed", "HOLD": "hold.created"}.get(env["verdict"], "payment.denied")
        await push(user["id"], event, env)
        return env

    def snapshot_envelope(hold_id, hold):
        status = "HOLD" if hold["status"] == "PENDING" else hold["status"]
        return make_envelope({"status": status, "proposal_id": hold_id, "rule_ids": hold["rule_ids"],
                              "reason": hold["reason"], "risk_band": hold["risk_band"],
                              "risk_reasons": hold["risk_reasons"], "receipt": hold["receipt"]})

    def owned_hold(hold_id, user):
        hold = orch.get_hold(hold_id) if _HOLD_RE.match(hold_id) else None
        if not hold or hold["owner"] != user["id"]:
            raise ApiError(404, "NOT_FOUND", "Not found.")        # same answer for 'missing' and 'not yours'
        return hold

    @app.get("/api/holds/{hold_id}")
    async def get_hold(hold_id: str, request: Request):
        user = require_user(request)
        return snapshot_envelope(hold_id, owned_hold(hold_id, user))

    @app.post("/api/holds/{hold_id}/decision")
    async def decide(hold_id: str, body: DecisionIn, request: Request):
        if trusted_ok(request):                                    # trusted-contact channel (Pi / ops UI)
            hold = orch.get_hold(hold_id) if _HOLD_RE.match(hold_id) else None
            if not hold:
                raise ApiError(404, "NOT_FOUND", "Not found.")
            if not body.approver:
                raise ApiError(422, "VALIDATION_ERROR", "Some fields are invalid.", {"approver": "required"})
            channel, approved_by = "trusted_contact", body.approver
        else:                                                      # customer channel (cookie session)
            user = require_user(request)
            hold = owned_hold(hold_id, user)
            channel, approved_by = "customer", user["id"]
        approval = {"approval_status": "APPROVED" if body.decision == "APPROVE" else "DECLINED",
                    "approved_by": approved_by, "proposal_id": hold_id}
        try:
            res = await run_in_threadpool(orch.resolve_hold, hold_id, approval, channel)
        except Exception:
            raise ApiError(503, "SECURITY_SERVICE_UNAVAILABLE", "Security service unavailable.")
        if res.get("reason") == "INVALID_APPROVAL":
            raise ApiError(403, "APPROVAL_NOT_PERMITTED", "This approver may not decide this hold.")
        env = make_envelope(res)
        event = {"EXECUTED": "payment.executed", "DECLINED": "hold.declined", "EXPIRED": "hold.expired",
                 "DENIED": "payment.denied", "FAILED": "payment.denied"}.get(res["status"], "hold.updated")
        await push(hold["owner"], event, env)
        return env

    # ------------------------------------------------------------------ live status (server -> browser only)
    @app.websocket("/api/ws")
    async def live(ws: WebSocket):
        origin = ws.headers.get("origin")
        host = ws.headers.get("host", "")
        scheme = "https" if ws.url.scheme == "wss" else "http"
        if origin and not origin_ok(origin, host, scheme):          # blocks cross-site WebSocket hijacking
            await ws.close(code=1008)
            return
        cookie = ws.cookies.get(COOKIE)
        user = users.session_user(cookie)
        await ws.accept()
        if not user:
            await ws.close(code=4401)
            return
        hub.add(user["id"], ws)
        try:
            await ws.send_json({"type": "connected"})
            while True:
                try:
                    msg = await asyncio.wait_for(ws.receive_text(), timeout=heartbeat_seconds)
                except asyncio.TimeoutError:
                    if not users.session_user(cookie):              # session expired / logged out elsewhere
                        await ws.close(code=4401)
                        break
                    await ws.send_json({"type": "heartbeat"})
                    continue
                if msg == "ping":
                    await ws.send_json({"type": "pong"})            # everything else from the client is ignored
        except WebSocketDisconnect:
            pass
        finally:
            hub.remove(user["id"], ws)

    # ------------------------------------------------------------------ ops (trusted key only)
    @app.get("/api/ops/audit/verify")
    async def ops_verify(request: Request):
        if not trusted_ok(request):
            raise ApiError(403, "FORBIDDEN", "Not permitted.")
        ok, bad = audit.verify_chain()
        return {"intact": ok, "first_bad_event": bad}

    @app.get("/api/ops/audit/session/{session_id}")
    async def ops_replay(session_id: str, request: Request):
        if not trusted_ok(request):
            raise ApiError(403, "FORBIDDEN", "Not permitted.")
        return audit.get_session_events(session_id)

    return app
