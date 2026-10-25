"""HTTP entry. Policy decides. The page only displays the result.

Routes:

    POST /auth/signup             {"display_name", "email", "password"}
    POST /auth/login              {"email", "password"}
    POST /session                 {"account_id": "acc-margaret"}
    GET  /sessions/{id}/messages
    POST /payments                {"session_id", "text"}
    POST /payments/{id}/decision  {"approve": true|false}
    GET  /audit/{session_id}
    GET  /scoring
    WS   /ws

Run from the repo root:

    python -m uvicorn server.main:app --host 127.0.0.1 --port 8000
"""

from __future__ import annotations

import hmac
import os
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from server.guardian import Guardian
from server.ws import hub

WEB = Path(__file__).resolve().parents[1] / "web"
STORE = Path(__file__).resolve().parent / "data" / "guardian.sqlite"

app = FastAPI(title="BreakMyAgent")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
guardian = Guardian(store_path=STORE)


class SessionIn(BaseModel):
    account_id: str = "acc-margaret"
    fresh: bool = False


class SignupIn(BaseModel):
    display_name: str = Field(min_length=1, max_length=40)
    email: str = Field(max_length=200)
    password: str = Field(min_length=8, max_length=128)


class LoginIn(BaseModel):
    email: str = Field(max_length=200)
    password: str = Field(max_length=128)


class PaymentIn(BaseModel):
    session_id: str
    text: str = Field(max_length=2000)


class DecisionIn(BaseModel):
    approve: bool
    channel: str = "customer"


@app.get("/health")
def health() -> dict:
    return {"ok": True}


@app.post("/auth/signup")
def signup(body: SignupIn) -> dict:
    try:
        return guardian.store.signup(body.display_name, body.email, body.password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None


@app.post("/auth/login")
def login(body: LoginIn) -> dict:
    found = guardian.store.login(body.email, body.password)
    if found is None:
        raise HTTPException(status_code=401, detail="Email or password is wrong.")
    return found


@app.post("/session")
def open_session(body: SessionIn) -> dict:
    try:
        session_id = guardian.open_session(body.account_id, resume=not body.fresh)
    except KeyError:
        raise HTTPException(status_code=404, detail="Unknown account") from None
    account = guardian.accounts[body.account_id]
    return {
        "session_id": session_id,
        "account_id": body.account_id,
        "customer_name": account["customer_name"],
        "balance": guardian.ledger.balance(body.account_id),
        "context": guardian.store.context(session_id),
    }


@app.get("/sessions/{session_id}/messages")
def messages(session_id: str) -> dict:
    try:
        guardian.sessions.get(session_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Unknown session") from None
    return {"messages": guardian.store.messages(session_id)}


@app.post("/payments")
async def pay(body: PaymentIn) -> dict:
    try:
        result = guardian.submit(body.session_id, body.text)
    except KeyError:
        raise HTTPException(status_code=404, detail="Unknown session") from None
    await hub.broadcast(_light(result))
    return result


@app.post("/payments/{proposal_id}/decision")
async def decide(proposal_id: str, body: DecisionIn, request: Request) -> dict:
    channel = body.channel
    if channel == "trusted_contact" and not _trusted(request):
        channel = "rejected"
    try:
        result = guardian.resolve(proposal_id, body.approve, channel=channel)
    except KeyError:
        raise HTTPException(status_code=404, detail="No held payment") from None
    await hub.broadcast(_light(result))
    return result


@app.get("/audit/{session_id}")
def audit(session_id: str) -> dict:
    return {"ok": guardian.audit.verify_chain(), "events": guardian.audit.replay(session_id)}


@app.get("/scoring")
def scoring() -> dict:
    return guardian.scoring.snapshot()


@app.websocket("/ws")
async def socket(socket: WebSocket) -> None:
    await hub.connect(socket)
    try:
        while True:
            await socket.receive_text()
    except WebSocketDisconnect:
        hub.disconnect(socket)


@app.get("/app")
@app.get("/login")
@app.get("/signup")
def page(request: Request) -> RedirectResponse:
    return RedirectResponse(url=f"/{request.url.path.strip('/')}.html")


app.mount("/", StaticFiles(directory=WEB, html=True), name="web")


def _trusted(request: Request) -> bool:
    expected = os.environ.get("TRUSTED_CONTACT_KEY") or os.environ.get("POLICY_SECRET") or "hacknotts-demo-policy"
    given = request.headers.get("x-trusted-contact", "")
    if len(given) != len(expected):
        return False
    return hmac.compare_digest(given, expected)


def _light(result: dict) -> dict:
    proposal = result.get("proposal") or {}
    return {
        "proposal_id": result.get("proposal_id"),
        "verdict": result.get("verdict"),
        "matched_policy": result.get("matched_policy"),
        "band": proposal.get("band"),
        "cited_card_id": proposal.get("cited_card_id"),
        "executed": result.get("executed"),
        "balance": result.get("balance"),
    }
