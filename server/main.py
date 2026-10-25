"""HTTP entry. Policy decides. The page only displays the result.

Routes:

    POST /session                 {"account_id": "acc-margaret"}
    POST /payments                {"session_id", "text"}
    POST /payments/{id}/decision  {"approve": true|false}
    GET  /audit/{session_id}
    GET  /scoring
    WS   /ws

Run from the repo root:

    python -m uvicorn server.main:app --host 127.0.0.1 --port 8000
"""

from __future__ import annotations

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from server.guardian import Guardian
from server.ws import hub

app = FastAPI(title="BreakMyAgent")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
guardian = Guardian()


class SessionIn(BaseModel):
    account_id: str = "acc-margaret"


class PaymentIn(BaseModel):
    session_id: str
    text: str = Field(max_length=2000)


class DecisionIn(BaseModel):
    approve: bool


@app.get("/health")
def health() -> dict:
    return {"ok": True}


@app.post("/session")
def open_session(body: SessionIn) -> dict:
    try:
        session_id = guardian.open_session(body.account_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Unknown account") from None
    return {"session_id": session_id, "account_id": body.account_id}


@app.post("/payments")
async def pay(body: PaymentIn) -> dict:
    try:
        result = guardian.submit(body.session_id, body.text)
    except KeyError:
        raise HTTPException(status_code=404, detail="Unknown session") from None
    await hub.broadcast(_light(result))
    return result


@app.post("/payments/{proposal_id}/decision")
async def decide(proposal_id: str, body: DecisionIn) -> dict:
    try:
        result = guardian.resolve(proposal_id, body.approve)
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
