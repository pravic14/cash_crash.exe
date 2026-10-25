# BreakMyAgent

Secure AI payment guardian for HackNotts '26. A customer chats and pays. Independent guards can block. Only the policy kernel can let money move.

**Core rule:** LLMs can say no, never yes. No model output can approve a payment.

Spec: `BMA final (Hopefully).pdf` in this repo.

## Who pushes where

One repo. Stay inside your folder. The only shared edit is `shared/` — change a schema only after the whole team agrees, then everyone else pulls before they keep building.

| Folder | Owner | What lands here |
| --- | --- | --- |
| `server/` | **A — Security core** | Sanitiser, orchestrator, policy kernel, capability tokens, ledger, audit, scoring, websocket. `server/llm.py` is **C's** file. |
| `ml/` | **B — ML** | M1–M4, transaction generator, training, eval charts, overnight retrain. |
| `rag/` | **C — RAG + LLM** | Scam cards, bank-policy cards, retriever. Also owns `server/llm.py` (quarantine parser, explainer, offline fallbacks). |
| `web/` | **D — Frontend** | Customer app (`/app`), ops dashboard (`/ops`), Red Team page (`/redteam`), 2000s styling. |
| `pi/` | **D — Hardware** | Trusted-contact box. Pi is a WebSocket client only. |
| `tests/` | Shared | A owns `test_policy.py`. Attack and scam fixtures live here so anyone can add a case. |
| `shared/` | Frozen at kickoff | Intent, proposal, and audit-event schemas. Import these. Do not invent parallel types. |

With three people: C's RAG cards stay in `rag/`, the quarantined parser folds into A's `server/llm.py`, and the explainer stays with whoever owns the dashboard copy.

## Demo fixtures already frozen

- Customer: `acc-margaret` (Margaret, balance £4,200, daily limit £3,000)
- Usual payee: `payee-landlord` (rent, known)
- Mule (policy P6): `payee-mule`
- Scam card the explainer must cite: `rag/cards/safe-account.md` (`id: safe-account`)

## RAG and the two LLM roles

One pasted message goes through `Guardian.submit`: the sanitiser, then `assess_message` (retriever, parser, M1–M4), then `orchestrate` (policy). Only an ALLOW verdict debits the ledger, and only with a 30-second single-use token. The models and the LLM cannot approve a payment.

```powershell
$env:PYTHONPATH = "."
$env:LLM_MODE = "off"
python -m uvicorn server.main:app --host 127.0.0.1 --port 8000
```

Copy `.env.example` to `.env`. `LLM_MODE=api` calls Groq. The variables are `LLM_API_KEY` (or `GROQ_API_KEY`), `LLM_BASE_URL` (`https://api.groq.com/openai/v1`), and `LLM_MODEL`. `LLM_MODE=off` keeps the rule parser and the template. Neither role can approve a payment.

## Run imports from this directory

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:PYTHONPATH = "."
```
