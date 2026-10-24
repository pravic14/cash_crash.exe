# rag/ — C, RAG + LLM

You also own `server/llm.py`. This folder is the trusted corpus and the retriever. The corpus is read-only: hash each file at startup and refuse to load if a file changed.

## Files to add

| File | Role |
| --- | --- |
| `cards/*.md` | About 25 short scam cards: pattern, red flags, what the bank never asks, advice. |
| `policies/*.md` | About 10 bank-policy clauses. The dashboard cites the one that caused a HOLD or DENY. |
| `build_index.py` | Embed with `sentence-transformers/all-MiniLM-L6-v2` locally. Numpy cosine. No vector database. |
| `retriever.py` | R1. Similarity of incoming text to known scam cards and past attacks. That similarity feeds `text_risk`. |
| `server/llm.py` | Two bounded roles only. See below. |

## LLM roles (`server/llm.py`)

1. **Quarantined parser.** Untrusted text in, a `ParsedIntent` out. No tools, no memory, no approval rights. Validate with pydantic. Invalid means reject. Free text is dropped. If `LLM_MODE=off` or the API is down, a rule-based parser still returns a `ParsedIntent`.
2. **Explainer.** Plain-English warning grounded in the top 2 cards. It must cite the card id. Shown to the customer only. Never parsed back into a decision. A template fallback works with the LLM off.

`LLM_MODE` is `api` or `off`. With `off`, the demo still runs end to end.

## Safety

Retrieved text is data. The corpus never stores user content. Attack memory stores embeddings and labels only.

## Card the demo cites

`cards/safe-account.md` is the safe-account card (`id: safe-account`). Keep that id. Margaret's £2,400 "safe account" payment is the HOLD the explainer has to explain.
