# rag/ — C, RAG + LLM

You also own `server/llm.py`. This folder is the trusted corpus and the retriever. The corpus is read-only: hash each file at startup and refuse to load if a file changed.

## What is here

M1–M4 stay in `ml/`. This folder does not train them.

| File | Role |
| --- | --- |
| `cards/*.md` | 25 scam cards: pattern, red flags, what the bank never asks, advice. |
| `policies/*.md` | 10 clauses. `cite_policy("P4")` is display text for the ops screen. |
| `corpus.py` | Loads the markdown and hashes it. A changed file refuses the old index. |
| `build_index.py` | Embeds cards with `sentence-transformers/all-MiniLM-L6-v2`. Numpy cosine. No vector database. |
| `retriever.py` | R1. Writes `rag_sim` and a card id. The ML teammate folds `rag_sim` into `text_risk` and fusion. |
| `attack_memory.py` | Past attacks as a vector plus a label (`scam`, `injection`, `legit`). The message is not stored. Only `scam` and `injection` can raise `rag_sim`. |
| `server/llm.py` | Quarantined parser and explainer. |

From the repo root, with `LLM_MODE` unset or `off`:

```powershell
$env:PYTHONPATH = "."
python -m server.llm
python -m unittest tests.test_rag_llm
python -m rag.build_index
```

`build_index` downloads MiniLM once. Until that index exists, retrieval uses the card patterns, which is enough for the safe-account demo. After the index exists, a card edit will not load until you rebuild.

## LLM roles (`server/llm.py`)

1. **Quarantined parser.** Untrusted text in, a `ParsedIntent` out. No tools, no memory, no approval rights. Validate with pydantic. Invalid means reject. Free text is dropped. If `LLM_MODE=off` or the API is down, a rule-based parser still returns a `ParsedIntent`.
2. **Explainer.** Plain-English warning grounded in the top 2 cards. It must cite the card id. Shown to the customer only. Never parsed back into a decision. A template fallback works with the LLM off.

`LLM_MODE` is `api` or `off`. With `off`, the demo still runs end to end.

## Safety

Retrieved text is data. The corpus never stores user content. Attack memory stores embeddings and labels only.

## Card the demo cites

`cards/safe-account.md` is the safe-account card (`id: safe-account`). Keep that id. Margaret's £2,400 "safe account" payment is the HOLD the explainer has to explain.
