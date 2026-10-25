# ml/ — B, ML

Four models. None of them can approve a payment. They only emit scores the policy kernel may ignore.

## Files to add

| File | Role |
| --- | --- |
| `gen_transactions.py` | Synthetic 6-month history per customer: salary, rent, groceries, regular payees. Also labelled scenarios for fusion. |
| `train_m1.py` | Injection detector. TF-IDF (word 1–2 + char 3–5) → logistic regression. Public prompt-injection set plus ~150 hand-written examples. |
| `train_m2.py` | Scam-language detector. Same pipeline. UCI SMS Spam plus ~200 UK scripts (safe account, HMRC, parcel fee, romance, invoice) against genuine bank messages. Emit `p(scam)` and the top n-grams. |
| `train_m3.py` | Transaction anomaly. IsolationForest per customer on amount vs history, new payee, payee age, hour, velocity, percent of balance, first-time reference. |
| `train_fusion.py` | M4. Small logistic regression over text risk, txn risk, RAG similarity, urgency, authority claim. Interpretable weights. Output `final_risk` and band LOW / MEDIUM / HIGH. |
| `eval.py` | Precision, recall, F1, and the false-positive rate on legitimate payments. Ablation table from the spec (full system, no ML, no policy, LLM stubbed, no RAG). |
| `data/` | Raw and generated sets. Do not commit huge downloads if a script can refetch them. |
| `models/` | Trained artefacts. Git ignores everything here except this folder. |

## Scores you must publish

Write them onto `shared.schemas.PaymentProposal`:

- M1 + M2 + R1 (C's similarity) → `text_risk`
- M3 → `txn_risk`
- M4 → `final_risk` and `band`

Report the false-positive rate on legitimate payments. Banks care about friction. Retrain M1/M2 from red-team attempts overnight if the attempt log exists.

## First checkpoint

Generator plus an M2 and M3 baseline, before the LLM is wired. Policy-only must still be able to demo.

## Transaction generator

`gen_transactions.py` creates synthetic transaction data for five customers, including `acc-margaret`.
It generates 270 normal and 30 suspicious transactions for each customer.
Margaret's rent to `payee-landlord` stays near £750. Suspicious payees include `payee-mule`.
The transactions are saved to `data/transactions.csv`.
Run `python ml/gen_transactions.py` to generate the dataset and print a summary.

## Train and score

From the repo root, after `pip install -r requirements.txt`:

```powershell
python ml/gen_transactions.py
python ml/test_gen.py
python ml/train_m1.py
python ml/train_m2.py
python ml/train_m3.py
python ml/train_fusion.py
python ml/inference.py
```

`inference.score_payment(...)` returns `injection_p`, `scam_p`, `text_risk`, `txn_risk`, `rag_sim`, `final_risk`, and `band` (`LOW`, `MEDIUM`, `HIGH`). `server.assess.assess_message` passes `rag_sim` in from the retriever. The function does not call the LLM and does not approve a payment. Models are saved under `ml/models/`, which git ignores.
