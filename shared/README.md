# shared/

Frozen at kickoff. Every other folder imports these types.

- `ParsedIntent` — only shape that leaves the quarantined LLM
- `PaymentProposal` — what the orchestrator hands to the guards and the policy kernel
- `AuditEvent` — one row of the hash chain
- `PolicyId` — P1–P9, shared with the ops dashboard so the cited rule matches the kernel

Do not add a second intent or proposal type in `server/`, `ml/`, or `web/`. If a field is missing, agree the change here first, push, and have everyone else pull.
