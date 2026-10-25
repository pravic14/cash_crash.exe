from server.schemas import PaymentProposal


class Clock:
    def __init__(self, t=1_800_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


def make_proposal(**kw):
    base = dict(proposal_id="TXN001", session_id="S1", account_id="A001",
                payee_id="RENT001", amount_pence=75_000, reference="rent")
    base.update(kw)
    return PaymentProposal(**base)


def approval(proposal_id, who="trusted_contact_1", status="APPROVED"):
    return {"approval_status": status, "approved_by": who, "proposal_id": proposal_id}
