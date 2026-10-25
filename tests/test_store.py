"""SQLite users, balances, session facts, and the chat transcript.

The JSON fixture stays at £4200. A second Guardian on the same file sees the debit.
The audit chain still has no customer text. The message table does, for the screen.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

os.environ["LLM_MODE"] = "off"

from server.guardian import Guardian
from server.ledger import load_accounts
from server.store import DEMO_EMAIL, DEMO_PASSWORD, Store
from shared.schemas import RiskBand
from tests.test_policy import NOW, _pay


class StoreTests(unittest.TestCase):
    def test_login_signup_and_a_wrong_password(self):
        store = Store(Path(tempfile.mkdtemp()) / "guardian.sqlite")
        margaret = store.login(DEMO_EMAIL, DEMO_PASSWORD)
        self.assertEqual(margaret["account_id"], "acc-margaret")
        self.assertIsNone(store.login(DEMO_EMAIL, "not-the-password"))
        created = store.signup("Ada Lovelace", "Ada@Example.com", "correct horse")
        self.assertTrue(created["account_id"].startswith("acc-"))
        self.assertEqual(store.login("ada@example.com", "correct horse")["display_name"], "Ada Lovelace")
        self.assertEqual(store.accounts[created["account_id"]]["balance"], 4200.0)
        with self.assertRaises(ValueError):
            store.signup("Ada again", "ada@example.com", "correct horse")

    def test_balance_context_and_hold_survive_a_new_guardian(self):
        folder = Path(tempfile.mkdtemp())
        path = folder / "guardian.sqlite"
        first = Guardian(audit_path=folder / "a.sqlite", store_path=path, cooloff_seconds=0)
        session_id = first.open_session("acc-margaret")
        allowed = first.apply(session_id, _pay(session_id), NOW)
        self.assertEqual(allowed["verdict"], "ALLOW")
        self.assertEqual(allowed["context"]["last_payee_id"], "payee-landlord")
        self.assertEqual(allowed["context"]["last_amount"], 750.0)

        held = _pay(
            session_id,
            proposal_id="held-payment",
            payee_id=None,
            amount=900,
            reference="",
            band=RiskBand.HIGH,
            final_risk=1.0,
            text_risk=0.8,
            rag_sim=0.8,
            cited_card_id="account-locked",
        )
        first.apply(session_id, held, NOW)

        second = Guardian(audit_path=folder / "b.sqlite", store_path=path, cooloff_seconds=0)
        resumed = second.open_session("acc-margaret", resume=True)
        self.assertEqual(resumed, session_id)
        self.assertEqual(second.ledger.balance("acc-margaret"), 3450.0)
        self.assertTrue(second.sessions.get(session_id).saw_payment)
        self.assertEqual(second.store.context(session_id)["cited_card_id"], "account-locked")
        self.assertEqual(second.store.context(session_id)["last_verdict"], "HOLD")
        self.assertIn("held-payment", second.holds)
        self.assertEqual(load_accounts()["acc-margaret"]["balance"], 4200.0)

        declined = second.resolve("held-payment", False, NOW)
        self.assertEqual(declined["verdict"], "DENY")
        third = Guardian(audit_path=folder / "c.sqlite", store_path=path, cooloff_seconds=0)
        self.assertNotIn("held-payment", third.holds)
        self.assertEqual(third.ledger.balance("acc-margaret"), 3450.0)

    def test_chat_text_is_kept_for_the_screen_and_left_out_of_the_audit(self):
        folder = Path(tempfile.mkdtemp())
        guardian = Guardian(audit_path=folder / "audit.sqlite", store_path=folder / "guardian.sqlite", cooloff_seconds=0)
        session_id = guardian.open_session("acc-margaret")
        text = "y" * 2001
        guardian.submit(session_id, text, NOW)
        saved = guardian.store.messages(session_id)
        self.assertEqual(saved[0]["role"], "you")
        self.assertEqual(saved[0]["body"], text)
        self.assertEqual(saved[1]["role"], "guardian")
        self.assertNotIn("yyyyyyyyyyyyyyyyyyyy", json.dumps(guardian.audit.replay(session_id)))
        facts = guardian.store.context(session_id)
        self.assertNotIn(text, json.dumps(facts))


if __name__ == "__main__":
    unittest.main()
