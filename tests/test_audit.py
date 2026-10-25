from server.audit import GENESIS_HASH, AuditLog


def test_events_stored_with_metadata_and_links():
    a = AuditLog()
    e1 = a.log_event("S1", "A", {"x": 1})
    e2 = a.log_event("S1", "B")
    assert e1["previous_hash"] == GENESIS_HASH and e2["previous_hash"] == e1["event_hash"]
    assert e1["timestamp"] and e1["session_id"] == "S1"


def test_valid_chain_passes():
    a = AuditLog()
    for i in range(5):
        a.log_event("S1", "E", {"i": i})
    assert a.verify_chain() == (True, None)


def test_modified_event_fails():
    a = AuditLog()
    for i in range(5):
        a.log_event("S1", "E", {"i": i})
    a._conn.execute("UPDATE events SET details='{\"i\":99}' WHERE seq=2")
    assert a.verify_chain() == (False, 2)


def test_deleted_event_fails():
    a = AuditLog()
    for i in range(5):
        a.log_event("S1", "E", {"i": i})
    a._conn.execute("DELETE FROM events WHERE seq=3")
    ok, bad = a.verify_chain()
    assert not ok


def test_session_replay_in_order():
    a = AuditLog()
    a.log_event("S1", "ONE")
    a.log_event("S2", "OTHER")
    a.log_event("S1", "TWO")
    assert [e["event_type"] for e in a.get_session_events("S1")] == ["ONE", "TWO"]


def test_secrets_are_redacted():
    a = AuditLog()
    e = a.log_event("S1", "X", {"sig": "abc", "token": {"claims": 1}, "ok": "fine"})
    assert e["details"]["sig"] == "[REDACTED]" and e["details"]["token"] == "[REDACTED]"
    assert e["details"]["ok"] == "fine"
