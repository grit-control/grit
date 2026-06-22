import sqlite3

import pytest

from grit.audit import AuditLog


@pytest.fixture
def audit(tmp_path):
    return AuditLog(str(tmp_path / "audit.db"))


def test_chain_intact(audit):
    for i in range(5):
        audit.record(f"tool{i}", {"i": i}, "allow", "r1", "ok", "executed", 10)
    result = audit.verify()
    assert result.ok and result.rows == 5


def test_empty_chain_ok(audit):
    assert audit.verify().ok


def test_tamper_content_detected(audit, tmp_path):
    audit.record("a", {}, "allow", None, None, "executed")
    audit.record("b", {}, "deny", "r", "no", "blocked")
    conn = sqlite3.connect(str(tmp_path / "audit.db"))
    conn.execute("UPDATE audit SET tool='HACKED' WHERE id=1")
    conn.commit()
    conn.close()
    result = audit.verify()
    assert not result.ok and result.broken_at == 1


def test_tamper_delete_detected(audit, tmp_path):
    for i in range(3):
        audit.record(f"t{i}", {}, "allow", None, None, "executed")
    conn = sqlite3.connect(str(tmp_path / "audit.db"))
    conn.execute("DELETE FROM audit WHERE id=2")
    conn.commit()
    conn.close()
    assert not audit.verify().ok


def test_approval_lifecycle(audit):
    aid = audit.create_approval("pay__transfer", {"amount": 200}, "needs human")
    assert audit.approval_status(aid) == "pending"
    assert audit.pending_approvals()[0]["id"] == aid
    assert audit.decide_approval(aid, "approved", "tester")
    assert audit.approval_status(aid) == "approved"
    # cannot re-decide
    assert not audit.decide_approval(aid, "denied")
    assert audit.pending_approvals() == []


def test_invalid_approval_status(audit):
    aid = audit.create_approval("t", {})
    with pytest.raises(ValueError):
        audit.decide_approval(aid, "maybe")
