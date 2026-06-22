"""Three flagship CLI features: watch (live feed), check (policy/risk
dry-run) and incident (Markdown postmortem)."""
import json

from grit.audit import AuditLog
from grit.cli import _watch_poll, main as cli_main
from grit.recorder import Recorder


def _result(text):
    return {"content": [{"type": "text", "text": text}], "isError": False}


# ---- watch: recent_since cursor + poll step ----

def test_recent_since_orders_and_filters(tmp_path):
    audit = AuditLog(str(tmp_path / "w.db"))
    for i in range(3):
        audit.record(f"t__{i}", {"i": i}, "allow", None, None, "executed")
    rows = audit.recent_since(0)
    assert [r["tool"] for r in rows] == ["t__0", "t__1", "t__2"]
    assert rows[0]["id"] < rows[1]["id"] < rows[2]["id"]
    # only newer-than-cursor rows come back
    tail = audit.recent_since(rows[0]["id"])
    assert [r["tool"] for r in tail] == ["t__1", "t__2"]


def test_watch_poll_advances_cursor_without_repeats(tmp_path):
    audit = AuditLog(str(tmp_path / "w.db"))
    audit.record("t__a", {}, "allow", None, None, "executed")
    audit.record("t__b", {}, "deny", "r1", "no", "blocked")
    last_id, rows = _watch_poll(audit, 0)
    assert [r["tool"] for r in rows] == ["t__a", "t__b"]
    assert last_id == rows[-1]["id"]
    # polling again with the advanced cursor yields nothing (no repeats)
    last_id2, rows2 = _watch_poll(audit, last_id)
    assert rows2 == [] and last_id2 == last_id
    # a fresh row shows up on the next poll and only once
    audit.record("t__c", {}, "allow", None, None, "executed")
    last_id3, rows3 = _watch_poll(audit, last_id2)
    assert [r["tool"] for r in rows3] == ["t__c"]
    assert last_id3 > last_id2


# ---- check: policy/risk dry-run ----

CHECK_POLICY = {"default_action": "allow", "rules": [
    {"id": "no-deletes", "tools": ["demo__delete_*"], "action": "deny",
     "reason": "destructive ops forbidden"},
    {"id": "approve-transfers", "tools": ["demo__transfer_money"],
     "where": [{"path": "amount", "gt": 50}], "action": "approve",
     "reason": "transfers over $50 need approval"},
    {"id": "rest", "tools": ["*"], "action": "allow"},
]}


def _write_config(tmp_path, risk_enabled=False):
    db = tmp_path / "chk.db"
    AuditLog(str(db))  # create empty chain
    pol = tmp_path / "policies.json"
    pol.write_text(json.dumps(CHECK_POLICY), encoding="utf-8")
    cfg = tmp_path / "grit.json"
    cfg.write_text(json.dumps({
        "audit_db": str(db), "policies": "policies.json",
        "risk": {"enabled": risk_enabled, "approve_at": 50, "deny_at": 85},
    }), encoding="utf-8")
    return str(cfg), str(db)


def test_check_allow(tmp_path, capsys):
    cfg, _ = _write_config(tmp_path)
    code = cli_main(["check", "demo__search_docs", "--config", cfg])
    out = capsys.readouterr().out
    assert code == 0
    assert "ALLOW" in out and "rest" in out


def test_check_approve(tmp_path, capsys):
    cfg, _ = _write_config(tmp_path)
    code = cli_main(["check", "demo__transfer_money",
                     "--args", '{"amount": 100}', "--config", cfg])
    out = capsys.readouterr().out
    assert code == 3
    assert "APPROVE" in out and "approve-transfers" in out


def test_check_deny(tmp_path, capsys):
    cfg, _ = _write_config(tmp_path)
    code = cli_main(["check", "demo__delete_account", "--config", cfg])
    out = capsys.readouterr().out
    assert code == 2
    assert "DENY" in out and "no-deletes" in out


def test_check_invalid_args_json(tmp_path, capsys):
    cfg, _ = _write_config(tmp_path)
    code = cli_main(["check", "demo__search_docs",
                     "--args", "{not json}", "--config", cfg])
    out = capsys.readouterr().out
    assert code == 1 and "invalid --args JSON" in out


def test_check_does_not_write_audit(tmp_path):
    """The dry-run guarantee: nothing lands in the audit table."""
    cfg, db = _write_config(tmp_path, risk_enabled=True)
    before = len(AuditLog(db).recent(1000))
    cli_main(["check", "demo__transfer_money",
              "--args", '{"amount": 999}', "--config", cfg])
    cli_main(["check", "demo__delete_account", "--config", cfg])
    cli_main(["check", "demo__search_docs", "--config", cfg])
    assert len(AuditLog(db).recent(1000)) == before == 0


# ---- incident: Markdown postmortem ----

def _seed_session(tmp_path, session="s1"):
    db = str(tmp_path / "i.db")
    audit = AuditLog(db)
    rec = Recorder(db)
    long_args = {"note": "x" * 200}
    audit.record("t__run", long_args, "allow", None, None, "executed", 12)
    rec.record(session, 1, "t__run", long_args, _result("done"),
               "executed", latency_ms=12)
    audit.record("t__pay", {"amount": 9}, "deny", "no-pay", "blocked",
                 "blocked", failure_class="policy_block")
    rec.record(session, 2, "t__pay", {"amount": 9}, None, "blocked",
               failure_class="policy_block")
    return db


def test_incident_report_sections_and_truncation(tmp_path, capsys):
    db = _seed_session(tmp_path)
    out_file = tmp_path / "report.md"
    code = cli_main(["incident", "s1", "--db", db, "--out", str(out_file)])
    assert code == 0
    assert "report written to" in capsys.readouterr().out
    report = out_file.read_text(encoding="utf-8")
    for section in ("# GRIT incident report — session s1", "## Summary",
                    "## Audit chain", "## Failure breakdown",
                    "## Call timeline", "## Costliest tools"):
        assert section in report
    assert "intact" in report
    assert "policy_block" in report
    # arguments truncated to 80 chars with an ellipsis
    assert "..." in report
    assert "x" * 200 not in report


def test_incident_unknown_session(tmp_path, capsys):
    db = _seed_session(tmp_path)
    code = cli_main(["incident", "ghost", "--db", db])
    out = capsys.readouterr().out
    assert code == 1 and "no recordings for session 'ghost'" in out


def test_incident_tampered_chain_still_writes_report(tmp_path, capsys):
    db = _seed_session(tmp_path)
    audit = AuditLog(db)
    with audit._connect() as conn:
        conn.execute("UPDATE audit SET arguments='{\"evil\":1}' WHERE id=1")
    out_file = tmp_path / "report.md"
    code = cli_main(["incident", "s1", "--db", db, "--out", str(out_file)])
    assert code == 2
    assert "TAMPERED" in out_file.read_text(encoding="utf-8")
