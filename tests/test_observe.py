"""Observe mode (monitor-before-enforce) and the events counter."""
import time

import pytest

from grit.audit import AuditLog
from grit.gateway import Gateway
from grit.recorder import Recorder


def _result(text):
    return {"content": [{"type": "text", "text": text}], "isError": False}


class StubUpstream:
    name = "stub"

    def call_tool(self, name, arguments):
        return _result("ok")


SCHEMA = {"type": "object", "properties": {"q": {"type": "string"}},
          "required": ["q"]}

DENY_ALL = {"default_action": "deny", "rules": [
    {"id": "no-pay", "tools": ["stub__pay"], "action": "deny",
     "reason": "payments are forbidden"},
    {"id": "hold-search", "tools": ["stub__search"], "action": "approve",
     "reason": "search needs approval"},
]}


def make_gateway(tmp_path, mode="observe", policy=None):
    cfg = {"audit_db": str(tmp_path / "g.db"), "mode": mode,
           "policy": policy or DENY_ALL,
           "risk": {"enabled": False}, "session_id": "obs-session",
           "approval": {"timeout_seconds": 0, "poll_interval": 0.01}}
    g = Gateway(cfg)
    for tool in ("pay", "search"):
        g.registry[f"stub__{tool}"] = (StubUpstream(),
                                       {"name": tool, "inputSchema": SCHEMA})
    return g


def test_observe_executes_policy_denied_call_as_shadow(tmp_path):
    g = make_gateway(tmp_path)
    out = g._handle_call({"name": "stub__pay", "arguments": {"q": "x"}})
    assert not out.get("isError")  # executed despite the deny rule
    row = AuditLog(str(tmp_path / "g.db")).recent(1)[0]
    assert row["status"] == "executed_shadow"
    assert row["decision"] == "deny" and row["rule_id"] == "no-pay"
    assert Recorder(str(tmp_path / "g.db")).trace("obs-session")[0][
        "status"] == "executed_shadow"


def test_observe_skips_approval_wait(tmp_path):
    g = make_gateway(tmp_path)
    started = time.time()
    out = g._handle_call({"name": "stub__search", "arguments": {"q": "x"}})
    assert not out.get("isError")
    assert time.time() - started < 2  # no approval poll loop
    row = AuditLog(str(tmp_path / "g.db")).recent(1)[0]
    assert row["status"] == "executed_shadow" and row["decision"] == "approve"
    # nothing left hanging in the approval queue
    assert AuditLog(str(tmp_path / "g.db")).pending_approvals() == []


def test_observe_kill_switch_still_blocks(tmp_path):
    g = make_gateway(tmp_path)
    audit = AuditLog(str(tmp_path / "g.db"))
    audit.set_paused(True, by="test")
    out = g._handle_call({"name": "stub__pay", "arguments": {"q": "x"}})
    assert out["isError"] and "PAUSED" in out["content"][0]["text"]


def test_observe_schema_validation_still_rejects(tmp_path):
    g = make_gateway(tmp_path)
    out = g._handle_call({"name": "stub__pay", "arguments": {}})
    assert out["isError"] and "missing required" in out["content"][0]["text"]


def test_enforce_mode_still_blocks(tmp_path):
    g = make_gateway(tmp_path, mode="enforce")
    out = g._handle_call({"name": "stub__pay", "arguments": {"q": "x"}})
    assert out["isError"]


def test_invalid_mode_rejected(tmp_path):
    with pytest.raises(ValueError):
        make_gateway(tmp_path, mode="yolo")


def test_gateway_advertises_mode(tmp_path):
    make_gateway(tmp_path, mode="observe")
    assert AuditLog(str(tmp_path / "g.db")).get_control("mode") == "observe"
    make_gateway(tmp_path, mode="enforce")
    assert AuditLog(str(tmp_path / "g.db")).get_control("mode") == "enforce"


def test_shadow_count_and_stats_nudge(tmp_path, capsys):
    from grit.cli import main as cli_main
    g = make_gateway(tmp_path)
    g._handle_call({"name": "stub__pay", "arguments": {"q": "x"}})
    db = str(tmp_path / "g.db")
    assert AuditLog(db).shadow_count() == 1
    assert cli_main(["stats", "--db", db]) == 0
    out = capsys.readouterr().out
    assert "OBSERVE" in out and "1 call would have been held" in out


def test_events_count_window(tmp_path):
    audit = AuditLog(str(tmp_path / "a.db"))
    now = time.time()
    audit.record("t", {}, "allow", None, None, "executed", ts=now - 8 * 86400)
    audit.record("t", {}, "allow", None, None, "executed", ts=now - 3600)
    audit.record("t", {}, "deny", None, None, "blocked", ts=now - 60)
    assert audit.events_count(since_hours=168.0) == 2


def test_events_histogram_buckets(tmp_path):
    audit = AuditLog(str(tmp_path / "a.db"))
    now = time.time()
    audit.record("t", {}, "allow", None, None, "executed", ts=now - 90)
    audit.record("t", {}, "allow", None, None, "executed", ts=now - 100)
    audit.record("t", {}, "allow", None, None, "executed", ts=now - 5 * 3600)
    audit.record("t", {}, "allow", None, None, "executed", ts=now - 30 * 3600)
    hist = audit.events_histogram(hours=24, now=now)
    assert len(hist) == 24
    assert hist[-1] == 2          # the freshest bucket
    assert hist[24 - 1 - 5] == 1  # five hours ago
    assert sum(hist) == 3         # the 30h-old event is outside the window
