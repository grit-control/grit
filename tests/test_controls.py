"""Kill switch, session budget guard, stuck-loop detection, export,
dashboard API."""
import json
import threading
import time
import urllib.request

import pytest

from grit.audit import AuditLog
from grit.cli import main as cli_main
from grit.dashboard import make_server
from grit.gateway import Gateway
from grit.recorder import Recorder
from grit.risk import STUCK_REPEATS, RiskEngine


def _result(text):
    return {"content": [{"type": "text", "text": text}], "isError": False}


class StubUpstream:
    name = "stub"

    def call_tool(self, name, arguments):
        return _result("ok")


SCHEMA = {"type": "object", "properties": {"q": {"type": "string"}}}


def make_gateway(tmp_path, **extra):
    cfg = {"audit_db": str(tmp_path / "g.db"),
           "policy": {"default_action": "allow", "rules": []},
           "risk": {"enabled": False}, "session_id": "test-session",
           "approval": {"timeout_seconds": 0, "poll_interval": 0.01},
           **extra}
    g = Gateway(cfg)
    g.registry["stub__search"] = (StubUpstream(),
                                  {"name": "search", "inputSchema": SCHEMA})
    return g


# ---- kill switch ----

def test_pause_refuses_everything_and_resume_restores(tmp_path):
    g = make_gateway(tmp_path)
    audit = AuditLog(str(tmp_path / "g.db"))
    audit.set_paused(True, by="test")
    out = g._handle_call({"name": "stub__search", "arguments": {"q": "x"}})
    assert out["isError"] and "PAUSED" in out["content"][0]["text"]
    last = audit.recent(1)[0]
    assert last["failure_class"] == "paused"
    assert last["rule_id"] == "kill-switch"
    # flight recorder saw it too
    assert Recorder(str(tmp_path / "g.db")).trace("test-session")[0][
        "failure_class"] == "paused"
    audit.set_paused(False, by="test")
    out = g._handle_call({"name": "stub__search", "arguments": {"q": "x"}})
    assert not out.get("isError")


def test_pause_cli_roundtrip(tmp_path, capsys):
    db = str(tmp_path / "c.db")
    AuditLog(db)  # create
    assert cli_main(["pause", "--db", db]) == 0
    assert AuditLog(db).is_paused()
    assert cli_main(["resume", "--db", db]) == 0
    assert not AuditLog(db).is_paused()


# ---- approval timeout race ----

def test_await_approval_honors_last_moment_decision(tmp_path):
    # human approves in the final poll window; the post-timeout "expired"
    # write must not clobber the human's real decision.
    g = make_gateway(tmp_path)
    audit = AuditLog(str(tmp_path / "g.db"))
    aid = audit.create_approval("stub__search", {"q": "x"}, "held")
    assert audit.decide_approval(aid, "approved", "human")
    # timeout_seconds=0 -> loop exits immediately, then attempts to expire
    assert g._await_approval(aid) == "approved"
    assert audit.approval_status(aid) == "approved"


def test_await_approval_times_out_when_undecided(tmp_path):
    g = make_gateway(tmp_path)
    audit = AuditLog(str(tmp_path / "g.db"))
    aid = audit.create_approval("stub__search", {"q": "x"}, "held")
    assert g._await_approval(aid) == "expired"
    assert audit.approval_status(aid) == "expired"


# ---- upstream-name / separator collision ----

def test_upstream_name_with_separator_rejected(tmp_path):
    with pytest.raises(ValueError, match="separator"):
        Gateway({"audit_db": str(tmp_path / "g.db"),
                 "policy": {"default_action": "allow", "rules": []},
                 "risk": {"enabled": False},
                 "upstreams": [{"name": "my__server", "command": "x"}]})


# ---- session budget guard ----

def test_budget_max_calls_deny(tmp_path):
    g = make_gateway(tmp_path, budget={"max_calls_per_session": 2,
                                       "action": "deny"})
    for _ in range(2):
        out = g._handle_call({"name": "stub__search", "arguments": {"q": "a"}})
        assert not out.get("isError")
    out = g._handle_call({"name": "stub__search", "arguments": {"q": "a"}})
    assert out["isError"] and "budget" in out["content"][0]["text"]
    last = AuditLog(str(tmp_path / "g.db")).recent(1)[0]
    assert last["failure_class"] == "budget_exceeded"
    assert last["rule_id"] == "session-budget"


def test_budget_max_tokens_holds_for_approval(tmp_path):
    g = make_gateway(tmp_path, budget={"max_tokens_per_session": 1,
                                       "action": "approve"})
    out = g._handle_call({"name": "stub__search", "arguments": {"q": "a"}})
    assert not out.get("isError")  # first call crosses the budget
    # second call exceeds -> held; approval times out instantly (timeout=0)
    out = g._handle_call({"name": "stub__search", "arguments": {"q": "a"}})
    assert out["isError"] and "not approved" in out["content"][0]["text"]
    last = AuditLog(str(tmp_path / "g.db")).recent(1)[0]
    assert last["rule_id"] == "session-budget"
    assert last["status"] == "approval_timeout"


def test_budget_invalid_action_rejected(tmp_path):
    with pytest.raises(ValueError):
        make_gateway(tmp_path, budget={"max_calls_per_session": 5,
                                       "action": "explode"})


def test_no_budget_means_unlimited(tmp_path):
    g = make_gateway(tmp_path)
    for _ in range(20):
        out = g._handle_call({"name": "stub__search", "arguments": {"q": "a"}})
        assert not out.get("isError")


# ---- stuck-loop risk factor ----

def test_stuck_loop_detected():
    eng = RiskEngine()
    args = {"q": "the same thing"}
    for _ in range(STUCK_REPEATS):
        eng.observe("docs__search", args)
    assessment = eng.assess("docs__search", args)
    assert any("stuck loop" in f for f in assessment.factors)


def test_no_stuck_loop_on_varied_args():
    eng = RiskEngine()
    for i in range(STUCK_REPEATS * 2):
        eng.observe("docs__search", {"q": f"query {i}"})
    assessment = eng.assess("docs__search", {"q": "query 1"})
    assert not any("stuck loop" in f for f in assessment.factors)


def test_stuck_loop_resets_after_different_call():
    eng = RiskEngine()
    args = {"q": "same"}
    for _ in range(STUCK_REPEATS):
        eng.observe("docs__search", args)
    eng.observe("docs__search", {"q": "different"})
    assessment = eng.assess("docs__search", args)
    assert not any("stuck loop" in f for f in assessment.factors)


# ---- export ----

def test_export_jsonl(tmp_path, capsys):
    db = str(tmp_path / "e.db")
    audit = AuditLog(db)
    audit.record("t__a", {"x": 1}, "allow", None, None, "executed", 5)
    Recorder(db).record("s1", 1, "t__a", {"x": 1}, _result("done"), "executed")
    out_file = tmp_path / "evidence.jsonl"
    assert cli_main(["export", "--db", db, "--out", str(out_file)]) == 0
    lines = [json.loads(l) for l in
             out_file.read_text(encoding="utf-8").splitlines()]
    assert lines[0]["type"] == "meta" and lines[0]["chain_ok"] is True
    types = {l["type"] for l in lines}
    assert types == {"meta", "audit", "recording"}


def test_export_flags_tampered_chain(tmp_path):
    db = str(tmp_path / "e.db")
    audit = AuditLog(db)
    audit.record("t__a", {}, "allow", None, None, "executed")
    with audit._connect() as conn:
        conn.execute("UPDATE audit SET arguments='{\"evil\":1}' WHERE id=1")
    out_file = tmp_path / "evidence.jsonl"
    assert cli_main(["export", "--db", db, "--out", str(out_file)]) == 2
    meta = json.loads(out_file.read_text(encoding="utf-8").splitlines()[0])
    assert meta["chain_ok"] is False


# ---- dashboard API ----

@pytest.fixture
def dash(tmp_path):
    db = str(tmp_path / "d.db")
    audit = AuditLog(db)
    audit.record("t__a", {"x": 1}, "allow", None, None, "executed", 5,
                 risk_score=10)
    audit.record("t__b", {}, "deny", "r1", "no", "blocked",
                 failure_class="policy_block")
    Recorder(db).record("s1", 1, "t__a", {"x": 1}, _result("done"), "executed")
    server = make_server(db, port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}", AuditLog(db)
    server.shutdown()


def _get_json(url):
    with urllib.request.urlopen(url, timeout=5) as resp:
        return json.loads(resp.read())


def _post_json(url, payload):
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read())


def test_dashboard_state_has_all_panels(dash):
    base, _ = dash
    state = _get_json(base + "/api/state")
    assert state["paused"] is False
    assert state["mode"] == "enforce" and state["shadow"] == 0
    assert state["events_7d"] == 2
    assert len(state["activity"]) == 24 and sum(state["activity"]) == 2
    assert state["stats"] and state["recent"]
    assert state["sessions"][0]["session_id"] == "s1"
    assert state["costs"][0]["tool"] == "t__a"
    assert state["failures"][0]["failure_class"] == "policy_block"
    # server clock for client-side relative times ("8s ago" column)
    assert abs(state["now"] - time.time()) < 60


def test_dashboard_trace_endpoint(dash):
    base, _ = dash
    trace = _get_json(base + "/api/trace?session=s1")["trace"]
    assert len(trace) == 1 and trace[0]["tool"] == "t__a"
    assert _get_json(base + "/api/trace?session=ghost")["trace"] == []


def test_dashboard_serves_page(dash):
    base, _ = dash
    with urllib.request.urlopen(base + "/", timeout=5) as resp:
        html = resp.read().decode("utf-8")
    assert "GRIT" in html and "PAUSE ALL AGENTS" in html
    assert "Activity" in html and "flight recorder" in html.lower()


def test_dashboard_pause_toggle(dash):
    base, audit = dash
    assert _post_json(base + "/api/pause", {"paused": True})["ok"]
    assert audit.is_paused()
    assert _get_json(base + "/api/state")["paused"] is True
    assert _post_json(base + "/api/pause", {"paused": False})["ok"]
    assert not audit.is_paused()
