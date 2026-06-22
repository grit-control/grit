"""Flight recorder, replay, costs, drift, schema validation, taxonomy."""
import time

import pytest

from grit.audit import AuditLog
from grit.gateway import Gateway, validate_args
from grit.recorder import Recorder, ReplayServer


def _result(text):
    return {"content": [{"type": "text", "text": text}], "isError": False}


# ---- recorder / costs ----

def test_record_sessions_trace_costs(tmp_path):
    rec = Recorder(str(tmp_path / "r.db"))
    rec.record("s1", 1, "a__x", {"q": "hi"}, _result("answer one"), "executed")
    rec.record("s1", 2, "a__x", {"q": "yo"}, None, "blocked", "policy_block")
    rec.record("s2", 1, "b__y", {}, _result("zzz"), "executed")
    sessions = {s["session_id"]: s for s in rec.sessions()}
    assert sessions["s1"]["calls"] == 2 and sessions["s1"]["failures"] == 1
    trace = rec.trace("s1")
    assert [t["seq"] for t in trace] == [1, 2]
    assert trace[1]["failure_class"] == "policy_block"
    costs = rec.costs("s1", usd_per_1m_tokens=3.0)
    assert costs[0]["tool"] == "a__x" and costs[0]["calls"] == 2
    assert costs[0]["tokens_out"] > 0 and costs[0]["est_usd"] >= 0


# ---- replay ----

@pytest.fixture
def replayer(tmp_path):
    rec = Recorder(str(tmp_path / "r.db"))
    rec.record("s1", 1, "pay__transfer", {"amount": 10}, _result("sent 10"),
               "executed")
    rec.record("s1", 2, "pay__transfer", {"amount": 20}, _result("sent 20"),
               "executed")
    rec.record("s1", 3, "docs__search", {"q": "a"}, _result("found"),
               "executed")
    return rec


def _call(server, tool, args, mid=1):
    return server.handle_message({"jsonrpc": "2.0", "id": mid,
                                  "method": "tools/call",
                                  "params": {"name": tool,
                                             "arguments": args}})["result"]


def test_replay_exact_match_out_of_order(replayer):
    server = ReplayServer(replayer, "s1")
    # ask for the SECOND recording first -> exact match by args
    r = _call(server, "pay__transfer", {"amount": 20})
    assert r["content"][0]["text"] == "sent 20"
    r = _call(server, "pay__transfer", {"amount": 10})
    assert r["content"][0]["text"] == "sent 10"
    assert server.divergences == []


def test_replay_divergence_fallback(replayer):
    server = ReplayServer(replayer, "s1")
    r = _call(server, "pay__transfer", {"amount": 999})  # never recorded
    assert r["content"][0]["text"] == "sent 10"  # next unconsumed served
    assert len(server.divergences) == 1


def test_replay_strict_divergence_is_miss(replayer):
    server = ReplayServer(replayer, "s1", strict=True)
    r = _call(server, "pay__transfer", {"amount": 999})
    assert r["isError"] and "replay miss" in r["content"][0]["text"]


def test_replay_exhaustion_and_unknown_tool(replayer):
    server = ReplayServer(replayer, "s1")
    _call(server, "docs__search", {"q": "a"})
    r = _call(server, "docs__search", {"q": "a"})
    assert r["isError"]
    r = _call(server, "never__seen", {})
    assert r["isError"]


def test_replay_tools_list(replayer):
    server = ReplayServer(replayer, "s1")
    out = server.handle_message({"jsonrpc": "2.0", "id": 1,
                                 "method": "tools/list", "params": {}})
    names = {t["name"] for t in out["result"]["tools"]}
    assert names == {"pay__transfer", "docs__search"}


def test_replay_empty_session_rejected(tmp_path):
    rec = Recorder(str(tmp_path / "r.db"))
    with pytest.raises(ValueError):
        ReplayServer(rec, "ghost")


# ---- schema validation ----

SCHEMA = {"type": "object",
          "properties": {"amount": {"type": "number"},
                         "to": {"type": "string"}},
          "required": ["amount"]}


def test_load_config_accepts_utf8_bom(tmp_path):
    # Windows editors and PowerShell routinely write a BOM
    from grit.gateway import load_config
    cfg = tmp_path / "grit.json"
    cfg.write_bytes(b'\xef\xbb\xbf{"policy": {"default_action": "allow"}}')
    config = load_config(str(cfg))
    assert config["policy"]["default_action"] == "allow"


def test_validate_args():
    assert validate_args(SCHEMA, {"amount": 5})[0]
    ok, why = validate_args(SCHEMA, {})
    assert not ok and "amount" in why
    ok, why = validate_args(SCHEMA, {"amount": "lots"})
    assert not ok and "number" in why
    ok, why = validate_args(SCHEMA, {"amount": 5, "to": 7})
    assert not ok and "string" in why
    assert validate_args(None, {"anything": 1})[0]
    assert validate_args(SCHEMA, {"amount": True})[0] is False


def test_validate_args_integer_accepts_integral_floats():
    schema = {"type": "object", "properties": {"n": {"type": "integer"}}}
    assert validate_args(schema, {"n": 5})[0]
    assert validate_args(schema, {"n": 5.0})[0]   # JSON int often arrives as float
    ok, why = validate_args(schema, {"n": 5.5})
    assert not ok and "integer" in why
    ok, why = validate_args(schema, {"n": "5"})
    assert not ok and "integer" in why
    assert validate_args(schema, {"n": True})[0] is False


# ---- gateway-level taxonomy + flight, no subprocesses ----

class StubUpstream:
    name = "stub"

    def call_tool(self, name, arguments):
        return _result("ok")


def make_gateway(tmp_path):
    cfg = {"audit_db": str(tmp_path / "g.db"),
           "policy": {"default_action": "allow", "rules": []},
           "risk": {"enabled": False}, "session_id": "test-session"}
    g = Gateway(cfg)
    g.registry["stub__pay"] = (StubUpstream(),
                               {"name": "pay", "inputSchema": SCHEMA})
    return g


def test_gateway_schema_mismatch_class(tmp_path):
    g = make_gateway(tmp_path)
    out = g._handle_call({"name": "stub__pay", "arguments": {"to": "x"}})
    assert out["isError"] and "missing required" in out["content"][0]["text"]
    audit = AuditLog(cfg_db := str(tmp_path / "g.db"))
    assert audit.recent(1)[0]["failure_class"] == "schema_mismatch"
    rec = Recorder(cfg_db)
    assert rec.trace("test-session")[0]["failure_class"] == "schema_mismatch"


def test_gateway_records_flight_on_success(tmp_path):
    g = make_gateway(tmp_path)
    out = g._handle_call({"name": "stub__pay", "arguments": {"amount": 5}})
    assert not out.get("isError")
    trace = Recorder(str(tmp_path / "g.db")).trace("test-session")
    assert len(trace) == 1 and trace[0]["status"] == "executed"
    assert trace[0]["result"] is not None
    assert AuditLog(str(tmp_path / "g.db")).recent(1)[0]["failure_class"] is None


# ---- drift / failure breakdown ----

def test_failure_breakdown(tmp_path):
    a = AuditLog(str(tmp_path / "a.db"))
    a.record("t", {}, "deny", None, None, "blocked", failure_class="policy_block")
    a.record("t", {}, "deny", None, None, "blocked", failure_class="policy_block")
    a.record("t", {}, "allow", None, None, "executed")
    rows = a.failure_breakdown()
    assert rows[0]["failure_class"] == "policy_block" and rows[0]["count"] == 2


def test_drift_detection(tmp_path):
    a = AuditLog(str(tmp_path / "a.db"))
    now = time.time()
    h = 3600.0
    # previous window: healthy
    for i in range(10):
        a.record("api__x", {}, "allow", None, None, "executed", 100,
                 ts=now - 1.5 * h)
    # current window: failures spike + latency x3
    for i in range(10):
        fc = "upstream_error" if i < 5 else None
        a.record("api__x", {}, "allow", None, None,
                 "error" if fc else "executed", 300, ts=now - 0.5 * h,
                 failure_class=fc)
    report = a.drift(window_hours=1.0, now=now)
    entry = next(r for r in report if r["tool"] == "api__x")
    assert "failure rate up" in entry["flags"]
    assert "latency 2x up" in entry["flags"]


def test_drift_new_and_silent_tools(tmp_path):
    a = AuditLog(str(tmp_path / "a.db"))
    now = time.time()
    a.record("old__t", {}, "allow", None, None, "executed", ts=now - 5400)
    a.record("new__t", {}, "allow", None, None, "executed", ts=now - 600)
    flags = {r["tool"]: r["flags"] for r in a.drift(window_hours=1.0, now=now)}
    assert flags["old__t"] == ["tool went silent"]
    assert flags["new__t"] == ["new tool in this window"]
