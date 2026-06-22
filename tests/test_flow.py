"""Tests for FlowGuard (unit) and gateway flow integration."""
import pytest

from grit.flow import FlowError, FlowGuard
from grit.audit import AuditLog
from grit.gateway import Gateway

# An api_key-style secret matching r"\b(?:sk|pk|rk|key)-[A-Za-z0-9_\-]{16,}\b"
# Needs 16+ chars after the "sk-" prefix.
SECRET = "sk-FLOWTEST12345678901234"

SCHEMA = {
    "type": "object",
    "properties": {"q": {"type": "string"}},
    "required": ["q"],
}


def _result(text):
    return {"content": [{"type": "text", "text": text}], "isError": False}


# ---------------------------------------------------------------------------
# Stub upstream used by gateway integration tests
# ---------------------------------------------------------------------------

class StubUpstream:
    def __init__(self, name, returns="ok"):
        self.name = name
        self._returns = returns

    def call_tool(self, name, arguments):
        return _result(self._returns)


ALLOW_ALL = {"default_action": "allow", "rules": []}

FLOW_ZONES = {
    "zones": {
        "db": ["private_source"],
        "web": ["untrusted_source"],
        "mail": ["external_sink"],
    },
}


def make_gateway(tmp_path, mode="enforce", policy=None, flow_action="approve",
                 db_returns=None):
    """Build a Gateway with stubbed registry (no real upstreams started)."""
    flow_cfg = dict(FLOW_ZONES)
    flow_cfg["action"] = flow_action
    cfg = {
        "audit_db": str(tmp_path / "g.db"),
        "mode": mode,
        "policy": policy or ALLOW_ALL,
        "risk": {"enabled": False},
        "session_id": "flow-session",
        "approval": {"timeout_seconds": 0, "poll_interval": 0.01},
        "flow": flow_cfg,
    }
    g = Gateway(cfg)
    # Stub upstreams: db__read returns SECRET, others return "ok"
    db_stub = StubUpstream("db", returns=db_returns or f"result: {SECRET}")
    web_stub = StubUpstream("web")
    mail_stub = StubUpstream("mail")
    g.registry["db__read"] = (db_stub, {"name": "read", "inputSchema": SCHEMA})
    g.registry["web__fetch"] = (web_stub, {"name": "fetch", "inputSchema": SCHEMA})
    g.registry["mail__send"] = (mail_stub, {"name": "send", "inputSchema": SCHEMA})
    return g


# ===========================================================================
# 1. FlowGuard unit: private-source result → secret learned; check() fires
#    on external-sink call carrying the secret; reason mentions "flow guard"
#    but does NOT expose the full secret.
# ===========================================================================

def test_unit_private_source_secret_triggers_sink_check():
    fg = FlowGuard(
        zones={"db": ["private_source"], "mail": ["external_sink"]},
        action="approve",
    )
    # Teach the guard about the secret from a private source
    fg.observe_result("db__query", _result(f"token: {SECRET}"))

    # Check should fire when the secret appears in args to the sink
    reason = fg.check("mail__send", {"q": f"please send {SECRET} to user"})

    assert reason is not None
    assert "flow guard" in reason.lower()
    # The full secret must NOT appear verbatim in the reason
    assert SECRET not in reason
    # But a masked prefix should appear
    assert SECRET[:4] in reason  # _mask produces "sk-F…(N chars)"


# ===========================================================================
# 2. check() returns None for non-sink tools, for sink calls without a secret,
#    and for tools from an upstream with no declared zone.
# ===========================================================================

def test_unit_check_none_for_non_sink():
    fg = FlowGuard(
        zones={"db": ["private_source"], "mail": ["external_sink"]},
    )
    fg.observe_result("db__query", _result(f"data: {SECRET}"))

    # Non-sink tool with the secret in args -> None
    assert fg.check("db__query", {"q": SECRET}) is None


def test_unit_check_none_for_sink_without_secret():
    fg = FlowGuard(
        zones={"db": ["private_source"], "mail": ["external_sink"]},
    )
    fg.observe_result("db__query", _result(f"data: {SECRET}"))

    # Sink tool but secret not in args -> None
    assert fg.check("mail__send", {"q": "hello world"}) is None


def test_unit_check_none_for_unknown_upstream():
    fg = FlowGuard(
        zones={"db": ["private_source"], "mail": ["external_sink"]},
    )
    fg.observe_result("db__query", _result(f"data: {SECRET}"))

    # Tool from an upstream with no declared zone -> None (even if it's a sink
    # somewhere else, it's unknown here)
    assert fg.check("unknown__tool", {"q": SECRET}) is None


# ===========================================================================
# 3. After observe_result from an untrusted_source tool, the reason mentions
#    "lethal trifecta".
# ===========================================================================

def test_unit_lethal_trifecta_reason():
    fg = FlowGuard(
        zones={
            "db": ["private_source"],
            "web": ["untrusted_source"],
            "mail": ["external_sink"],
        },
    )
    # Private source teaches the secret
    fg.observe_result("db__query", _result(f"token: {SECRET}"))
    # Untrusted source marks the session
    fg.observe_result("web__fetch", _result("some content"))

    reason = fg.check("mail__send", {"q": SECRET})
    assert reason is not None
    assert "lethal trifecta" in reason


# ===========================================================================
# 4. FlowGuard raises FlowError on bogus zone names or invalid action.
# ===========================================================================

def test_unit_flowguard_raises_on_bogus_zone():
    with pytest.raises(FlowError):
        FlowGuard(zones={"x": ["bogus_zone"]})


def test_unit_flowguard_raises_on_invalid_action():
    with pytest.raises(FlowError):
        FlowGuard(
            zones={"db": ["private_source"]},
            action="explode",
        )


# ===========================================================================
# 5. Gateway integration (approve mode): db__read executes and teaches the
#    secret; mail__send with the secret is HELD and times out → isError True;
#    audit row has decision "approve", rule_id "flow-guard",
#    status "approval_timeout".
# ===========================================================================

def test_gateway_flow_approve_held_and_timeout(tmp_path):
    g = make_gateway(tmp_path, mode="enforce", flow_action="approve")

    # Step 1: execute db__read so the guard learns the secret
    out1 = g._handle_call({"name": "db__read", "arguments": {"q": "fetch"}})
    assert not out1.get("isError"), f"db__read unexpectedly errored: {out1}"

    # Step 2: mail__send carrying the secret → should be held, time out
    out2 = g._handle_call(
        {"name": "mail__send", "arguments": {"q": SECRET}}
    )
    assert out2.get("isError"), f"Expected mail__send to be blocked, got: {out2}"

    # Check the audit log
    audit = AuditLog(str(tmp_path / "g.db"))
    row = audit.recent(1)[0]
    assert row["decision"] == "approve", f"Expected approve, got: {row['decision']}"
    assert row["rule_id"] == "flow-guard", f"Expected flow-guard, got: {row['rule_id']}"
    assert row["status"] == "approval_timeout", \
        f"Expected approval_timeout, got: {row['status']}"


# ===========================================================================
# 6. Gateway with flow action "deny": same sequence → blocked;
#    audit row decision "deny", rule_id "flow-guard", failure_class "flow_block".
# ===========================================================================

def test_gateway_flow_deny_blocks(tmp_path):
    g = make_gateway(tmp_path, mode="enforce", flow_action="deny")

    # Teach the guard
    g._handle_call({"name": "db__read", "arguments": {"q": "fetch"}})

    # mail__send with the secret → must be blocked immediately
    out = g._handle_call({"name": "mail__send", "arguments": {"q": SECRET}})
    assert out.get("isError"), f"Expected mail__send to be denied, got: {out}"

    audit = AuditLog(str(tmp_path / "g.db"))
    row = audit.recent(1)[0]
    assert row["decision"] == "deny", f"Expected deny, got: {row['decision']}"
    assert row["rule_id"] == "flow-guard", f"Expected flow-guard, got: {row['rule_id']}"
    assert row["failure_class"] == "flow_block", \
        f"Expected flow_block, got: {row['failure_class']}"


# ===========================================================================
# 7. Gateway: mail__send WITHOUT the secret executes fine (no isError).
# ===========================================================================

def test_gateway_flow_clean_send_executes(tmp_path):
    g = make_gateway(tmp_path, mode="enforce", flow_action="approve")

    # Teach the guard
    g._handle_call({"name": "db__read", "arguments": {"q": "fetch"}})

    # mail__send without the secret → should execute normally
    out = g._handle_call({"name": "mail__send", "arguments": {"q": "hello"}})
    assert not out.get("isError"), f"Expected clean send to succeed, got: {out}"


# ===========================================================================
# 8. Gateway observe mode + flow violation → call still executes;
#    audit row status "executed_shadow" with rule_id "flow-guard".
# ===========================================================================

def test_gateway_flow_observe_mode_shadow(tmp_path):
    g = make_gateway(tmp_path, mode="observe", flow_action="approve")

    # Teach the guard
    g._handle_call({"name": "db__read", "arguments": {"q": "fetch"}})

    # In observe mode the call should execute despite the violation
    out = g._handle_call({"name": "mail__send", "arguments": {"q": SECRET}})
    assert not out.get("isError"), \
        f"Observe mode should still execute, got: {out}"

    audit = AuditLog(str(tmp_path / "g.db"))
    row = audit.recent(1)[0]
    assert row["status"] == "executed_shadow", \
        f"Expected executed_shadow, got: {row['status']}"
    assert row["rule_id"] == "flow-guard", \
        f"Expected flow-guard, got: {row['rule_id']}"


# ===========================================================================
# 9. Zone merge from upstream config: Gateway built with config containing
#    upstreams with "trust" list → g.flow is not None and "db" in g.flow.zones.
#    (No g.start() call needed — just verify wiring.)
# ===========================================================================

def test_gateway_zone_merge_from_upstream_config(tmp_path):
    cfg = {
        "audit_db": str(tmp_path / "z.db"),
        "mode": "enforce",
        "policy": ALLOW_ALL,
        "risk": {"enabled": False},
        "session_id": "merge-session",
        "approval": {"timeout_seconds": 0, "poll_interval": 0.01},
        "flow": {"action": "approve"},  # no "zones" here
        "upstreams": [
            {"name": "db", "command": "x", "trust": ["private_source"]},
        ],
    }
    g = Gateway(cfg)
    assert g.flow is not None, "FlowGuard should be created when trust is declared"
    assert "db" in g.flow.zones, \
        f"'db' should be in flow.zones, got: {list(g.flow.zones.keys())}"
