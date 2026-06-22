"""End-to-end: real gateway subprocess + real demo MCP server subprocess,
spoken to over actual stdio MCP framing."""
import json
import os
import subprocess
import sys
import threading
import time

import pytest

from grit.audit import AuditLog

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMO = os.path.join(ROOT, "examples", "demo_server.py")

POLICY = {
    "default_action": "deny",
    "rules": [
        {"id": "no-delete", "tools": ["demo__delete_*"], "action": "deny",
         "reason": "destructive"},
        {"id": "big", "tools": ["demo__transfer_money"],
         "where": [{"path": "amount", "gt": 1000}], "action": "deny"},
        {"id": "mid", "tools": ["demo__transfer_money"],
         "where": [{"path": "amount", "gt": 50}], "action": "approve"},
        {"id": "rest", "tools": ["*"], "action": "allow"},
    ],
}


class GatewayClient:
    def __init__(self, config_path):
        env = dict(os.environ, PYTHONPATH=ROOT)
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "grit.cli", "serve",
             "--config", config_path],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, env=env, cwd=ROOT, bufsize=1)
        self._id = 0

    def request(self, method, params, timeout=30):
        self._id += 1
        self.proc.stdin.write(json.dumps(
            {"jsonrpc": "2.0", "id": self._id, "method": method,
             "params": params}) + "\n")
        self.proc.stdin.flush()
        deadline = time.time() + timeout
        while time.time() < deadline:
            line = self.proc.stdout.readline()
            if not line:
                raise RuntimeError("gateway closed stdout")
            msg = json.loads(line)
            if msg.get("id") == self._id:
                return msg
        raise TimeoutError(method)

    def call(self, tool, arguments):
        return self.request("tools/call",
                            {"name": tool, "arguments": arguments})["result"]

    def handshake(self):
        result = self.request("initialize", {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "pytest", "version": "1.0"}})["result"]
        self.proc.stdin.write(json.dumps(
            {"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
        self.proc.stdin.flush()
        return result

    def close(self):
        try:
            self.proc.stdin.close()
            self.proc.wait(timeout=10)
        except Exception:
            self.proc.kill()


@pytest.fixture
def setup(tmp_path):
    db = str(tmp_path / "grit.db")
    config = {
        "audit_db": db,
        "policy": POLICY,
        "approval": {"timeout_seconds": 8, "poll_interval": 0.1},
        "redaction": {"enabled": ["email", "api_key"]},
        "upstreams": [{"name": "demo", "command": sys.executable,
                       "args": [DEMO]}],
    }
    config_path = str(tmp_path / "grit.json")
    with open(config_path, "w") as fh:
        json.dump(config, fh)
    client = GatewayClient(config_path)
    info = client.handshake()
    assert info["serverInfo"]["name"] == "grit"
    yield client, db
    client.close()


def test_tools_are_prefixed_and_aggregated(setup):
    client, _ = setup
    tools = client.request("tools/list", {})["result"]["tools"]
    names = {t["name"] for t in tools}
    assert names == {"demo__search_docs", "demo__send_email",
                     "demo__transfer_money", "demo__delete_file"}
    assert all("inputSchema" in t for t in tools)


def test_allowed_call_is_redacted(setup):
    client, db = setup
    result = client.call("demo__search_docs", {"query": "contracts"})
    text = result["content"][0]["text"]
    assert not result.get("isError")
    assert "jane.doe@acme-corp.com" not in text
    assert "sk-test-" not in text
    assert "[REDACTED:email]" in text and "[REDACTED:api_key]" in text
    log = AuditLog(db).recent(5)
    assert log[0]["status"] == "executed" and log[0]["decision"] == "allow"


def test_denied_by_glob(setup):
    client, db = setup
    result = client.call("demo__delete_file", {"path": "/etc/passwd"})
    assert result["isError"]
    assert "blocked" in result["content"][0]["text"].lower()
    assert AuditLog(db).recent(5)[0]["status"] == "blocked"


def test_denied_by_argument(setup):
    client, _ = setup
    result = client.call("demo__transfer_money",
                         {"amount": 5000, "recipient": "X"})
    assert result["isError"]


def test_unknown_tool(setup):
    client, _ = setup
    result = client.call("demo__rm_rf", {})
    assert result["isError"] and "unknown tool" in result["content"][0]["text"]


def test_approval_timeout_blocks(setup, tmp_path):
    client, db = setup
    started = time.time()
    result = client.call("demo__transfer_money",
                         {"amount": 200, "recipient": "X"})
    assert result["isError"]
    assert "approval" in result["content"][0]["text"]
    assert time.time() - started >= 7  # actually waited for the timeout
    log = AuditLog(db).recent(5)
    assert log[0]["status"] == "approval_timeout"


def test_human_approval_unblocks_call(setup):
    client, db = setup
    audit = AuditLog(db)

    def approve_when_pending():
        deadline = time.time() + 6
        while time.time() < deadline:
            pending = audit.pending_approvals()
            if pending:
                audit.decide_approval(pending[0]["id"], "approved", "tester")
                return
            time.sleep(0.1)

    thread = threading.Thread(target=approve_when_pending)
    thread.start()
    result = client.call("demo__transfer_money",
                         {"amount": 200, "recipient": "Acme"})
    thread.join()
    assert not result.get("isError")
    assert "Transferred $200" in result["content"][0]["text"]
    log = audit.recent(5)
    assert log[0]["status"] == "executed_after_approval"


def test_human_denial_blocks_call(setup):
    client, db = setup
    audit = AuditLog(db)

    def deny_when_pending():
        deadline = time.time() + 6
        while time.time() < deadline:
            pending = audit.pending_approvals()
            if pending:
                audit.decide_approval(pending[0]["id"], "denied", "tester")
                return
            time.sleep(0.1)

    thread = threading.Thread(target=deny_when_pending)
    thread.start()
    result = client.call("demo__transfer_money",
                         {"amount": 300, "recipient": "Acme"})
    thread.join()
    assert result["isError"]
    assert audit.recent(5)[0]["status"] == "approval_denied"


def test_audit_chain_verifies_after_session(setup):
    client, db = setup
    client.call("demo__search_docs", {"query": "a"})
    client.call("demo__delete_file", {"path": "/x"})
    client.call("demo__send_email", {"to": "a@b.com", "subject": "s",
                                     "body": "b"})
    result = AuditLog(db).verify()
    assert result.ok and result.rows == 3
