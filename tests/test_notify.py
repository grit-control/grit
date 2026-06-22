"""Approval webhook: fire-and-forget, Slack-compatible, never blocks calls."""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from grit.gateway import Gateway


def _result(text):
    return {"content": [{"type": "text", "text": text}], "isError": False}


class StubUpstream:
    name = "stub"

    def call_tool(self, name, arguments):
        return _result("ok")


def make_gateway(tmp_path, notify_url):
    cfg = {"audit_db": str(tmp_path / "g.db"),
           "policy": {"default_action": "deny", "rules": [
               {"id": "hold-pay", "tools": ["stub__pay"],
                "action": "approve", "reason": "payments need a human"}]},
           "risk": {"enabled": False}, "session_id": "n-session",
           "approval": {"timeout_seconds": 0, "poll_interval": 0.01,
                        "notify_url": notify_url}}
    g = Gateway(cfg)
    g.registry["stub__pay"] = (StubUpstream(),
                               {"name": "pay", "inputSchema": {"type": "object"}})
    return g


def test_webhook_receives_held_call(tmp_path):
    received = []
    got = threading.Event()

    class Hook(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            received.append(json.loads(self.rfile.read(length)))
            got.set()
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Hook)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}/hook"
        g = make_gateway(tmp_path, url)
        out = g._handle_call({"name": "stub__pay", "arguments": {"amount": 9}})
        assert out["isError"]  # timeout=0 -> not approved; that's fine
        assert got.wait(timeout=5), "webhook never arrived"
        text = received[0]["text"]
        assert "stub__pay" in text and "grit approve" in text
    finally:
        server.shutdown()


def test_unreachable_webhook_does_not_break_call(tmp_path):
    g = make_gateway(tmp_path, "http://127.0.0.1:1/nope")  # nothing listens
    out = g._handle_call({"name": "stub__pay", "arguments": {"amount": 9}})
    assert out["isError"] and "not approved" in out["content"][0]["text"]


def test_no_url_no_webhook(tmp_path):
    g = make_gateway(tmp_path, None)
    out = g._handle_call({"name": "stub__pay", "arguments": {"amount": 9}})
    assert out["isError"]  # held + instant timeout, no crash
