"""The GRIT gateway: a stdio MCP server that proxies upstream MCP servers
and adds visibility, policies, approvals, risk scoring, redaction and audit.

Config (grit.json):
{
  "audit_db": "grit.db",
  "mode": "enforce",                      // "observe": log decisions, block nothing
                                          // (kill switch still blocks; schema
                                          // validation still rejects)
  "policies": "policies.json",            // or inline: "policy": {...}
  "approval": {"timeout_seconds": 120, "poll_interval": 0.5,
               "notify_url": "https://hooks.slack.com/services/..."},  // optional
  "redaction": {"enabled": ["email", "api_key"], "custom": {}},
  "risk": {"enabled": true, "approve_at": 50, "deny_at": 85},
  "budget": {"max_calls_per_session": 500,
             "max_tokens_per_session": 2000000, "action": "approve"},
  "upstreams": [
    {"name": "demo", "command": "python3", "args": ["examples/demo_server.py"]}
  ]
}
Relative paths are resolved against the config file's directory.

Decision pipeline for every tools/call:
  0. kill switch            -- a paused gateway refuses everything
  1. schema validation      -- malformed/hallucinated calls die early
  2. policy.evaluate()      -- explicit rules always win (first match)
  3. risk.assess()          -- if the policy says ALLOW, the risk engine can
                               still escalate to APPROVE (>= approve_at) or
                               DENY (>= deny_at)
  4. flow.check()           -- a verbatim secret from a private source headed
                               to an external sink escalates, even past ALLOW
  5. session budget guard   -- runaway loops get held or blocked
  6. approval wait          -- APPROVE holds the call for a human
  7. execute + redact + audit (with risk score); baselines learn from
     executed calls only; every call lands in the flight recorder
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
import urllib.request
from typing import Optional, TextIO

from . import __version__
from .audit import AuditLog
from .flow import FlowGuard
from .jsonrpc import (METHOD_NOT_FOUND, error_response, read_message,
                      response, write_message)
from .policy import ALLOW, APPROVE, DENY, Decision, PolicyEngine
from .recorder import Recorder
from .redact import Redactor
from .risk import RiskAssessment, RiskEngine
from .upstream import PROTOCOL_VERSION, UpstreamError, UpstreamServer

SEPARATOR = "__"
RISK_RULE_ID = "risk-engine"
BUDGET_RULE_ID = "session-budget"
KILL_SWITCH_RULE_ID = "kill-switch"
FLOW_RULE_ID = "flow-guard"

_FCLASS_BY_RULE = {RISK_RULE_ID: "risk_block",
                   BUDGET_RULE_ID: "budget_exceeded",
                   KILL_SWITCH_RULE_ID: "paused",
                   FLOW_RULE_ID: "flow_block"}

_TYPE_MAP = {"string": str, "boolean": bool, "object": dict, "array": list}


def validate_args(schema: Optional[dict], args: dict) -> tuple[bool, str]:
    """Minimal JSON-schema check: catches hallucinated/malformed tool calls
    before they hit a live system, and tells the agent exactly what to fix."""
    if not schema or schema.get("type") not in (None, "object"):
        return True, ""
    for req in schema.get("required", []):
        if req not in args:
            return False, f"missing required argument '{req}'"
    for key, value in args.items():
        sub = schema.get("properties", {}).get(key)
        if not isinstance(sub, dict):
            continue
        expected = sub.get("type")
        if expected == "number":
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                return False, f"argument '{key}' must be a number"
        elif expected == "integer":
            # JSON has no int/float distinction; a client serializing through
            # JS/TS routinely sends 5.0 for an integer field. Accept integral
            # floats, still reject 5.5 and booleans.
            if isinstance(value, bool) or not (
                    isinstance(value, int)
                    or (isinstance(value, float) and value.is_integer())):
                return False, f"argument '{key}' must be an integer"
        elif expected in _TYPE_MAP and not isinstance(value, _TYPE_MAP[expected]):
            return False, f"argument '{key}' must be of type {expected}"
    return True, ""


def _log(msg: str) -> None:
    print(f"[grit] {msg}", file=sys.stderr, flush=True)


def load_config(config_path: str) -> dict:
    # utf-8-sig: Windows editors and PowerShell routinely write a BOM
    with open(config_path, "r", encoding="utf-8-sig") as fh:
        config = json.load(fh)
    base = os.path.dirname(os.path.abspath(config_path))

    def resolve(path: str) -> str:
        return path if os.path.isabs(path) else os.path.join(base, path)

    config["audit_db"] = resolve(config.get("audit_db", "grit.db"))
    if "policy" not in config:
        with open(resolve(config.get("policies", "policies.json")),
                  "r", encoding="utf-8-sig") as fh:
            config["policy"] = json.load(fh)
    return config


def tool_text_result(text: str, is_error: bool = False) -> dict:
    return {"content": [{"type": "text", "text": text}], "isError": is_error}


class Gateway:
    def __init__(self, config: dict):
        self.config = config
        # observe mode: decisions are computed and logged but nothing is
        # blocked — the WAF/EDR-style "monitor before enforce" adoption path
        self.mode = config.get("mode", "enforce")
        if self.mode not in ("enforce", "observe"):
            raise ValueError(f"mode must be 'enforce' or 'observe', "
                             f"got {self.mode!r}")
        # tools are exposed as <name>__<tool>; a '__' inside an upstream name
        # would make flow/zone resolution split on the wrong boundary and
        # silently mis-route trust zones, so reject it loudly at startup.
        for _u in config.get("upstreams", []):
            _name = _u.get("name", "")
            if not _name or SEPARATOR in _name:
                raise ValueError(
                    f"invalid upstream name {_name!r}: must be non-empty and "
                    f"must not contain the reserved separator {SEPARATOR!r}")
        self.policy = PolicyEngine(config["policy"])
        self.audit = AuditLog(config["audit_db"])
        # advertise the running mode so stats/dashboard can show it and
        # nudge observe-mode users toward enforce — the activation metric
        self.audit.set_control("mode", self.mode, by="gateway")
        red = config.get("redaction", {})
        self.redactor = Redactor(red.get("enabled"), red.get("custom"))
        approval = config.get("approval", {})
        self.approval_timeout = float(approval.get("timeout_seconds", 120))
        self.poll_interval = float(approval.get("poll_interval", 0.5))
        # Slack-compatible webhook: the team hears about held calls where
        # they already live, instead of watching a dashboard
        self.notify_url = approval.get("notify_url")
        risk_cfg = config.get("risk", {})
        self.risk_enabled = bool(risk_cfg.get("enabled", True))
        self.risk_approve_at = int(risk_cfg.get("approve_at", 50))
        self.risk_deny_at = int(risk_cfg.get("deny_at", 85))
        self.risk = RiskEngine(audit=self.audit) if self.risk_enabled else None
        # flow guard: trust zones per upstream (private_source /
        # untrusted_source / external_sink) -> verbatim-secret egress control
        flow_cfg = config.get("flow") or {}
        zones = dict(flow_cfg.get("zones") or {})
        for u in config.get("upstreams", []):
            if u.get("trust"):
                zones[u["name"]] = u["trust"]
        self.flow = (FlowGuard(zones, flow_cfg.get("action", "approve"))
                     if zones and flow_cfg.get("enabled", True) else None)
        self.recorder = Recorder(config["audit_db"])
        self.session_id = config.get("session_id") or \
            f"s-{time.strftime('%Y%m%d-%H%M%S')}-{os.getpid()}"
        self._seq = 0
        # session budget guard: stops runaway loops from burning money
        budget = config.get("budget") or {}
        self.budget_max_calls = budget.get("max_calls_per_session")
        self.budget_max_tokens = budget.get("max_tokens_per_session")
        self.budget_action = budget.get("action", "approve")
        if self.budget_action not in (APPROVE, DENY):
            raise ValueError(f"budget.action must be 'approve' or 'deny', "
                             f"got {self.budget_action!r}")
        self._session_tokens = 0
        self.upstreams: list[UpstreamServer] = [
            UpstreamServer(u["name"], u["command"], u.get("args"),
                           u.get("env"), float(u.get("timeout", 30)))
            for u in config.get("upstreams", [])
        ]
        self.registry: dict[str, tuple[UpstreamServer, dict]] = {}

    # ---- lifecycle ----

    def start(self) -> None:
        for up in self.upstreams:
            tools = up.start()
            for tool in tools:
                prefixed = f"{up.name}{SEPARATOR}{tool['name']}"
                self.registry[prefixed] = (up, tool)
            _log(f"upstream '{up.name}': {len(tools)} tools")
        _log(f"gateway ready: {len(self.registry)} tools, "
             f"risk engine {'on' if self.risk_enabled else 'off'}")

    def stop(self) -> None:
        for up in self.upstreams:
            up.stop()

    # ---- MCP server over stdio ----

    def serve_stdio(self, stdin: Optional[TextIO] = None,
                    stdout: Optional[TextIO] = None) -> None:
        stdin = stdin or sys.stdin
        stdout = stdout or sys.stdout
        while True:
            msg = read_message(stdin)
            if msg is None:
                break
            reply = self.handle_message(msg)
            if reply is not None:
                write_message(stdout, reply)
        self.stop()

    def handle_message(self, msg: dict) -> Optional[dict]:
        method = msg.get("method")
        req_id = msg.get("id")
        if method is None or method.startswith("notifications/"):
            return None
        try:
            if method == "initialize":
                return response(req_id, {
                    "protocolVersion": (msg.get("params") or {}).get(
                        "protocolVersion", PROTOCOL_VERSION),
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "grit", "version": __version__},
                })
            if method == "ping":
                return response(req_id, {})
            if method == "tools/list":
                return response(req_id, {"tools": self._list_tools()})
            if method == "tools/call":
                return response(req_id, self._handle_call(msg.get("params") or {}))
            return error_response(req_id, METHOD_NOT_FOUND,
                                  f"method not supported by grit: {method}")
        except Exception as exc:  # never crash the loop
            _log(f"internal error on {method}: {exc}")
            return response(req_id, tool_text_result(
                f"GRIT internal error: {exc}", is_error=True)) \
                if method == "tools/call" else \
                error_response(req_id, -32603, f"internal error: {exc}")

    def _list_tools(self) -> list[dict]:
        tools = []
        for prefixed, (up, tool) in self.registry.items():
            entry = dict(tool)
            entry["name"] = prefixed
            tools.append(entry)
        return tools

    # ---- the core: policy + risk enforced tool call ----

    def _flight(self, tool: str, arguments: dict, result: Optional[dict],
                status: str, failure_class: Optional[str],
                latency_ms: Optional[int] = None) -> None:
        self._seq += 1
        tokens_in, tokens_out = self.recorder.record(
            self.session_id, self._seq, tool, arguments, result, status,
            failure_class, latency_ms)
        self._session_tokens += tokens_in + tokens_out

    def _budget_breach(self) -> Optional[str]:
        """Reason string if the NEXT call would exceed the session budget."""
        if self.budget_max_calls is not None and \
                self._seq + 1 > self.budget_max_calls:
            return (f"session budget exceeded: call #{self._seq + 1} over "
                    f"the {self.budget_max_calls}-call limit")
        if self.budget_max_tokens is not None and \
                self._session_tokens > self.budget_max_tokens:
            return (f"session budget exceeded: ~{self._session_tokens} tokens "
                    f"of tool traffic over the {self.budget_max_tokens} limit")
        return None

    def _handle_call(self, params: dict) -> dict:
        tool: str = params.get("name", "")
        arguments: dict = params.get("arguments") or {}

        # the kill switch outranks everything: a human said STOP
        if self.audit.is_paused():
            self.audit.record(tool, arguments, DENY, KILL_SWITCH_RULE_ID,
                              "gateway paused by operator", "blocked",
                              failure_class="paused")
            self._flight(tool, arguments, None, "blocked", "paused")
            _log(f"PAUSED — refused {tool}")
            return tool_text_result(
                "GRIT: the gateway is PAUSED by a human operator. "
                "No tool calls will execute until it is resumed "
                "(grit resume). Stop and report this to the user.", True)

        if tool not in self.registry:
            self.audit.record(tool, arguments, DENY, None, "unknown tool",
                              "blocked", failure_class="unknown_tool")
            self._flight(tool, arguments, None, "blocked", "unknown_tool")
            return tool_text_result(f"GRIT: unknown tool '{tool}'", True)

        # hallucinated/malformed calls die here, with a fix-it message
        upstream_def = self.registry[tool][1]
        ok, why = validate_args(upstream_def.get("inputSchema"), arguments)
        if not ok:
            self.audit.record(tool, arguments, DENY, None, why, "blocked",
                              failure_class="schema_mismatch")
            self._flight(tool, arguments, None, "blocked", "schema_mismatch")
            _log(f"SCHEMA MISMATCH {tool}: {why}")
            return tool_text_result(
                f"GRIT: invalid arguments for '{tool}': {why}. "
                f"Fix the arguments and retry.", True)

        decision = self.policy.evaluate(tool, arguments)
        risk: Optional[RiskAssessment] = (
            self.risk.assess(tool, arguments) if self.risk else None)
        risk_score = risk.score if risk else None

        # risk engine may escalate calls that static policy allowed
        if decision.action == ALLOW and risk:
            if risk.score >= self.risk_deny_at:
                decision = Decision(DENY, RISK_RULE_ID, risk.summary())
            elif risk.score >= self.risk_approve_at:
                decision = Decision(APPROVE, RISK_RULE_ID, risk.summary())

        # flow guard: a verbatim secret from a private source headed to an
        # external sink escalates — even past a policy ALLOW, and it
        # overrides an APPROVE reason so the human sees the scary part
        if self.flow and decision.action in (ALLOW, APPROVE):
            violation = self.flow.check(tool, arguments)
            if violation:
                action = DENY if self.flow.action == DENY else APPROVE
                decision = Decision(action, FLOW_RULE_ID, violation)

        # session budget guard: runaway loops stop costing money here
        if decision.action == ALLOW and \
                (self.budget_max_calls is not None or
                 self.budget_max_tokens is not None):
            breach = self._budget_breach()
            if breach:
                decision = Decision(self.budget_action, BUDGET_RULE_ID, breach)

        # observe mode: log what WOULD have happened, then execute anyway.
        # After a week the audit answers "what would GRIT have stopped?" —
        # flipping to enforce becomes an informed decision, not a leap.
        shadow = self.mode == "observe" and decision.action != ALLOW
        if shadow:
            _log(f"OBSERVE: would {decision.action} {tool} ({decision.reason})")

        if not shadow and decision.action == DENY:
            fclass = _FCLASS_BY_RULE.get(decision.rule_id, "policy_block")
            self.audit.record(tool, arguments, DENY, decision.rule_id,
                              decision.reason, "blocked",
                              risk_score=risk_score, failure_class=fclass)
            self._flight(tool, arguments, None, "blocked", fclass)
            _log(f"BLOCKED {tool} ({decision.reason})")
            return tool_text_result(
                f"GRIT blocked this call. Reason: {decision.reason}", True)

        if not shadow and decision.action == APPROVE:
            approval_id = self.audit.create_approval(
                tool, arguments, decision.reason, risk_score=risk_score)
            _log(f"HELD {tool} for human approval (id={approval_id}, "
                 f"risk={risk_score}); run: grit approve {approval_id}")
            self._notify_approval(approval_id, tool, arguments,
                                  risk_score, decision.reason)
            status = self._await_approval(approval_id)
            if status != "approved":
                final = "approval_denied" if status == "denied" else "approval_timeout"
                self.audit.record(tool, arguments, APPROVE, decision.rule_id,
                                  decision.reason, final, risk_score=risk_score,
                                  failure_class=final)
                self._flight(tool, arguments, None, final, final)
                _log(f"NOT APPROVED {tool} ({final})")
                return tool_text_result(
                    f"GRIT: call was held for human approval and was not "
                    f"approved ({final}). Reason: {decision.reason}", True)
            _log(f"APPROVED {tool} (id={approval_id})")

        upstream, tool_def = self.registry[tool]
        started = time.time()
        try:
            result = upstream.call_tool(tool_def["name"], arguments)
        except UpstreamError as exc:
            latency_ms = int((time.time() - started) * 1000)
            self.audit.record(tool, arguments, decision.action,
                              decision.rule_id, decision.reason, "error",
                              latency_ms, risk_score=risk_score,
                              failure_class="upstream_error")
            self._flight(tool, arguments, None, "error", "upstream_error",
                         latency_ms)
            return tool_text_result(f"GRIT: upstream error: {exc}", True)
        latency_ms = int((time.time() - started) * 1000)
        status = "executed_shadow" if shadow else (
            "executed_after_approval" if decision.action == APPROVE
            else "executed")
        # the tool ran but reported failure -> that's a taxonomy class too
        fclass = "tool_error" if result.get("isError") else None
        self.audit.record(tool, arguments, decision.action, decision.rule_id,
                          decision.reason, status, latency_ms,
                          risk_score=risk_score, failure_class=fclass)
        if self.risk:
            self.risk.observe(tool, arguments)  # learn from executed calls only
        if self.flow:
            # raw result, pre-redaction: the guard must see real secrets
            self.flow.observe_result(tool, result)
        redacted = self.redactor.redact(result)
        self._flight(tool, arguments, redacted, status, fclass, latency_ms)
        return redacted

    def _notify_approval(self, approval_id: int, tool: str, arguments: dict,
                         risk_score: Optional[int], reason: str) -> None:
        """Fire-and-forget webhook; must never break or delay the call path."""
        if not self.notify_url:
            return
        text = (f"GRIT: call held for approval #{approval_id}\n"
                f"tool: {tool}  args: {json.dumps(arguments, sort_keys=True)}\n"
                f"risk: {risk_score if risk_score is not None else '-'}  "
                f"reason: {reason}\n"
                f"decide: grit approve {approval_id}  /  "
                f"grit deny {approval_id}")
        payload = json.dumps({"text": text}).encode("utf-8")

        def _post() -> None:
            try:
                req = urllib.request.Request(
                    self.notify_url, data=payload,
                    headers={"Content-Type": "application/json"})
                urllib.request.urlopen(req, timeout=5).close()
            except Exception as exc:
                _log(f"approval webhook failed: {exc}")

        threading.Thread(target=_post, daemon=True).start()

    def _await_approval(self, approval_id: int) -> str:
        deadline = time.time() + self.approval_timeout
        while time.time() < deadline:
            status = self.audit.approval_status(approval_id)
            if status and status != "pending":
                return status
            time.sleep(self.poll_interval)
        # decide_approval updates only WHERE status='pending'; if a human
        # decided in the final poll window it returns False — honor that
        # real decision instead of clobbering it with a false "expired".
        if self.audit.decide_approval(approval_id, "expired", "system:timeout"):
            return "expired"
        return self.audit.approval_status(approval_id) or "expired"
