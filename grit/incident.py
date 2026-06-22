"""Incident-replay artifact: one caught tool-call, made shareable.

The flight recorder answers "what did the agent do?"; this turns a single
*caught* moment into a self-contained artifact a human can forward — the
exact tool-call GRIT stopped (or would have), why it was caught, the step
it would have died at, and the one command that replays the whole session
offline. It is the Sentry link for an agent incident: the thing an engineer
drops in Slack that brings the next person in.

Two layers, on purpose:

* ``build_artifact()`` returns the structured incident as a plain dict — an
  open, versioned schema (``format`` / ``format_version``). The format is the
  thing worth owning and publishing, independent of how it is drawn.
* ``render_html()`` produces a dependency-free, single-file HTML card and
  embeds that same JSON inside it, so the machine-readable format always
  travels with the human-readable card.

Sharing safety: recorded arguments are stored verbatim, so a flow-guard catch
holds the very secret the guard stopped. Arguments are run through the
redactor before they enter the artifact — the shareable card never leaks what
GRIT exists to protect.
"""
from __future__ import annotations

import html as _html
import json
import time
from typing import Any, Optional

from .redact import Redactor

FORMAT = "grit.incident"
FORMAT_VERSION = "1"

# A recorded call counts as "caught" when enforcement stopped/held it, or when
# observe mode logged that it WOULD have been stopped (executed_shadow).
_HARD_CATCH = {"blocked", "approval_denied", "approval_timeout"}
_SHADOW = "executed_shadow"

# Which catch is the most worth showing, when a session has several.
_SEVERITY = {
    "flow_block": 6,
    "risk_block": 5,
    "policy_block": 4,
    "budget_exceeded": 3,
    "paused": 2,
    "unknown_tool": 1,
    "schema_mismatch": 1,
}

_CATEGORY = {
    "flow_block": "Flow guard: verbatim secret heading to an external sink "
                  "(lethal trifecta)",
    "risk_block": "Risk engine: behavioral anomaly",
    "policy_block": "Policy: explicit rule",
    "budget_exceeded": "Session budget: runaway protection",
    "paused": "Kill switch: operator paused the gateway",
    "schema_mismatch": "Schema validation: malformed/hallucinated call",
    "unknown_tool": "Unknown tool",
    "tool_error": "Tool reported an error",
    "upstream_error": "Upstream error",
}


def _severity(failure_class: Optional[str]) -> int:
    return _SEVERITY.get(failure_class or "", 0)


def _iso(ts: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def pick_headline(trace: list[dict]) -> dict:
    """Choose the call worth featuring: the most severe hard catch, else the
    latest observe-mode would-block, else (nothing caught) the last call."""
    hard = [r for r in trace if r["status"] in _HARD_CATCH]
    if hard:
        return max(hard, key=lambda r: (_severity(r["failure_class"]), r["seq"]))
    shadow = [r for r in trace if r["status"] == _SHADOW]
    if shadow:
        return shadow[-1]
    return trace[-1]


def _is_caught(status: str) -> bool:
    return status in _HARD_CATCH or status == _SHADOW


def _category(status: str, failure_class: Optional[str],
              decision: dict) -> str:
    if status == _SHADOW:
        would = decision.get("decision") or "held"
        return f"Observe mode: would have been {would}"
    if status == "approval_denied":
        return "Human approval: denied"
    if status == "approval_timeout":
        return "Human approval: timed out (no decision)"
    if failure_class in _CATEGORY:
        return _CATEGORY[failure_class]
    if status == "error":
        return _CATEGORY.get(failure_class, "Error")
    return "Executed: no enforcement action"


def build_artifact(recorder: Any, audit: Any, session_id: str,
                   seq: Optional[int] = None,
                   redactor: Optional[Redactor] = None) -> dict:
    """Build the structured incident artifact for one call in a session.

    ``recorder`` / ``audit`` are a :class:`~grit.recorder.Recorder` and an
    :class:`~grit.audit.AuditLog` over the same DB. ``seq`` features a
    specific step; without it, the most significant caught call is chosen.
    Raises ``ValueError`` for an unknown session or step.
    """
    trace = recorder.trace(session_id)
    if not trace:
        raise ValueError(f"session '{session_id}' has no recorded calls")
    if seq is not None:
        row = next((r for r in trace if r["seq"] == seq), None)
        if row is None:
            raise ValueError(
                f"session '{session_id}' has no call at step {seq}")
    else:
        row = pick_headline(trace)

    status = row["status"]
    # The recorder has no decision rationale; the audit chain does. The audit
    # table is not session-scoped, so reconnect the two by the call itself.
    decision = audit.match_call(row["tool"], row["arguments"], status,
                                row["failure_class"], row["ts"]) or {}

    redactor = redactor or Redactor()
    try:
        arguments: Any = json.loads(row["arguments"])
    except (json.JSONDecodeError, TypeError):
        arguments = row["arguments"]
    arguments = redactor.redact(arguments)

    audit_hash = decision.get("hash")
    return {
        "format": FORMAT,
        "format_version": FORMAT_VERSION,
        "session": session_id,
        "step": row["seq"],
        "total_steps": len(trace),
        "captured_at": _iso(row["ts"]),
        "tool": row["tool"],
        "arguments": arguments,
        "arguments_redacted": True,
        "caught": _is_caught(status),
        "outcome": status,
        "failure_class": row["failure_class"],
        "category": _category(status, row["failure_class"], decision),
        "decision": decision.get("decision"),
        "rule_id": decision.get("rule_id"),
        "reason": decision.get("reason"),
        "risk_score": decision.get("risk_score"),
        "latency_ms": row["latency_ms"],
        "audit_hash": audit_hash,
        "replay_command": f"grit replay {session_id}",
    }


_CSS = """
* { box-sizing: border-box; }
body { margin: 0; padding: 32px 16px; background: #0a0c10; color: #e6e9ef;
  font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
.card { max-width: 680px; margin: 0 auto; background: #12151c;
  border: 1px solid #232836; border-radius: 14px; overflow: hidden; }
.head { padding: 22px 26px; border-bottom: 1px solid #232836; }
.badge { display: inline-block; font-size: 12px; font-weight: 700;
  letter-spacing: .06em; padding: 4px 10px; border-radius: 999px; }
.badge.caught { background: #3b1219; color: #ff9aa6; }
.badge.shadow { background: #2a2410; color: #f4d06f; }
.badge.none { background: #14241a; color: #7fdca0; }
.cat { margin: 12px 0 0; font-size: 19px; font-weight: 650; }
.body { padding: 22px 26px; }
.row { display: flex; gap: 14px; margin: 0 0 14px; }
.k { width: 130px; flex: none; color: #8b93a6; font-size: 13px; padding-top: 2px; }
.v { flex: 1; min-width: 0; }
code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
pre { margin: 0; padding: 12px 14px; background: #0a0c10; border: 1px solid #232836;
  border-radius: 8px; overflow-x: auto; font-size: 13px; }
.tool { font-size: 15px; color: #c4b5fd; font-weight: 600; }
.reason { padding: 12px 14px; background: #0a0c10; border-left: 3px solid #8b7cf6;
  border-radius: 6px; color: #d6dae3; }
.risk { display: inline-block; font-weight: 700; font-size: 13px;
  padding: 3px 9px; border-radius: 6px; }
.risk.hi { background: #3b1219; color: #ff9aa6; }
.risk.mid { background: #2a2410; color: #f4d06f; }
.risk.lo { background: #14241a; color: #7fdca0; }
.step { font-size: 15px; }
.step b { color: #ff9aa6; }
.foot { padding: 16px 26px; border-top: 1px solid #232836; color: #6b7385;
  font-size: 12px; display: flex; justify-content: space-between; gap: 12px; }
.foot code { color: #8b93a6; }
a { color: #c4b5fd; }
"""


def render_html(artifact: dict) -> str:
    """Render the artifact as a self-contained, dependency-free HTML card
    with the structured JSON embedded inside it."""
    esc = _html.escape
    a = artifact
    args = a["arguments"]
    args_text = (args if isinstance(args, str)
                 else json.dumps(args, indent=2, ensure_ascii=False))

    if a["outcome"] == _SHADOW:
        badge_cls, badge_txt = "shadow", "WOULD HAVE BEEN CAUGHT"
    elif a["caught"]:
        badge_cls, badge_txt = "caught", "CAUGHT"
    else:
        badge_cls, badge_txt = "none", "NO ENFORCEMENT ACTION"

    rows = [
        ("Tool call", f"<span class='tool'>{esc(a['tool'])}</span>"
                      f"<pre>{esc(args_text)}</pre>"),
    ]
    if a.get("reason"):
        rows.append(("Why", f"<div class='reason'>{esc(a['reason'])}</div>"))
    risk = a.get("risk_score")
    if risk is not None:
        rcls = "hi" if risk >= 85 else "mid" if risk >= 50 else "lo"
        rows.append(("Risk score",
                     f"<span class='risk {rcls}'>{esc(str(risk))}/100</span>"))
    rows.append(("Step",
                 f"<span class='step'>would have died at step "
                 f"<b>{a['step']}</b> of {a['total_steps']}</span>"))
    rows.append(("Replay",
                 f"<pre>{esc(a['replay_command'])}</pre>"
                 "<div style='color:#6b7385;font-size:12px;margin-top:6px'>"
                 "re-runs the whole session offline against recorded results "
                 "— no live tools, no spend</div>"))

    body = "".join(
        f"<div class='row'><div class='k'>{esc(k)}</div>"
        f"<div class='v'>{v}</div></div>" for k, v in rows)

    audit_hash = a.get("audit_hash")
    prov = (f"audit chain <code>{esc(audit_hash[:16])}...</code> tamper-evident"
            if audit_hash else "not matched in audit chain")
    embedded = json.dumps(a, ensure_ascii=False).replace("<", "\\u003c")

    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        f"<title>GRIT incident — {esc(a['tool'])}</title>"
        f"<style>{_CSS}</style></head><body><div class='card'>"
        f"<div class='head'><span class='badge {badge_cls}'>{esc(badge_txt)}</span>"
        f"<div class='cat'>{esc(a['category'])}</div></div>"
        f"<div class='body'>{body}</div>"
        f"<div class='foot'><span>{prov}</span>"
        f"<span>{esc(a['captured_at'])} - {esc(FORMAT)} v{esc(FORMAT_VERSION)}</span>"
        "</div></div>"
        f"<script type='application/json' id='grit-incident'>{embedded}</script>"
        "</body></html>"
    )
