"""Policy Wind Tunnel — test a candidate policy against recorded history.

The central fear that prevents teams from tightening policy is the
false-positive: "what if my new rule blocks a real, legitimate call?"
Backtesting kills that fear with data. Feed a candidate policy config and
every call the flight recorder has ever captured; get back a precise count
of what *would* have been blocked, held for approval, or newly freed —
before a single production call is affected.

The technique is borrowed straight from algorithmic trading, where no sane
engineer deploys a strategy without running it over historical fills first.
The flight recorder makes this uniquely possible here: because it stores the
full serialised arguments for every call (not just metadata), the policy
engine can re-evaluate each one with the exact same inputs, including
historical timestamps so that rate-limit windows replay faithfully.

Typical output for a tightening run:
  "would have blocked 2 incidents and held 1 of 14,310 legitimate calls"

That's the sentence that turns a security debate into a merge request.
"""
from __future__ import annotations

import json
from typing import Optional

from .policy import ALLOW, APPROVE, DENY, PolicyEngine

# Status values produced by the gateway that mean the call was actually
# executed (not blocked, not pending approval).
_EXECUTED_STATUSES = {"executed", "executed_shadow", "executed_after_approval"}


def backtest(policy_config: dict, records: list[dict]) -> dict:
    """Evaluate *policy_config* against every row in *records*.

    Args:
        policy_config: A policy dict in the same format accepted by
            :class:`~grit.policy.PolicyEngine` (keys: ``default_action``,
            ``rules``).
        records: Rows from :meth:`~grit.recorder.Recorder.records` —
            chronological (ts, seq) order.  Each row must contain at least:
            ``session_id``, ``seq``, ``tool``, ``arguments`` (JSON text),
            ``status``, and ``ts``.

    Returns:
        A dict with keys:

        ``total``
            Number of rows successfully evaluated.
        ``skipped``
            Rows whose ``arguments`` field could not be parsed as JSON.
        ``counts``
            ``{"allow": n, "approve": n, "deny": n}`` — new-policy action
            distribution over evaluated rows.
        ``would_block_executed``
            Rows that were historically *executed* but the new policy would
            *deny*.  Each entry carries ``session_id``, ``seq``, ``tool``,
            ``arguments`` (raw JSON text), ``old_status``, ``new_action``,
            ``rule_id``, ``reason``.
        ``would_hold_executed``
            Rows that were historically *executed* but the new policy would
            *approve* (hold for human review).
        ``would_allow_blocked``
            Rows that were historically *blocked* but the new policy would
            *allow*.
    """
    engine = PolicyEngine(policy_config)

    counts: dict[str, int] = {ALLOW: 0, APPROVE: 0, DENY: 0}
    skipped = 0
    would_block_executed: list[dict] = []
    would_hold_executed: list[dict] = []
    would_allow_blocked: list[dict] = []

    for row in records:
        args_text: str = row.get("arguments", "") or ""
        try:
            arguments: dict = json.loads(args_text)
        except (json.JSONDecodeError, ValueError):
            skipped += 1
            continue

        tool: str = row.get("tool", "")
        ts: Optional[float] = row.get("ts")
        decision = engine.evaluate(tool, arguments, now=ts)

        new_action = decision.action
        counts[new_action] = counts.get(new_action, 0) + 1

        old_status: str = row.get("status", "")
        was_executed = old_status in _EXECUTED_STATUSES
        was_blocked = old_status == "blocked"

        entry: Optional[dict] = None
        if was_executed and new_action == DENY:
            entry = would_block_executed
        elif was_executed and new_action == APPROVE:
            entry = would_hold_executed
        elif was_blocked and new_action == ALLOW:
            entry = would_allow_blocked

        if entry is not None:
            entry.append({
                "session_id": row.get("session_id"),
                "seq": row.get("seq"),
                "tool": tool,
                "arguments": args_text,
                "old_status": old_status,
                "new_action": new_action,
                "rule_id": decision.rule_id,
                "reason": decision.reason,
            })

    total = sum(counts.values())
    return {
        "total": total,
        "skipped": skipped,
        "counts": counts,
        "would_block_executed": would_block_executed,
        "would_hold_executed": would_hold_executed,
        "would_allow_blocked": would_allow_blocked,
    }
