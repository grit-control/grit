"""Behavioral diff between two recorded agent sessions.

The two worst debug phrases in agent development are "it failed, I reran it,
it worked" and "the second run produced different output" — with no idea
*where* the divergence happened or *why*. This module kills both by treating
two session traces as sequences of observable decisions and computing a
structured diff: the exact step where the agent's *choices* parted ways
(different call = the agent diverged) vs. where the *world* diverged (same
call, different outcome = an external service changed). That distinction
is the seed of regression testing for agents: run the same task twice,
diff what the agent DID, and you know immediately whether to fix the agent
or the environment.
"""
from __future__ import annotations


def diff_sessions(trace_a: list[dict], trace_b: list[dict]) -> dict:
    """Compute a behavioral diff between two recorded agent session traces.

    Each trace is a list of dicts as returned by ``Recorder.trace(session_id)``
    — ordered by ``seq`` and containing at minimum: ``tool``, ``args_hash``,
    ``result``, ``status``, ``failure_class``, ``tokens_in``, ``tokens_out``.

    The walk is *positional*: step *i* of session A is compared against step
    *i* of session B (not matched by content).  The first structural divergence
    (tool or arguments differ) stops the walk immediately; outcome/result
    changes on otherwise identical calls are accumulated throughout.

    Returns a dict with keys:

    * ``a_calls`` / ``b_calls`` — total call counts for each session.
    * ``common_prefix`` — steps walked before the first structural divergence
      (equals ``min(a_calls, b_calls)`` when there is none).
    * ``first_divergence`` — dict describing the first structural divergence,
      or ``None`` when the call sequences are identical.
    * ``outcome_changes`` — list of steps where the same call produced a
      different status/failure-class or different result payload.
    * ``identical`` — ``True`` only when ``first_divergence`` is ``None`` and
      ``outcome_changes`` is empty.
    * ``a_tokens`` / ``b_tokens`` — sum of ``tokens_in + tokens_out`` over
      each session (useful for cost-regression detection).
    """
    len_a = len(trace_a)
    len_b = len(trace_b)
    min_len = min(len_a, len_b)

    first_divergence: dict | None = None
    outcome_changes: list[dict] = []
    steps_walked = 0

    for i in range(min_len):
        a = trace_a[i]
        b = trace_b[i]
        step = i + 1

        if a["tool"] != b["tool"]:
            first_divergence = {
                "step": step,
                "kind": "different_tool",
                "a_tool": a["tool"],
                "a_args": a["arguments"],
                "b_tool": b["tool"],
                "b_args": b["arguments"],
            }
            break

        if a["args_hash"] != b["args_hash"]:
            first_divergence = {
                "step": step,
                "kind": "different_arguments",
                "tool": a["tool"],
                "a_args": a["arguments"],
                "b_args": b["arguments"],
            }
            break

        # Identical call (same tool + same args_hash) — check outcome.
        steps_walked += 1
        a_status = a.get("status")
        b_status = b.get("status")
        a_failure = a.get("failure_class")
        b_failure = b.get("failure_class")

        if a_status != b_status or a_failure != b_failure:
            outcome_changes.append({
                "step": step,
                "kind": "different_outcome",
                "tool": a["tool"],
                "a_status": a_status,
                "b_status": b_status,
                "a_failure": a_failure,
                "b_failure": b_failure,
            })
        elif (a.get("result") or "") != (b.get("result") or ""):
            outcome_changes.append({
                "step": step,
                "kind": "different_result",
                "tool": a["tool"],
            })
    else:
        # Loop completed without a break — all min_len steps were identical.
        steps_walked = min_len

    common_prefix = steps_walked

    if first_divergence is None and len_a != len_b:
        first_divergence = {
            "step": min_len + 1,
            "kind": "extra_calls",
            "a_calls": len_a,
            "b_calls": len_b,
        }

    a_tokens = sum((r.get("tokens_in") or 0) + (r.get("tokens_out") or 0)
                   for r in trace_a)
    b_tokens = sum((r.get("tokens_in") or 0) + (r.get("tokens_out") or 0)
                   for r in trace_b)

    return {
        "a_calls": len_a,
        "b_calls": len_b,
        "common_prefix": common_prefix,
        "first_divergence": first_divergence,
        "outcome_changes": outcome_changes,
        "identical": first_divergence is None and not outcome_changes,
        "a_tokens": a_tokens,
        "b_tokens": b_tokens,
    }
