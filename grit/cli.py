"""GRIT command-line interface."""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

from . import __version__
from .audit import AuditLog
from .gateway import Gateway, load_config

EXAMPLE_CONFIG = {
    "audit_db": "grit.db",
    "mode": "enforce",  # "observe": log every decision, block nothing
    "policies": "policies.json",
    "approval": {"timeout_seconds": 120, "poll_interval": 0.5},
    "redaction": {"enabled": ["email", "credit_card", "aws_key", "api_key", "us_ssn"]},
    "risk": {"enabled": True, "approve_at": 50, "deny_at": 85},
    "budget": {"max_calls_per_session": 500,
               "max_tokens_per_session": 2_000_000, "action": "approve"},
    "upstreams": [
        {"name": "demo", "command": sys.executable,
         "args": ["examples/demo_server.py"]}
    ],
}

EXAMPLE_POLICIES = {
    "default_action": "deny",
    "rules": [
        {"id": "no-destructive", "tools": ["*delete*", "*remove*", "*drop*"],
         "action": "deny", "reason": "destructive operations are forbidden"},
        {"id": "block-large-transfers", "tools": ["demo__transfer_money"],
         "where": [{"path": "amount", "gt": 1000}], "action": "deny",
         "reason": "transfers over $1000 are forbidden"},
        {"id": "approve-transfers", "tools": ["demo__transfer_money"],
         "where": [{"path": "amount", "gt": 50}], "action": "approve",
         "reason": "transfers over $50 need human approval"},
        {"id": "internal-email-only", "tools": ["demo__send_email"],
         "where": [{"path": "to", "not_regex": "@company\\.com$"}],
         "action": "deny", "reason": "email allowed only to @company.com"},
        {"id": "search-rate-limit", "tools": ["demo__search_docs"],
         "action": "allow",
         "rate_limit": {"max_calls": 5, "window_seconds": 60}},
        {"id": "allow-the-rest", "tools": ["*"], "action": "allow"},
    ],
}


_ANSI = {"red": "31", "green": "32", "yellow": "33", "magenta": "35",
         "bold": "1", "dim": "2"}
_COLOR: bool | None = None


def _color_enabled() -> bool:
    if os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        return False
    if os.name == "nt":
        os.system("")  # enables VT escape processing in legacy consoles
    return True


def _c(text: str, *styles: str) -> str:
    """Wrap text in ANSI styles when stdout is an interactive terminal."""
    global _COLOR
    if _COLOR is None:
        _COLOR = _color_enabled()
    if not _COLOR or not styles:
        return text
    return f"\x1b[{';'.join(_ANSI[s] for s in styles)}m{text}\x1b[0m"


def _risk_styles(risk) -> tuple[str, ...]:
    if risk is None:
        return ()
    if risk >= 85:
        return ("red", "bold")
    if risk >= 60:
        return ("red",)
    if risk >= 30:
        return ("yellow",)
    return ("green",)


_DECISION_STYLES = {"allow": ("green",), "deny": ("red",),
                    "approve": ("yellow",)}


def _status_styles(status: str) -> tuple[str, ...]:
    if status.startswith("executed"):
        return ("green",)
    if status == "error":
        return ("magenta",)
    return ("red",)


def _db_path(args: argparse.Namespace) -> str:
    if getattr(args, "db", None):
        return args.db
    if getattr(args, "config", None) and os.path.exists(args.config):
        return load_config(args.config)["audit_db"]
    return "grit.db"


def cmd_serve(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    gateway = Gateway(config)
    gateway.start()
    gateway.serve_stdio()
    return 0


def cmd_init(args: argparse.Namespace) -> int:
    for name, payload in (("grit.json", EXAMPLE_CONFIG),
                          ("policies.json", EXAMPLE_POLICIES)):
        if os.path.exists(name) and not args.force:
            print(f"skip {name} (exists; use --force to overwrite)")
            continue
        with open(name, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False)
        print(f"wrote {name}")
    print("\nNext: grit serve --config grit.json")
    return 0


def cmd_pending(args: argparse.Namespace) -> int:
    audit = AuditLog(_db_path(args))
    pending = audit.pending_approvals()
    if not pending:
        print("no pending approvals")
        return 0
    for item in pending:
        age = int(time.time() - item["ts"])
        risk = item.get("risk_score")
        print(f"#{item['id']}  {item['tool']}  args={item['arguments']}  "
              f"risk={risk if risk is not None else '-'}  "
              f"policy={item['reason'] or '-'}  waiting {age}s")
    return 0


def cmd_decide(args: argparse.Namespace, status: str) -> int:
    audit = AuditLog(_db_path(args))
    if audit.decide_approval(args.id, status, decided_by=args.by):
        print(f"approval #{args.id} -> {status}")
        return 0
    print(f"approval #{args.id} not found or already decided")
    return 1


def _format_row(row: dict) -> str:
    """One colored audit line — shared by `log` and `watch` so they never
    drift apart."""
    ts = time.strftime("%H:%M:%S", time.localtime(row["ts"]))
    lat = f"{row['latency_ms']}ms" if row["latency_ms"] is not None else "-"
    risk = row["risk_score"]
    decision = _c(f"{row['decision']:<7}",
                  *_DECISION_STYLES.get(row["decision"], ()))
    status = _c(f"{row['status']:<24}", *_status_styles(row["status"]))
    risk_txt = _c(f"{risk if risk is not None else '-':<4}",
                  *_risk_styles(risk))
    return (f"{_c(ts, 'dim')}  {decision} {status} "
            f"{row['tool']:<28} risk={risk_txt} "
            f"rule={row['rule_id'] or '-':<22} {lat:>7}  {row['arguments']}")


def cmd_log(args: argparse.Namespace) -> int:
    audit = AuditLog(_db_path(args))
    rows = audit.recent(args.n)
    for row in reversed(rows):
        print(_format_row(row))
    return 0


def _watch_poll(audit: AuditLog, last_id: int) -> tuple[int, list[dict]]:
    """One polling step: fetch rows newer than `last_id`.

    Returns the advanced cursor and the new rows (oldest first). The cursor
    only moves forward, so rows are never printed twice."""
    rows = audit.recent_since(last_id)
    if rows:
        last_id = rows[-1]["id"]
    return last_id, rows


def cmd_watch(args: argparse.Namespace) -> int:
    audit = AuditLog(_db_path(args))
    # start from the current tail so we tail *new* decisions, not history
    seen = audit.recent(1)
    last_id = seen[0]["id"] if seen else 0
    print(f"watching {audit.path} — Ctrl+C to stop")
    try:
        while True:
            last_id, rows = _watch_poll(audit, last_id)
            for row in rows:
                print(_format_row(row))
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("stopped")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    """Dry-run a tool call through policy + risk WITHOUT executing or
    recording anything — the loop you want while authoring policies.

    Runs the same decision the gateway would: policy first-match, then (if
    the policy allows and risk is enabled) the risk engine can escalate to
    APPROVE or DENY. Exit codes: 0 allow, 3 approve, 2 deny."""
    from .policy import ALLOW, APPROVE, DENY, Decision, PolicyEngine
    from .risk import RiskEngine

    try:
        arguments = json.loads(args.args) if args.args else {}
    except json.JSONDecodeError as exc:
        print(f"invalid --args JSON: {exc}")
        return 1
    if not isinstance(arguments, dict):
        print("--args must be a JSON object")
        return 1

    try:
        config = load_config(args.config)
    except FileNotFoundError as exc:
        print(f"config not found: {exc.filename} "
              f"(run 'grit init' or pass --config)")
        return 1
    except json.JSONDecodeError as exc:
        print(f"config is not valid JSON: {exc}")
        return 1
    policy = PolicyEngine(config["policy"])
    risk_cfg = config.get("risk", {})
    risk_enabled = bool(risk_cfg.get("enabled", True))
    approve_at = int(risk_cfg.get("approve_at", 50))
    deny_at = int(risk_cfg.get("deny_at", 85))

    decision = policy.evaluate(args.tool, arguments)
    assessment = None
    if risk_enabled:
        # warm-start from the audit db so baselines reflect real history,
        # exactly like the gateway does at startup
        engine = RiskEngine(audit=AuditLog(_db_path(args)))
        assessment = engine.assess(args.tool, arguments)
        if decision.action == ALLOW:
            if assessment.score >= deny_at:
                decision = Decision(DENY, "risk-engine", assessment.summary())
            elif assessment.score >= approve_at:
                decision = Decision(APPROVE, "risk-engine",
                                    assessment.summary())

    styled = _c(decision.action.upper(),
                *_DECISION_STYLES.get(decision.action, ()), "bold")
    print(f"{styled}  {args.tool}  args={json.dumps(arguments, sort_keys=True)}")
    print(f"  rule:   {decision.rule_id or '-'}")
    print(f"  reason: {decision.reason}")
    if assessment is not None:
        risk_txt = _c(str(assessment.score), *_risk_styles(assessment.score))
        print(f"  risk:   {risk_txt}/100 ({assessment.level})")
        for factor in assessment.factors:
            print(f"    - {factor}")
    else:
        print("  risk:   disabled")
    return {ALLOW: 0, APPROVE: 3, DENY: 2}[decision.action]


def cmd_incident(args: argparse.Namespace) -> int:
    """Compose a Markdown incident report for one session from the flight
    recorder + audit chain — the one-command postmortem artifact.

    Exits 2 (and still writes the report) when the audit chain is TAMPERED;
    exits 1 when the session is unknown."""
    from .recorder import Recorder
    db = _db_path(args)
    rec = Recorder(db)
    rows = rec.trace(args.session)
    if not rows:
        print(f"no recordings for session '{args.session}'")
        return 1

    audit = AuditLog(db)
    verdict = audit.verify()
    costs = rec.costs(args.session, args.usd_per_1m)

    started, ended = rows[0]["ts"], rows[-1]["ts"]
    duration = ended - started
    executed = sum(1 for r in rows if str(r["status"]).startswith("executed"))
    errors = sum(1 for r in rows if r["status"] == "error")
    blocked = len(rows) - executed - errors
    failures = sum(1 for r in rows if r["failure_class"])
    est_tokens = sum((r["tokens_in"] or 0) + (r["tokens_out"] or 0)
                     for r in rows)
    total_usd = sum(c["est_usd"] for c in costs)

    def fmt_ts(ts):
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))

    lines = [f"# GRIT incident report — session {args.session}", ""]
    lines += ["## Summary", "",
              f"- started: {fmt_ts(started)}",
              f"- ended: {fmt_ts(ended)}",
              f"- duration: {duration:.1f}s",
              f"- total calls: {len(rows)}",
              f"- executed: {executed}  blocked: {blocked}  errors: {errors}",
              f"- failures: {failures}",
              f"- est. tokens: {est_tokens}",
              f"- est. cost: ${total_usd:.4f} "
              f"(at ${args.usd_per_1m:g}/1M tokens)", ""]

    lines += ["## Audit chain", ""]
    if verdict.ok:
        lines += [f"- status: intact", f"- rows: {verdict.rows}", ""]
    else:
        lines += [f"- status: **TAMPERED**", f"- rows: {verdict.rows}",
                  f"- detail: {verdict.detail}", ""]

    by_class: dict[str, int] = {}
    for r in rows:
        if r["failure_class"]:
            by_class[r["failure_class"]] = by_class.get(r["failure_class"], 0) + 1
    if by_class:
        lines += ["## Failure breakdown", ""]
        for fclass, count in sorted(by_class.items(),
                                    key=lambda kv: (-kv[1], kv[0])):
            lines.append(f"- {fclass}: {count}")
        lines.append("")

    lines += ["## Call timeline", "",
              "| seq | time | status | failure | tool | latency | "
              "tokens in/out | arguments |",
              "|---|---|---|---|---|---|---|---|"]
    for r in rows:
        t = time.strftime("%H:%M:%S", time.localtime(r["ts"]))
        fc = r["failure_class"] or "-"
        lat = f"{r['latency_ms']}ms" if r["latency_ms"] is not None else "-"
        a = r["arguments"]
        if len(a) > 80:
            a = a[:77] + "..."
        lines.append(f"| {r['seq']} | {t} | {r['status']} | {fc} | "
                     f"{r['tool']} | {lat} | "
                     f"{r['tokens_in']}/{r['tokens_out']} | {a} |")
    lines.append("")

    lines += ["## Costliest tools", ""]
    top = sorted(costs, key=lambda c: (c["tokens_in"] or 0)
                 + (c["tokens_out"] or 0), reverse=True)[:5]
    lines += ["| tool | calls | tokens in | tokens out | est usd |",
              "|---|---|---|---|---|"]
    for c in top:
        lines.append(f"| {c['tool']} | {c['calls']} | {c['tokens_in']} | "
                     f"{c['tokens_out']} | {c['est_usd']:.4f} |")
    lines.append("")

    report = "\n".join(lines)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(report)
        print(f"report written to {args.out}")
    else:
        print(report)
    return 2 if not verdict.ok else 0


def cmd_incident_card(args: argparse.Namespace) -> int:
    """Emit a shareable incident-replay artifact for one caught call: the
    self-contained 'here is the dangerous call your agent would have made,
    and here is how to replay it' card (or --json for the open format)."""
    from .recorder import Recorder
    from .incident import build_artifact, render_html
    db = _db_path(args)
    try:
        artifact = build_artifact(Recorder(db), AuditLog(db), args.session,
                                  args.seq)
    except ValueError as exc:
        print(exc)
        return 1
    out = (json.dumps(artifact, indent=2, ensure_ascii=False)
           if args.json else render_html(artifact))
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(out)
        print(f"incident card written to {args.out}")
    else:
        print(out)
    return 0


def cmd_stats(args: argparse.Namespace) -> int:
    audit = AuditLog(_db_path(args))
    rows = audit.stats()
    if not rows:
        print("no calls recorded yet")
        return 0
    mode = audit.get_control("mode", "enforce")
    if mode == "observe":
        n = audit.shadow_count()
        print(_c(f'mode: OBSERVE — nothing is blocked; '
                 f'{n} call{"" if n == 1 else "s"} would have been held or '
                 f'denied (set "mode": "enforce" when convinced)', "yellow"))
    else:
        print(f"mode: {_c(mode, 'green')}")
    print(f"events last 7 days: {audit.events_count()}\n")
    print(f"{'TOOL':<30} {'CALLS':>6} {'EXEC':>6} {'BLOCKED':>8} "
          f"{'ERRORS':>7} {'AVG_MS':>7} {'AVG_RISK':>9} {'MAX_RISK':>9}")
    for r in rows:
        print(f"{r['tool']:<30} {r['calls']:>6} {r['executed']:>6} "
              f"{r['blocked']:>8} {r['errors']:>7} "
              f"{r['avg_latency_ms'] if r['avg_latency_ms'] is not None else '-':>7} "
              f"{r['avg_risk'] if r['avg_risk'] is not None else '-':>9} "
              f"{r['max_risk'] if r['max_risk'] is not None else '-':>9}")
    return 0


def cmd_sessions(args: argparse.Namespace) -> int:
    from .recorder import Recorder
    rows = Recorder(_db_path(args)).sessions()
    if not rows:
        print("no recorded sessions")
        return 0
    print(f"{'SESSION':<28} {'STARTED':<20} {'CALLS':>6} {'FAILURES':>9} "
          f"{'EST_TOKENS':>11}")
    for r in rows:
        started = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["started"]))
        print(f"{r['session_id']:<28} {started:<20} {r['calls']:>6} "
              f"{r['failures']:>9} {r['est_tokens']:>11}")
    return 0


def cmd_trace(args: argparse.Namespace) -> int:
    from .recorder import Recorder
    rows = Recorder(_db_path(args)).trace(args.session)
    if not rows:
        print(f"no recordings for session '{args.session}'")
        return 1
    for r in rows:
        ts = time.strftime("%H:%M:%S", time.localtime(r["ts"]))
        fc = r["failure_class"] or "-"
        lat = f"{r['latency_ms']}ms" if r["latency_ms"] is not None else "-"
        print(f"#{r['seq']:<4} {ts}  {r['status']:<24} {fc:<18} "
              f"{r['tool']:<28} {lat:>7}  in={r['tokens_in']}t "
              f"out={r['tokens_out']}t  {r['arguments']}")
    return 0


def cmd_replay(args: argparse.Namespace) -> int:
    from .recorder import Recorder, ReplayServer
    server = ReplayServer(Recorder(_db_path(args)), args.session,
                          strict=args.strict)
    print(f"[grit] replaying session {args.session} as a stdio MCP server",
          file=sys.stderr, flush=True)
    server.serve_stdio()
    return 0


def cmd_costs(args: argparse.Namespace) -> int:
    from .recorder import Recorder
    rows = Recorder(_db_path(args)).costs(args.session, args.usd_per_1m)
    if not rows:
        print("no recorded calls")
        return 0
    print(f"{'TOOL':<30} {'CALLS':>6} {'TOKENS_IN':>10} {'TOKENS_OUT':>11} "
          f"{'EST_USD':>9}")
    total = 0.0
    for r in rows:
        total += r["est_usd"]
        print(f"{r['tool']:<30} {r['calls']:>6} {r['tokens_in']:>10} "
              f"{r['tokens_out']:>11} {r['est_usd']:>9.4f}")
    print(f"{'TOTAL (context flow through tools)':<30} {'':>29} {total:>9.4f}")
    return 0


def cmd_backtest(args: argparse.Namespace) -> int:
    """Policy Wind Tunnel: what would this policy have done to history?

    Exit 0: report printed. Exit 1: nothing recorded yet. Exit 2: more
    executed calls would be denied than --max-blocked allows (CI gate)."""
    from .backtest import backtest
    from .recorder import Recorder
    with open(args.policies, "r", encoding="utf-8-sig") as fh:
        policy = json.load(fh)
    records = Recorder(_db_path(args)).records(session_id=args.session,
                                               limit=args.limit)
    if not records:
        print("no recorded history to backtest against")
        return 1
    report = backtest(policy, records)
    counts = report["counts"]
    skipped = f" (skipped {report['skipped']} unparsable)" \
        if report["skipped"] else ""
    print(f"backtest: {report['total']} recorded calls vs "
          f"{args.policies}{skipped}")
    print(f"  new policy verdicts: "
          f"{_c(str(counts.get('allow', 0)) + ' allow', 'green')}, "
          f"{_c(str(counts.get('approve', 0)) + ' approve', 'yellow')}, "
          f"{_c(str(counts.get('deny', 0)) + ' deny', 'red')}")
    block = report["would_block_executed"]
    hold = report["would_hold_executed"]
    freed = report["would_allow_blocked"]
    print(f"  changes vs history: {len(block)} executed calls would now be "
          f"DENIED; {len(hold)} would be HELD for approval; "
          f"{len(freed)} previously blocked would now be ALLOWED")
    shown = 0
    for label, style, entries in (("DENY", "red", block),
                                  ("HOLD", "yellow", hold),
                                  ("FREE", "green", freed)):
        for e in entries:
            if shown >= args.show:
                break
            print(f"  {_c(label, style)} {e['tool']} "
                  f"[{e['session_id']}#{e['seq']}] {e['old_status']} -> "
                  f"{e['new_action']} ({e['rule_id']})  {e['arguments'][:80]}")
            shown += 1
    remaining = len(block) + len(hold) + len(freed) - shown
    if remaining > 0:
        print(f"  ... and {remaining} more (raise --show)")
    if args.max_blocked is not None and len(block) > args.max_blocked:
        print(_c(f"FAIL: {len(block)} executed calls would be denied, "
                 f"over the --max-blocked {args.max_blocked} gate",
                 "red", "bold"))
        return 2
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    """Behavioral diff of two recorded sessions.

    Exit 0: behaviorally identical. Exit 3: diverged. Exit 1: missing."""
    from .recorder import Recorder
    from .sessdiff import diff_sessions
    rec = Recorder(_db_path(args))
    trace_a, trace_b = rec.trace(args.session_a), rec.trace(args.session_b)
    if not trace_a or not trace_b:
        missing = args.session_a if not trace_a else args.session_b
        print(f"no recordings for session '{missing}'")
        return 1
    d = diff_sessions(trace_a, trace_b)
    print(f"A {args.session_a}: {d['a_calls']} calls ~{d['a_tokens']}t    "
          f"B {args.session_b}: {d['b_calls']} calls ~{d['b_tokens']}t")
    if d["identical"]:
        print(_c(f"sessions are behaviorally identical "
                 f"({d['a_calls']} calls)", "green", "bold"))
        return 0
    div = d["first_divergence"]
    if div:
        if div["kind"] == "different_tool":
            print(_c(f"DIVERGED at step {div['step']}: the agent chose a "
                     f"different call", "red", "bold"))
            print(f"  A: {div['a_tool']} {div['a_args']}\n"
                  f"  B: {div['b_tool']} {div['b_args']}")
        elif div["kind"] == "different_arguments":
            print(_c(f"DIVERGED at step {div['step']}: same tool "
                     f"{div['tool']}, different arguments", "red", "bold"))
            print(f"  A: {div['a_args']}\n  B: {div['b_args']}")
        else:  # extra_calls
            longer = "A" if div["a_calls"] > div["b_calls"] else "B"
            print(_c(f"DIVERGED at step {div['step']}: {longer} kept going "
                     f"(A {div['a_calls']} calls, B {div['b_calls']})",
                     "red", "bold"))
        print(f"  common prefix: {d['common_prefix']} identical calls")
    for ch in d["outcome_changes"]:
        if ch["kind"] == "different_outcome":
            a_f = f"/{ch['a_failure']}" if ch["a_failure"] else ""
            b_f = f"/{ch['b_failure']}" if ch["b_failure"] else ""
            print(_c(f"  step {ch['step']} {ch['tool']}: same call, "
                     f"different outcome — A {ch['a_status']}{a_f} vs "
                     f"B {ch['b_status']}{b_f}  (the world changed, "
                     f"not the agent)", "yellow"))
        else:
            print(f"  step {ch['step']} {ch['tool']}: same call, "
                  f"different result payload")
    return 3


def cmd_drift(args: argparse.Namespace) -> int:
    report = AuditLog(_db_path(args)).drift(window_hours=args.hours)
    flagged = [r for r in report if r["flags"]]
    if not report:
        print("no audit data")
        return 0
    if not flagged:
        print(f"no drift detected across {len(report)} tools "
              f"(window: {args.hours}h vs previous {args.hours}h)")
        return 0
    for r in flagged:
        cur, prev = r["current"], r["previous"]
        def fmt(x):
            return (f"calls={x['calls']} fail={x['failure_rate']:.0%} "
                    f"lat={int(x['avg_latency'] or 0)}ms "
                    f"risk={int(x['avg_risk'] or 0)}") if x else "absent"
        print(f"DRIFT {r['tool']}: {', '.join(r['flags'])}\n"
              f"  prev: {fmt(prev)}\n  curr: {fmt(cur)}")
    return 1


def cmd_failures(args: argparse.Namespace) -> int:
    rows = AuditLog(_db_path(args)).failure_breakdown()
    if not rows:
        print("no failures recorded — nice")
        return 0
    total = sum(r["count"] for r in rows)
    for r in rows:
        print(f"{r['failure_class']:<22} {r['count']:>6}  "
              f"{r['count'] / total:>6.0%}")
    return 0


def cmd_pause(args: argparse.Namespace) -> int:
    audit = AuditLog(_db_path(args))
    audit.set_paused(True, by=args.by)
    print(_c("PAUSED: the gateway now refuses every tool call until "
             "'grit resume'", "red", "bold"))
    return 0


def cmd_resume(args: argparse.Namespace) -> int:
    audit = AuditLog(_db_path(args))
    audit.set_paused(False, by=args.by)
    print(_c("RESUMED: tool calls flow through policies again",
             "green", "bold"))
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    """JSONL evidence packet: audit chain + flight recordings + chain status.

    The thing you hand to an auditor (SOC 2, a customer security review)
    or attach to an incident review."""
    from .recorder import Recorder
    db = _db_path(args)
    audit = AuditLog(db)
    verdict = audit.verify()
    out = open(args.out, "w", encoding="utf-8") if args.out else sys.stdout
    try:
        meta = {"type": "meta", "exported_at": time.time(),
                "grit_version": __version__,
                "chain_ok": verdict.ok, "chain_rows": verdict.rows,
                "chain_detail": verdict.detail}
        out.write(json.dumps(meta, ensure_ascii=False) + "\n")
        for row in reversed(audit.recent(limit=args.limit)):
            out.write(json.dumps({"type": "audit", **row},
                                 ensure_ascii=False) + "\n")
        rec = Recorder(db)
        sessions = [s["session_id"] for s in rec.sessions()] \
            if not args.session else [args.session]
        for sid in sessions:
            for row in rec.trace(sid):
                out.write(json.dumps({"type": "recording", **row},
                                     ensure_ascii=False) + "\n")
    finally:
        if args.out:
            out.close()
            print(f"exported to {args.out} (chain "
                  f"{'intact' if verdict.ok else 'TAMPERED'}, "
                  f"{verdict.rows} audit rows)")
    return 0 if verdict.ok else 2


def cmd_verify(args: argparse.Namespace) -> int:
    result = AuditLog(_db_path(args)).verify()
    if result.ok:
        print(f"OK: audit chain intact ({result.rows} records)")
        return 0
    print(f"TAMPERED: {result.detail}")
    return 2


def cmd_dashboard(args: argparse.Namespace) -> int:
    from .dashboard import run_dashboard
    run_dashboard(_db_path(args), args.port)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="grit",
        description="GRIT: the agent control plane. Policies, human "
                    "approvals, risk scoring, session budgets, kill switch, "
                    "flight recorder with deterministic replay and "
                    "tamper-evident audit for AI agent tool calls (MCP).")
    parser.add_argument("--version", action="version",
                        version=f"grit {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("serve", help="run the gateway as a stdio MCP server")
    p.add_argument("--config", default="grit.json")
    p.set_defaults(fn=cmd_serve)

    p = sub.add_parser("init", help="scaffold grit.json + policies.json")
    p.add_argument("--force", action="store_true")
    p.set_defaults(fn=cmd_init)

    handlers = {"pending": cmd_pending, "log": cmd_log, "watch": cmd_watch,
                "check": cmd_check, "incident": cmd_incident,
                "incident-card": cmd_incident_card,
                "stats": cmd_stats,
                "verify": cmd_verify, "dashboard": cmd_dashboard,
                "sessions": cmd_sessions, "trace": cmd_trace,
                "replay": cmd_replay, "costs": cmd_costs,
                "backtest": cmd_backtest, "diff": cmd_diff,
                "drift": cmd_drift, "failures": cmd_failures,
                "pause": cmd_pause, "resume": cmd_resume,
                "export": cmd_export}
    for name, helptext in (
            ("pending", "list calls waiting for approval"),
            ("log", "show recent audit records"),
            ("watch", "live tail of decisions (Ctrl+C to stop)"),
            ("check", "dry-run a call against policies + risk "
                      "(no execution)"),
            ("incident", "generate a Markdown incident report for a session"),
            ("incident-card", "shareable incident-replay artifact for one "
                              "caught call (self-contained HTML, or --json)"),
            ("stats", "per-tool ops summary (volume, errors, risk)"),
            ("verify", "verify the audit hash chain"),
            ("dashboard", "run the local web dashboard"),
            ("sessions", "list recorded agent sessions"),
            ("trace", "print the call timeline of a session"),
            ("replay", "serve a recorded session as a mock MCP server"),
            ("costs", "estimated context cost of tool traffic"),
            ("backtest", "test a candidate policy file against recorded "
                         "history (Policy Wind Tunnel; exit 2 over "
                         "--max-blocked)"),
            ("diff", "behavioral diff of two recorded sessions "
                     "(exit 0 identical, 3 diverged)"),
            ("drift", "compare tool behavior: last window vs previous"),
            ("failures", "failure taxonomy breakdown"),
            ("pause", "KILL SWITCH: refuse every tool call until resume"),
            ("resume", "lift the kill switch"),
            ("export", "JSONL evidence packet for auditors/incident review")):
        p = sub.add_parser(name, help=helptext)
        p.add_argument("--config", default="grit.json")
        p.add_argument("--db", default=None, help="path to audit db")
        if name == "log":
            p.add_argument("-n", type=int, default=30)
        if name == "watch":
            p.add_argument("--interval", type=float, default=1.0,
                           help="poll interval in seconds (default 1.0)")
        if name == "check":
            p.add_argument("tool", help="tool name, e.g. demo__transfer_money")
            p.add_argument("--args", default=None,
                           help='call arguments as JSON, e.g. \'{"amount":49}\'')
        if name == "incident":
            p.add_argument("session")
            p.add_argument("--out", default=None,
                           help="output file (default: stdout)")
            p.add_argument("--usd-per-1m", type=float, default=3.0,
                           dest="usd_per_1m")
        if name == "incident-card":
            p.add_argument("session")
            p.add_argument("--seq", type=int, default=None,
                           help="feature a specific call by step number "
                                "(default: the most significant caught call)")
            p.add_argument("--out", default=None,
                           help="output file (default: stdout); .html card")
            p.add_argument("--json", action="store_true",
                           help="emit the structured artifact (open format) "
                                "instead of HTML")
        if name == "dashboard":
            p.add_argument("--port", type=int, default=8787)
        if name in ("trace", "replay"):
            p.add_argument("session")
        if name == "replay":
            p.add_argument("--strict", action="store_true")
        if name == "costs":
            p.add_argument("--session", default=None)
            p.add_argument("--usd-per-1m", type=float, default=3.0,
                           dest="usd_per_1m")
        if name == "backtest":
            p.add_argument("policies", help="candidate policies.json to test")
            p.add_argument("--session", default=None,
                           help="limit history to one session")
            p.add_argument("--limit", type=int, default=None,
                           help="max records to evaluate")
            p.add_argument("--show", type=int, default=10,
                           help="changed calls to print (default 10)")
            p.add_argument("--max-blocked", type=int, default=None,
                           dest="max_blocked",
                           help="CI gate: exit 2 if more executed calls "
                                "would now be denied")
        if name == "diff":
            p.add_argument("session_a")
            p.add_argument("session_b")
        if name == "drift":
            p.add_argument("--hours", type=float, default=24.0)
        if name in ("pause", "resume"):
            p.add_argument("--by", default="cli")
        if name == "export":
            p.add_argument("--out", default=None,
                           help="output file (default: stdout)")
            p.add_argument("--session", default=None,
                           help="limit recordings to one session")
            p.add_argument("--limit", type=int, default=1_000_000,
                           help="max audit rows")
        p.set_defaults(fn=handlers[name])

    for name, status in (("approve", "approved"), ("deny", "denied")):
        p = sub.add_parser(name, help=f"{name} a pending call")
        p.add_argument("id", type=int)
        p.add_argument("--config", default="grit.json")
        p.add_argument("--db", default=None)
        p.add_argument("--by", default="cli")
        p.set_defaults(fn=lambda a, s=status: cmd_decide(a, s))

    args = parser.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
