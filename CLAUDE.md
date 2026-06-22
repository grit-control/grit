# CLAUDE.md

Guidance for Claude Code when working in this repository.

## Project

**GRIT — the agent control plane** ("Stripe Radar for AI agent actions").
An MCP gateway that sits between an agent and its tool servers and adds:
per-call policy decisions (allow / deny / approve), a behavioral risk engine,
session budgets, a kill switch, human-in-the-loop approvals (CLI + web
dashboard), tamper-evident audit (sha256 hash chain over SQLite), PII/secret
redaction, a flight recorder with deterministic replay and cost metering,
drift detection and a failure taxonomy. The public pitch and usage guide is
`README.md`.

## Commands

```bash
python -m pytest -q                      # full test suite (incl. e2e over real stdio)
python -m pytest tests/test_risk.py -q   # single test file
python -m pytest -q -k "name"            # single test by keyword

python -m grit.cli init                # write grit.json + policies.json
python -m grit.cli serve --config grit.json   # run the gateway (MCP stdio)
python -m grit.cli dashboard           # web UI: kill switch, approvals, sessions, costs
python -m grit.cli pause               # KILL SWITCH: refuse every call until resume
python -m grit.cli resume              # lift the kill switch
python -m grit.cli pending             # calls held for human approval
python -m grit.cli approve <id>        # release a held call (deny <id> to refuse)
python -m grit.cli stats               # per-tool ops stats
python -m grit.cli log -n 50           # recent decisions with risk scores
python -m grit.cli watch               # live tail of decisions (Ctrl+C)
python -m grit.cli check <tool> --args '{"k": 1}'   # policy/risk dry-run (exit 0/3/2)
python -m grit.cli incident <session> --out r.md    # Markdown postmortem
python -m grit.cli incident-card <session> --out card.html   # shareable incident-replay card: one caught call + replay (--json = open format)
python -m grit.cli sessions            # recorded agent sessions (flight recorder)
python -m grit.cli trace <session>     # full call timeline of a session
python -m grit.cli replay <session>    # serve recorded responses as a mock MCP server
python -m grit.cli diff <a> <b>        # behavioral diff of two sessions (exit 0 identical / 3 diverged)
python -m grit.cli backtest cand.json  # policy wind tunnel vs recorded history (exit 2 over --max-blocked)
python -m grit.cli costs               # estimated context cost per tool
python -m grit.cli drift               # last window vs previous: behavior shifts
python -m grit.cli failures            # failure taxonomy breakdown
python -m grit.cli verify              # audit hash chain check (exit 0 ok, 2 tampered)
python -m grit.cli export --out e.jsonl   # evidence packet for auditors

python examples/demo.py                  # live end-to-end demo (10 scenes)
```

On Windows use `python`; README examples use `python3` (macOS/Linux).

## Architecture

Call flow in `grit/gateway.py`: **kill switch → schema validation → policy →
risk → flow guard → session budget → approval → execute → redact → audit**
(+ every call, blocked or not, lands in the flight recorder). Config `"mode": "observe"`
computes and logs every decision (`executed_shadow`) but blocks nothing —
except the kill switch and schema validation, which always apply.

| Module | Role |
|---|---|
| `grit/jsonrpc.py` | MCP stdio framing (newline-delimited JSON-RPC 2.0) |
| `grit/upstream.py` | upstream MCP server subprocess management; tools exposed as `<server>__<tool>` |
| `grit/policy.py` | ordered first-match rules, default deny, rate limits |
| `grit/risk.py` | risk engine: behavioral baselines, numeric anomalies (z-score vs median/MAD), novelty, velocity bursts, stuck loops, secrets-in-args; scores 0–100, escalates via `approve_at` / `deny_at` |
| `grit/audit.py` | hash-chained audit log + approvals + controls (kill switch) + drift + failure taxonomy (SQLite, WAL) |
| `grit/redact.py` | PII/secret redaction of tool results |
| `grit/recorder.py` | flight recorder + deterministic replay + cost meter (token estimates) |
| `grit/incident.py` | shareable incident-replay artifact: one caught call → self-contained HTML + embedded open JSON format (the "Sentry link" for an agent incident) |
| `grit/flow.py` | flow guard: trust zones per upstream, verbatim-secret egress control (the lethal trifecta enforced) |
| `grit/backtest.py` | policy wind tunnel: evaluate candidate rules against recorded history |
| `grit/sessdiff.py` | behavioral diff between two recorded sessions (first divergence, outcome changes) |
| `grit/gateway.py` | the control plane itself (incl. session budget guard) |
| `grit/cli.py` | all CLI entry points |
| `grit/dashboard.py` | local web dashboard (stdlib `http.server`): kill switch, approvals, sessions, costs, failures |

## Hard constraints

- **Zero runtime dependencies.** Python 3.10+ stdlib only. Never add packages to
  `pyproject.toml` dependencies; tests may assume only `pytest` as a dev tool.
- **Audit log is append-only and hash-chained.** Never change the chain/record
  format without a migration story — `grit.cli verify` must keep working
  against existing logs.
- **Blocked calls must not poison risk baselines** — only executed calls feed
  the learning loop.
- Every feature ships with tests; cross-process behavior gets an e2e test over
  real stdio subprocesses (see `tests/test_e2e.py`, `tests/conftest.py`).
- Keep the "MVP limitations (honest list)" section of `README.md` truthful —
  update it when scope changes.

## gstack configuration

Explicit instruction for Claude Code: the git workflow in this repo is
**stacked branches via gstack** ([Bendzae/gstack](https://github.com/Bendzae/gstack),
binary `gs`). These commands are the active interface; prefer them over raw
git for anything involving stack branches or PRs.

### Active commands

| Command | Use it to |
|---|---|
| `gs new` | start a new stack: branches off the current branch and checks out the new branch |
| `gs add` | stack one more branch on top of the current stack |
| `gs sync` (alias `gs ss`) | pull, rebase and push **all** stack branches and refresh PR descriptions |
| `gs up` / `gs down` | move one branch up / down the stack |
| `gs change` (alias `gs c`) | interactively pick a stack branch |
| `gs pr new` | open GitHub PRs for every stack branch that has none yet |
| `gs pr merge` | merge the whole stack bottom-up into the base branch |
| `gs help` | list commands |

### How to behave

1. **One logical change = one stack branch.** For multi-step features, build a
   stack: `gs new` for the base layer, `gs add` for each subsequent layer —
   small, independently reviewable branches instead of one big branch.
2. **Never hand-rebase or force-push stack branches.** Keeping the stack
   consistent is `gs sync`'s job — it rebases and pushes every branch and
   updates PR descriptions. Do not use `git rebase` / `git push --force` on
   branches that belong to a stack.
3. **Navigate the stack with `gs up` / `gs down` / `gs change`**, not
   `git checkout`, so gstack's stack state stays correct.
4. **PR lifecycle:** create PRs with `gs pr new`; merge only with
   `gs pr merge` (bottom-up, in order). Never merge a mid-stack PR manually —
   it breaks the branches above it.
5. **Plain git is still fine** for everything that doesn't touch stack
   structure: `git status`, `git diff`, `git log`, staging and committing on
   the current branch.
6. **Config & secrets:** gstack reads a GitHub personal access token from
   `$HOME/.gstack/config.toml`. Never print, log or commit that token; if it
   is missing, tell the user to add it rather than working around it.
7. **Preconditions:** if `gs` is not on PATH or the directory is not a git
   repository yet, say so explicitly and fall back to plain git for the
   immediate task — do not emulate stack operations by hand and do not
   install tools or run `git init` without being asked.
