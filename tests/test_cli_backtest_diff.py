"""CLI wiring for `grit backtest` and `grit diff`: exit codes + output."""
import json

from grit.cli import main as cli_main
from grit.recorder import Recorder

RESULT = {"content": [{"type": "text", "text": "ok"}], "isError": False}

CANDIDATE = {"default_action": "allow", "rules": [
    {"id": "big", "tools": ["pay__*"],
     "where": [{"path": "amount", "gt": 1000}], "action": "deny",
     "reason": "transfers over $1000 are forbidden"},
]}


def _seed(db: str) -> None:
    rec = Recorder(db)
    rec.record("a", 1, "pay__transfer_money", {"amount": 10}, RESULT,
               "executed", ts=1.0)
    rec.record("a", 2, "pay__transfer_money", {"amount": 5000}, RESULT,
               "executed", ts=2.0)
    rec.record("b", 1, "pay__transfer_money", {"amount": 10}, RESULT,
               "executed", ts=3.0)
    rec.record("b", 2, "pay__transfer_money", {"amount": 99}, RESULT,
               "executed", ts=4.0)


def _policy_file(tmp_path):
    pol = tmp_path / "candidate.json"
    pol.write_text(json.dumps(CANDIDATE), encoding="utf-8")
    return str(pol)


def test_backtest_cli_reports_changes(tmp_path, capsys):
    db = str(tmp_path / "m.db")
    _seed(db)
    assert cli_main(["backtest", _policy_file(tmp_path), "--db", db]) == 0
    out = capsys.readouterr().out
    assert "4 recorded calls" in out
    assert "1 executed calls would now be DENIED" in out
    assert "pay__transfer_money" in out and "big" in out


def test_backtest_cli_max_blocked_gate(tmp_path):
    db = str(tmp_path / "m.db")
    _seed(db)
    pol = _policy_file(tmp_path)
    assert cli_main(["backtest", pol, "--db", db,
                     "--max-blocked", "0"]) == 2
    assert cli_main(["backtest", pol, "--db", db,
                     "--max-blocked", "1"]) == 0


def test_backtest_cli_empty_history(tmp_path):
    db = str(tmp_path / "empty.db")
    Recorder(db)  # creates the schema, no rows
    assert cli_main(["backtest", _policy_file(tmp_path), "--db", db]) == 1


def test_diff_cli_identical_and_diverged(tmp_path, capsys):
    db = str(tmp_path / "m.db")
    _seed(db)
    assert cli_main(["diff", "a", "a", "--db", db]) == 0
    assert "behaviorally identical" in capsys.readouterr().out
    # a and b share step 1; step 2 args differ (5000 vs 99)
    assert cli_main(["diff", "a", "b", "--db", db]) == 3
    out = capsys.readouterr().out
    assert "DIVERGED at step 2" in out and "different arguments" in out


def test_diff_cli_missing_session(tmp_path):
    db = str(tmp_path / "m.db")
    _seed(db)
    assert cli_main(["diff", "a", "nope", "--db", db]) == 1
