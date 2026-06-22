"""Policy Wind Tunnel — backtest() and Recorder.records() tests."""
import json

import pytest

from grit.backtest import backtest
from grit.recorder import Recorder

# ---------------------------------------------------------------------------
# Candidate policy for all tests
# ---------------------------------------------------------------------------

CANDIDATE_POLICY = {
    "default_action": "allow",
    "rules": [
        {
            "id": "big",
            "tools": ["pay__transfer*"],
            "where": [{"path": "amount", "gt": 1000}],
            "action": "deny",
        },
        {
            "id": "mid",
            "tools": ["pay__transfer*"],
            "where": [{"path": "amount", "gt": 50}],
            "action": "approve",
        },
    ],
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _result(text: str) -> dict:
    return {"content": [{"type": "text", "text": text}], "isError": False}


def _seed_recorder(tmp_path) -> Recorder:
    """Create a Recorder populated with the canonical test scenario.

    Timeline (ts chosen to keep strict chronological order):
      seq 1  pay__transfer_money  amount=10     → executed
      seq 2  pay__transfer_money  amount=5000   → executed   (big-rule catch)
      seq 3  pay__transfer_money  amount=60     → executed   (mid-rule catch)
      seq 4  users__delete_user   {}            → blocked
    """
    rec = Recorder(str(tmp_path / "r.db"))
    base_ts = 1_700_000_000.0
    rec.record("ses1", 1, "pay__transfer_money", {"amount": 10},
               _result("ok"), "executed", ts=base_ts)
    rec.record("ses1", 2, "pay__transfer_money", {"amount": 5000},
               _result("ok"), "executed", ts=base_ts + 1)
    rec.record("ses1", 3, "pay__transfer_money", {"amount": 60},
               _result("ok"), "executed", ts=base_ts + 2)
    rec.record("ses2", 4, "users__delete_user", {},
               None, "blocked", ts=base_ts + 3)
    return rec


# ---------------------------------------------------------------------------
# Recorder.records() tests
# ---------------------------------------------------------------------------

class TestRecorderRecords:
    def test_returns_all_rows_in_chronological_order(self, tmp_path):
        rec = _seed_recorder(tmp_path)
        rows = rec.records()
        assert len(rows) == 4
        # Chronological by (ts, seq)
        seqs = [r["seq"] for r in rows]
        assert seqs == [1, 2, 3, 4]

    def test_session_filter_returns_only_that_session(self, tmp_path):
        rec = _seed_recorder(tmp_path)
        rows = rec.records(session_id="ses2")
        assert len(rows) == 1
        assert rows[0]["tool"] == "users__delete_user"

    def test_session_filter_unknown_session_returns_empty(self, tmp_path):
        rec = _seed_recorder(tmp_path)
        assert rec.records(session_id="ghost") == []

    def test_limit_respected(self, tmp_path):
        rec = _seed_recorder(tmp_path)
        rows = rec.records(limit=2)
        assert len(rows) == 2
        # Must be the first two chronologically
        assert [r["seq"] for r in rows] == [1, 2]

    def test_limit_with_session_filter(self, tmp_path):
        rec = _seed_recorder(tmp_path)
        rows = rec.records(session_id="ses1", limit=1)
        assert len(rows) == 1 and rows[0]["seq"] == 1

    def test_rows_are_plain_dicts(self, tmp_path):
        rec = _seed_recorder(tmp_path)
        for row in rec.records():
            assert isinstance(row, dict)


# ---------------------------------------------------------------------------
# backtest() tests
# ---------------------------------------------------------------------------

class TestBacktest:
    def _run(self, tmp_path) -> tuple[Recorder, dict]:
        rec = _seed_recorder(tmp_path)
        result = backtest(CANDIDATE_POLICY, rec.records())
        return rec, result

    # ---- totals ----

    def test_total_equals_evaluated_rows(self, tmp_path):
        _, result = self._run(tmp_path)
        assert result["total"] == 4

    def test_skipped_zero_when_all_args_valid(self, tmp_path):
        _, result = self._run(tmp_path)
        assert result["skipped"] == 0

    def test_counts_sum_to_total(self, tmp_path):
        _, result = self._run(tmp_path)
        assert sum(result["counts"].values()) == result["total"]

    def test_counts_distribution(self, tmp_path):
        _, result = self._run(tmp_path)
        c = result["counts"]
        # amount=10  → allow (below mid threshold)
        # amount=5000 → deny  (big rule)
        # amount=60  → approve (mid rule)
        # delete_user → allow (default, no matching rule)
        assert c["deny"] == 1
        assert c["approve"] == 1
        assert c["allow"] == 2

    # ---- would_block_executed ----

    def test_would_block_executed_has_exactly_one_entry(self, tmp_path):
        _, result = self._run(tmp_path)
        assert len(result["would_block_executed"]) == 1

    def test_would_block_executed_entry_is_the_large_transfer(self, tmp_path):
        _, result = self._run(tmp_path)
        entry = result["would_block_executed"][0]
        assert entry["tool"] == "pay__transfer_money"
        args = json.loads(entry["arguments"])
        assert args["amount"] == 5000
        assert entry["old_status"] == "executed"
        assert entry["new_action"] == "deny"
        assert entry["rule_id"] == "big"

    # ---- would_hold_executed ----

    def test_would_hold_executed_has_exactly_one_entry(self, tmp_path):
        _, result = self._run(tmp_path)
        assert len(result["would_hold_executed"]) == 1

    def test_would_hold_executed_entry_is_medium_transfer(self, tmp_path):
        _, result = self._run(tmp_path)
        entry = result["would_hold_executed"][0]
        assert entry["tool"] == "pay__transfer_money"
        args = json.loads(entry["arguments"])
        assert args["amount"] == 60
        assert entry["old_status"] == "executed"
        assert entry["new_action"] == "approve"
        assert entry["rule_id"] == "mid"

    # ---- would_allow_blocked ----

    def test_would_allow_blocked_has_exactly_one_entry(self, tmp_path):
        _, result = self._run(tmp_path)
        assert len(result["would_allow_blocked"]) == 1

    def test_would_allow_blocked_entry_is_delete_user(self, tmp_path):
        _, result = self._run(tmp_path)
        entry = result["would_allow_blocked"][0]
        assert entry["tool"] == "users__delete_user"
        assert entry["old_status"] == "blocked"
        assert entry["new_action"] == "allow"
        assert entry["rule_id"] is None  # default action — no rule matched

    # ---- entry shape ----

    def test_entry_has_required_keys(self, tmp_path):
        _, result = self._run(tmp_path)
        required = {"session_id", "seq", "tool", "arguments",
                    "old_status", "new_action", "rule_id", "reason"}
        for list_key in ("would_block_executed", "would_hold_executed",
                         "would_allow_blocked"):
            for entry in result[list_key]:
                assert required <= set(entry.keys()), (
                    f"entry in {list_key!r} missing keys: "
                    f"{required - set(entry.keys())}"
                )

    # ---- skipped path ----

    def test_skipped_incremented_for_malformed_arguments(self):
        """Directly inject a row with invalid JSON to exercise the skip path."""
        fake_row = {
            "session_id": "s1",
            "seq": 99,
            "tool": "pay__transfer_money",
            "arguments": "NOT_VALID_JSON{{{",
            "status": "executed",
            "ts": 1_700_000_000.0,
        }
        result = backtest(CANDIDATE_POLICY, [fake_row])
        assert result["skipped"] == 1
        assert result["total"] == 0

    def test_skipped_mixed_valid_and_invalid(self):
        """One valid row + one malformed: total=1, skipped=1."""
        valid_row = {
            "session_id": "s1",
            "seq": 1,
            "tool": "pay__transfer_money",
            "arguments": json.dumps({"amount": 10}),
            "status": "executed",
            "ts": 1_700_000_000.0,
        }
        bad_row = {
            "session_id": "s1",
            "seq": 2,
            "tool": "pay__transfer_money",
            "arguments": "{{bad",
            "status": "executed",
            "ts": 1_700_000_001.0,
        }
        result = backtest(CANDIDATE_POLICY, [valid_row, bad_row])
        assert result["total"] == 1
        assert result["skipped"] == 1

    # ---- executed_shadow and executed_after_approval also count ----

    def test_executed_shadow_treated_as_executed(self):
        row = {
            "session_id": "s1",
            "seq": 1,
            "tool": "pay__transfer_money",
            "arguments": json.dumps({"amount": 9999}),
            "status": "executed_shadow",
            "ts": 1_700_000_000.0,
        }
        result = backtest(CANDIDATE_POLICY, [row])
        assert len(result["would_block_executed"]) == 1
        assert result["would_block_executed"][0]["old_status"] == "executed_shadow"

    def test_executed_after_approval_treated_as_executed(self):
        row = {
            "session_id": "s1",
            "seq": 1,
            "tool": "pay__transfer_money",
            "arguments": json.dumps({"amount": 75}),
            "status": "executed_after_approval",
            "ts": 1_700_000_000.0,
        }
        result = backtest(CANDIDATE_POLICY, [row])
        assert len(result["would_hold_executed"]) == 1

    # ---- rate-limit windows replay historically ----

    def test_rate_limit_uses_historical_ts(self):
        """Rate-limit windows must honour the row ts, not wall-clock time."""
        rl_policy = {
            "default_action": "allow",
            "rules": [
                {
                    "id": "rl",
                    "tools": ["pay__transfer_money"],
                    "action": "allow",
                    "rate_limit": {"max_calls": 2, "window_seconds": 10},
                }
            ],
        }
        base = 1_700_000_000.0
        rows = [
            {"session_id": "s", "seq": i + 1, "tool": "pay__transfer_money",
             "arguments": json.dumps({"amount": 1}),
             "status": "executed", "ts": base + i}
            for i in range(3)  # 3 calls within 10 s → 3rd should be denied
        ]
        result = backtest(rl_policy, rows)
        # The 3rd call exceeds the window limit; would_block_executed has 1 entry
        assert len(result["would_block_executed"]) == 1
        assert result["would_block_executed"][0]["seq"] == 3

    # ---- empty inputs ----

    def test_empty_records_returns_zeros(self):
        result = backtest(CANDIDATE_POLICY, [])
        assert result["total"] == 0
        assert result["skipped"] == 0
        assert result["counts"] == {"allow": 0, "approve": 0, "deny": 0}
        assert result["would_block_executed"] == []
        assert result["would_hold_executed"] == []
        assert result["would_allow_blocked"] == []
