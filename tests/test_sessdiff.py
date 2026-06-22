"""Tests for grit.sessdiff — behavioral diff between two recorded sessions."""
import time

import pytest

from grit.recorder import Recorder
from grit.sessdiff import diff_sessions


def _result(text: str) -> dict:
    return {"content": [{"type": "text", "text": text}], "isError": False}


def _seed(rec: Recorder, session_id: str, calls: list[tuple]) -> None:
    """Insert a sequence of (seq, tool, arguments, result, status, failure_class)
    tuples into the recorder under *session_id*."""
    for seq, tool, arguments, result, status, *rest in calls:
        failure_class = rest[0] if rest else None
        rec.record(session_id, seq, tool, arguments, result, status,
                   failure_class=failure_class, ts=time.time())


# ---- test 1: identical sessions ----------------------------------------

def test_identical_sessions(tmp_path):
    rec = Recorder(str(tmp_path / "r.db"))
    calls = [
        (1, "fs__read",   {"path": "/a"},  _result("hello"),  "executed"),
        (2, "fs__write",  {"path": "/b"},  _result("ok"),     "executed"),
        (3, "net__fetch", {"url": "http"}, _result("200 OK"), "executed"),
    ]
    _seed(rec, "a", calls)
    _seed(rec, "b", calls)

    result = diff_sessions(rec.trace("a"), rec.trace("b"))

    assert result["identical"] is True
    assert result["first_divergence"] is None
    assert result["outcome_changes"] == []
    assert result["common_prefix"] == 3
    assert result["a_calls"] == 3
    assert result["b_calls"] == 3


# ---- test 2: different arguments at step 2 -----------------------------

def test_different_arguments_step2(tmp_path):
    rec = Recorder(str(tmp_path / "r.db"))
    _seed(rec, "a", [
        (1, "fs__read", {"path": "/same"}, _result("x"), "executed"),
        (2, "fs__read", {"path": "/path-a"}, _result("y"), "executed"),
        (3, "fs__read", {"path": "/same2"}, _result("z"), "executed"),
    ])
    _seed(rec, "b", [
        (1, "fs__read", {"path": "/same"}, _result("x"), "executed"),
        (2, "fs__read", {"path": "/path-b"}, _result("y"), "executed"),
        (3, "fs__read", {"path": "/same2"}, _result("z"), "executed"),
    ])

    result = diff_sessions(rec.trace("a"), rec.trace("b"))

    assert result["identical"] is False
    assert result["first_divergence"] is not None
    assert result["first_divergence"]["kind"] == "different_arguments"
    assert result["first_divergence"]["step"] == 2
    assert result["first_divergence"]["tool"] == "fs__read"
    assert result["common_prefix"] == 1


# ---- test 3: different tool at step 1 ----------------------------------

def test_different_tool_step1(tmp_path):
    rec = Recorder(str(tmp_path / "r.db"))
    _seed(rec, "a", [
        (1, "fs__read",  {"path": "/x"}, _result("data"), "executed"),
        (2, "net__fetch", {"url": "u"},  _result("resp"), "executed"),
    ])
    _seed(rec, "b", [
        (1, "net__fetch", {"url": "u"}, _result("resp"), "executed"),
        (2, "fs__read",   {"path": "/x"}, _result("data"), "executed"),
    ])

    result = diff_sessions(rec.trace("a"), rec.trace("b"))

    assert result["first_divergence"]["kind"] == "different_tool"
    assert result["first_divergence"]["step"] == 1
    assert result["first_divergence"]["a_tool"] == "fs__read"
    assert result["first_divergence"]["b_tool"] == "net__fetch"
    assert result["common_prefix"] == 0


# ---- test 4: same calls, different outcome at step 2 -------------------

def test_different_outcome_step2(tmp_path):
    rec = Recorder(str(tmp_path / "r.db"))
    args = {"path": "/shared"}
    _seed(rec, "a", [
        (1, "fs__read", args, _result("ok"), "executed"),
        (2, "fs__read", args, _result("ok"), "executed"),
        (3, "fs__read", args, _result("ok"), "executed"),
    ])
    _seed(rec, "b", [
        (1, "fs__read", args, _result("ok"),  "executed"),
        (2, "fs__read", args, None,           "error",    "upstream_error"),
        (3, "fs__read", args, _result("ok"),  "executed"),
    ])

    result = diff_sessions(rec.trace("a"), rec.trace("b"))

    assert result["identical"] is False
    assert result["first_divergence"] is None   # no structural divergence
    assert len(result["outcome_changes"]) == 1
    change = result["outcome_changes"][0]
    assert change["kind"] == "different_outcome"
    assert change["step"] == 2
    assert change["tool"] == "fs__read"
    assert change["a_status"] == "executed"
    assert change["b_status"] == "error"
    assert change["a_failure"] is None
    assert change["b_failure"] == "upstream_error"


# ---- test 5: B has extra 4th call (extra_calls) ------------------------

def test_extra_calls_in_b(tmp_path):
    rec = Recorder(str(tmp_path / "r.db"))
    shared = [
        (1, "fs__read",   {"path": "/a"}, _result("1"), "executed"),
        (2, "net__fetch", {"url": "http"}, _result("2"), "executed"),
        (3, "fs__write",  {"path": "/c"}, _result("3"), "executed"),
    ]
    _seed(rec, "a", shared)
    _seed(rec, "b", shared + [(4, "fs__read", {"path": "/d"}, _result("4"), "executed")])

    result = diff_sessions(rec.trace("a"), rec.trace("b"))

    assert result["first_divergence"] is not None
    assert result["first_divergence"]["kind"] == "extra_calls"
    assert result["first_divergence"]["step"] == 4
    assert result["first_divergence"]["a_calls"] == 3
    assert result["first_divergence"]["b_calls"] == 4
    assert result["common_prefix"] == 3
    assert result["identical"] is False


# ---- test 6: same call/status but different result payload -------------

def test_different_result_payload(tmp_path):
    rec = Recorder(str(tmp_path / "r.db"))
    args = {"query": "weather"}
    _seed(rec, "a", [
        (1, "search__query", args, _result("sunny"),  "executed"),
        (2, "search__query", args, _result("cloudy"), "executed"),
    ])
    _seed(rec, "b", [
        (1, "search__query", args, _result("sunny"), "executed"),
        (2, "search__query", args, _result("rainy"),  "executed"),
    ])

    result = diff_sessions(rec.trace("a"), rec.trace("b"))

    assert result["identical"] is False
    assert result["first_divergence"] is None
    assert len(result["outcome_changes"]) == 1
    change = result["outcome_changes"][0]
    assert change["kind"] == "different_result"
    assert change["step"] == 2
    assert change["tool"] == "search__query"


# ---- token totals are computed -------------------------------------------

def test_token_totals_present(tmp_path):
    rec = Recorder(str(tmp_path / "r.db"))
    args = {"q": "x"}
    _seed(rec, "a", [(1, "t__x", args, _result("hello world"), "executed")])
    _seed(rec, "b", [(1, "t__x", args, _result("hi"),          "executed")])

    result = diff_sessions(rec.trace("a"), rec.trace("b"))

    assert result["a_tokens"] > 0
    assert result["b_tokens"] > 0
