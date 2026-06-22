import pytest

from grit.policy import ALLOW, APPROVE, DENY, PolicyEngine, PolicyError

POLICY = {
    "default_action": "deny",
    "rules": [
        {"id": "no-delete", "tools": ["*delete*"], "action": "deny",
         "reason": "destructive"},
        {"id": "big", "tools": ["pay__transfer"],
         "where": [{"path": "amount", "gt": 1000}], "action": "deny"},
        {"id": "mid", "tools": ["pay__transfer"],
         "where": [{"path": "amount", "gt": 50}], "action": "approve"},
        {"id": "internal-mail", "tools": ["mail__send"],
         "where": [{"path": "to", "not_regex": "@company\\.com$"}],
         "action": "deny"},
        {"id": "search", "tools": ["docs__search"], "action": "allow",
         "rate_limit": {"max_calls": 2, "window_seconds": 60}},
        {"id": "rest", "tools": ["*"], "action": "allow"},
    ],
}


@pytest.fixture
def engine():
    return PolicyEngine(POLICY)


def test_glob_deny(engine):
    d = engine.evaluate("fs__delete_file", {"path": "/x"})
    assert d.action == DENY and d.rule_id == "no-delete"


def test_numeric_tiers(engine):
    assert engine.evaluate("pay__transfer", {"amount": 5000}).action == DENY
    assert engine.evaluate("pay__transfer", {"amount": 200}).action == APPROVE
    assert engine.evaluate("pay__transfer", {"amount": 10}).action == ALLOW


def test_numeric_boundary(engine):
    # exactly 1000 is NOT > 1000 -> falls to approve tier
    assert engine.evaluate("pay__transfer", {"amount": 1000}).action == APPROVE
    # exactly 50 is NOT > 50 -> falls through to allow
    assert engine.evaluate("pay__transfer", {"amount": 50}).action == ALLOW


def test_not_regex(engine):
    assert engine.evaluate("mail__send", {"to": "a@evil.com"}).action == DENY
    assert engine.evaluate("mail__send", {"to": "a@company.com"}).action == ALLOW


def test_missing_path_does_not_match(engine):
    # 'amount' missing -> tier rules don't match -> allow-the-rest
    assert engine.evaluate("pay__transfer", {}).action == ALLOW


def test_rate_limit(engine):
    now = 1000.0
    assert engine.evaluate("docs__search", {"q": "a"}, now=now).action == ALLOW
    assert engine.evaluate("docs__search", {"q": "b"}, now=now + 1).action == ALLOW
    third = engine.evaluate("docs__search", {"q": "c"}, now=now + 2)
    assert third.action == DENY and "rate limit" in third.reason
    # window slides -> allowed again
    assert engine.evaluate("docs__search", {"q": "d"}, now=now + 120).action == ALLOW


def test_default_action():
    engine = PolicyEngine({"default_action": "deny", "rules": []})
    d = engine.evaluate("anything", {})
    assert d.action == DENY and d.rule_id is None


def test_first_match_wins(engine):
    # 'no-delete' precedes 'rest'
    assert engine.evaluate("docs__delete_index", {}).rule_id == "no-delete"


def test_invalid_action_rejected():
    with pytest.raises(PolicyError):
        PolicyEngine({"rules": [{"id": "x", "action": "explode"}]})


def test_nested_path():
    engine = PolicyEngine({"default_action": "deny", "rules": [
        {"id": "n", "tools": ["t"],
         "where": [{"path": "meta.user", "regex": "^admin$"}],
         "action": "allow"}]})
    assert engine.evaluate("t", {"meta": {"user": "admin"}}).action == ALLOW
    assert engine.evaluate("t", {"meta": {"user": "bob"}}).action == DENY
