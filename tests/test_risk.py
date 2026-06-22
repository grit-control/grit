from grit.audit import AuditLog
from grit.risk import RiskEngine


def test_novelty_then_learned():
    e = RiskEngine()
    first = e.assess("crm__lookup", {"q": "x"})
    assert any("first ever" in f for f in first.factors)
    e.observe("crm__lookup", {"q": "x"})
    second = e.assess("crm__lookup", {"q": "y"})
    assert not any("first ever" in f for f in second.factors)
    assert second.score < first.score


def test_destructive_vs_read():
    e = RiskEngine()
    e.observe("db__drop_table", {})
    e.observe("db__read_rows", {})
    assert e.assess("db__drop_table", {}).score > e.assess("db__read_rows", {}).score
    assert any("destructive" in f for f in e.assess("db__drop_table", {}).factors)


def test_numeric_anomaly():
    e = RiskEngine()
    for amount in (12, 14, 13, 15, 12, 13):
        e.observe("pay__transfer", {"amount": amount})
    normal = e.assess("pay__transfer", {"amount": 14})
    spike = e.assess("pay__transfer", {"amount": 490})
    assert not any("deviates" in f for f in normal.factors)
    assert any("deviates" in f for f in spike.factors)
    assert spike.score >= normal.score + 35


def test_anomaly_needs_baseline():
    e = RiskEngine()
    e.observe("pay__transfer", {"amount": 10})  # only 1 observation
    out = e.assess("pay__transfer", {"amount": 99999})
    assert not any("deviates" in f for f in out.factors)


def test_secrets_in_arguments():
    e = RiskEngine()
    e.observe("mail__send", {})
    clean = e.assess("mail__send", {"body": "see you tomorrow"})
    dirty = e.assess("mail__send",
                     {"body": "key: sk-live-a1b2c3d4e5f6g7h8i9j0"})
    assert any("secret" in f for f in dirty.factors)
    assert dirty.score > clean.score


def test_email_in_args_is_not_a_secret():
    e = RiskEngine()
    e.observe("mail__send", {})
    out = e.assess("mail__send", {"to": "bob@company.com"})
    assert not any("secret" in f for f in out.factors)


def test_sensitive_targets():
    e = RiskEngine()
    e.observe("fs__read", {})
    out = e.assess("fs__read", {"path": "/etc/passwd"})
    assert any("sensitive" in f for f in out.factors)


def test_velocity_burst():
    e = RiskEngine()
    now = 1000.0
    for i in range(12):
        e.observe("api__fetch", {"u": i}, ts=now + i)
    burst = e.assess("api__fetch", {"u": 99}, now=now + 12)
    assert any("burst" in f for f in burst.factors)
    calm = e.assess("api__fetch", {"u": 99}, now=now + 5000)
    assert not any("burst" in f for f in calm.factors)


def test_score_clipped_and_levels():
    e = RiskEngine()
    monster = e.assess("prod__delete_all", {
        "path": "/etc/secrets", "note": "sk-live-a1b2c3d4e5f6g7h8i9j0"})
    assert monster.score <= 100
    assert monster.level in ("high", "critical")
    assert e.assess("calm__read", {}).level in ("low", "medium")


def test_warm_start_from_audit(tmp_path):
    db = str(tmp_path / "a.db")
    audit = AuditLog(db)
    for amount in (10, 11, 10, 12, 11, 10):
        audit.record("pay__transfer", {"amount": amount}, "allow", "r",
                     None, "executed", 5)
    audit.record("evil__tool", {"amount": 9}, "deny", "r", None, "blocked")
    e = RiskEngine(audit=audit)
    # learned baseline from executed rows -> anomaly detected
    spike = e.assess("pay__transfer", {"amount": 400})
    assert any("deviates" in f for f in spike.factors)
    # blocked rows must NOT train the engine
    assert any("first ever" in f for f in e.assess("evil__tool", {}).factors)


def test_summary_format():
    e = RiskEngine()
    out = e.assess("x__delete", {})
    assert "risk" in out.summary() and "/100" in out.summary()
