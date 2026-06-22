"""Incident-replay artifact: headline selection, audit correlation, the
secret-redaction safety property, the embedded open format, and CLI wiring."""
import json

import pytest

from grit.audit import AuditLog
from grit.incident import FORMAT, build_artifact, render_html
from grit.recorder import Recorder

SECRET = "sk-ABCDEF0123456789XYZ"  # matches the api_key redaction pattern


def _result(text):
    return {"content": [{"type": "text", "text": text}], "isError": False}


def _event(rec, audit, session, seq, tool, args, status, *, failure_class=None,
           decision="allow", reason=None, risk_score=None, ts=1000.0):
    """Seed one call into both the recorder and the (matching) audit row,
    sharing tool/args/status/failure_class/ts so match_call reconnects them."""
    result = _result("ok") if status.startswith("executed") else None
    rec.record(session, seq, tool, args, result, status,
               failure_class=failure_class, ts=ts)
    audit.record(tool, args, decision, f"{decision}-rule", reason, status,
                 risk_score=risk_score, failure_class=failure_class, ts=ts)


@pytest.fixture
def seeded(tmp_path):
    db = str(tmp_path / "m.db")
    rec, audit = Recorder(db), AuditLog(db)
    # seq1: a policy block (severity 4)
    _event(rec, audit, "s1", 1, "pay__transfer", {"amount": 5000}, "blocked",
           failure_class="policy_block", decision="deny",
           reason="transfers over $1000 are forbidden", risk_score=20, ts=1000.0)
    # seq2: a flow-guard catch (severity 6) — and the args hold a real secret
    _event(rec, audit, "s1", 2, "mail__send", {"body": f"key {SECRET}"},
           "blocked", failure_class="flow_block", decision="deny",
           reason=f"flow guard: arguments carry a secret from db toward an "
                  f"external sink", risk_score=None, ts=1001.0)
    # seq3: an ordinary executed call
    _event(rec, audit, "s1", 3, "docs__search", {"q": "hi"}, "executed",
           decision="allow", ts=1002.0)
    return db, rec, audit


def test_headline_picks_most_severe_catch(seeded):
    db, rec, audit = seeded
    a = build_artifact(rec, audit, "s1")
    assert a["step"] == 2 and a["total_steps"] == 3          # flow > policy
    assert a["failure_class"] == "flow_block"
    assert a["caught"] is True
    assert a["category"].startswith("Flow guard")
    assert "flow guard" in a["reason"]
    assert a["replay_command"] == "grit replay s1"
    assert a["audit_hash"]                                    # correlated
    assert a["format"] == FORMAT


def test_arguments_are_redacted_in_artifact_and_html(seeded):
    db, rec, audit = seeded
    a = build_artifact(rec, audit, "s1")           # the flow-block event
    blob = json.dumps(a)
    assert SECRET not in blob
    assert "[REDACTED:api_key]" in blob
    html = render_html(a)
    assert SECRET not in html                       # never leaks in the card
    assert "[REDACTED:api_key]" in html


def test_specific_step_and_risk_correlation(seeded):
    db, rec, audit = seeded
    a = build_artifact(rec, audit, "s1", seq=1)
    assert a["step"] == 1 and a["failure_class"] == "policy_block"
    assert a["risk_score"] == 20
    assert a["decision"] == "deny"


def test_html_is_self_contained_and_embeds_open_format(seeded):
    db, rec, audit = seeded
    a = build_artifact(rec, audit, "s1")
    html = render_html(a)
    assert "http://" not in html and "https://" not in html   # no external refs
    assert "CAUGHT" in html
    marker = "id='grit-incident'>"
    start = html.index(marker) + len(marker)
    embedded = html[start:html.index("</script>", start)]
    parsed = json.loads(embedded)
    assert parsed["step"] == a["step"] and parsed["tool"] == a["tool"]
    assert parsed["format"] == FORMAT


def test_observe_mode_shadow_is_a_would_have_caught(tmp_path):
    db = str(tmp_path / "obs.db")
    rec, audit = Recorder(db), AuditLog(db)
    _event(rec, audit, "obs", 1, "pay__transfer", {"amount": 99},
           "executed_shadow", decision="deny",
           reason="would block: transfer needs approval", risk_score=70)
    a = build_artifact(rec, audit, "obs")
    assert a["caught"] is True
    assert a["outcome"] == "executed_shadow"
    assert a["category"].startswith("Observe mode")
    assert "WOULD HAVE BEEN CAUGHT" in render_html(a)


def test_clean_session_falls_back_to_last_call(tmp_path):
    db = str(tmp_path / "clean.db")
    rec, audit = Recorder(db), AuditLog(db)
    _event(rec, audit, "c", 1, "docs__search", {"q": "a"}, "executed", ts=1.0)
    _event(rec, audit, "c", 2, "docs__search", {"q": "b"}, "executed", ts=2.0)
    a = build_artifact(rec, audit, "c")
    assert a["caught"] is False
    assert a["step"] == 2
    assert a["category"] == "Executed: no enforcement action"


def test_unknown_session_and_step_raise(seeded):
    db, rec, audit = seeded
    with pytest.raises(ValueError):
        build_artifact(rec, audit, "ghost")
    with pytest.raises(ValueError):
        build_artifact(rec, audit, "s1", seq=999)


def test_cli_incident_card_json(seeded, capsys):
    db, rec, audit = seeded
    from grit.cli import main
    rc = main(["incident-card", "s1", "--db", db, "--json"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["format"] == FORMAT and data["session"] == "s1"
    assert data["step"] == 2
