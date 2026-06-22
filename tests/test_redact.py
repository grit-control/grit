import pytest

from grit.redact import Redactor


def test_email_and_key():
    r = Redactor(enabled=["email", "api_key"])
    out = r.redact_text("contact jane.doe@acme.com key sk-abcdefghij0123456789")
    assert "jane.doe@acme.com" not in out
    assert "sk-abcdefghij0123456789" not in out
    assert "[REDACTED:email]" in out and "[REDACTED:api_key]" in out


def test_nested_structure():
    r = Redactor(enabled=["email"])
    obj = {"content": [{"type": "text", "text": "mail bob@x.io now"}],
           "isError": False, "count": 3}
    out = r.redact(obj)
    assert out["content"][0]["text"] == "mail [REDACTED:email] now"
    assert out["count"] == 3 and out["isError"] is False


def test_custom_pattern():
    r = Redactor(enabled=[], custom={"ticket": r"TICKET-\d{4}"})
    assert r.redact_text("see TICKET-1234") == "see [REDACTED:ticket]"


def test_aws_and_ssn():
    r = Redactor()
    out = r.redact_text("key AKIAIOSFODNN7EXAMPLE ssn 123-45-6789")
    assert "AKIA" not in out and "123-45-6789" not in out


def test_unknown_builtin_rejected():
    with pytest.raises(ValueError):
        Redactor(enabled=["nope"])
