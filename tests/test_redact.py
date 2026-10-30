from __future__ import annotations

from mcp_gatekeeper.redact import Redactor

# Fake secrets are assembled at runtime so no secret-shaped string sits in the source.
FAKE_OPENAI = "sk-" + "test" + "x" * 24
FAKE_AWS = "AKIA" + "EXAMPLE" + "0" * 9


def test_secret_keys_are_masked_whole():
    out, found = Redactor().redact(
        {"api_key": "anything", "Password": "hunter2", "nested": {"client-secret": "s"}, "user": "ok"}
    )
    assert out == {
        "api_key": "[REDACTED]",
        "Password": "[REDACTED]",
        "nested": {"client-secret": "[REDACTED]"},
        "user": "ok",
    }
    assert found == ["secret-key"]


def test_api_keys_and_bearer_tokens_in_text():
    text = f"use {FAKE_OPENAI} or {FAKE_AWS}; header Authorization: Bearer abc.def-123456"
    out, found = Redactor().redact({"note": text})
    assert FAKE_OPENAI not in out["note"] and FAKE_AWS not in out["note"]
    assert "abc.def-123456" not in out["note"]
    assert set(found) == {"api-key", "token"}


def test_email_phone_and_ssn():
    out, found = Redactor().redact(["mail jane@example.com", "call +44 20 7946 0958", "ssn 078-05-1120"])
    assert out == ["mail [REDACTED:email]", "call [REDACTED:phone]", "ssn [REDACTED:ssn]"]
    assert found == ["email", "phone", "ssn"]


def test_iban_is_checked_with_mod97():
    out, found = Redactor().redact({"iban": "GB82 WEST 1234 5698 7654 32", "ref": "GB00 WEST 1234 5698 7654 32"})
    assert out["iban"] == "[REDACTED:iban …5432]"
    assert out["ref"] == "GB00 WEST 1234 5698 7654 32"  # fails the checksum, left alone
    assert found == ["iban"]


def test_card_numbers_need_a_valid_luhn_checksum():
    out, _ = Redactor().redact(
        {"card": "4111 1111 1111 1111", "order": "4111 1111 1111 1112", "as_int": 4111111111111111, "amount": 2500}
    )
    assert out["card"] == "[REDACTED:card …1111]"
    assert out["order"] == "4111 1111 1111 1112"
    assert out["as_int"] == "[REDACTED:card …1111]"
    assert out["amount"] == 2500


def test_private_key_and_jwt():
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIfake\n-----END RSA PRIVATE KEY-----"
    jwt = "eyJhbGciOi.eyJzdWIiOi.c2lnbmF0dXJl"
    out, found = Redactor().redact({"k": pem, "t": jwt})
    assert out == {"k": "[REDACTED:private-key]", "t": "[REDACTED:jwt]"}
    assert found == ["jwt", "private-key"]


def test_policy_can_add_keys_and_patterns():
    r = Redactor(extra_keys=["account_holder_dob"], extra_patterns=[r"CUST-\d{6}"])
    out, found = r.redact({"account_holder_dob": "1990-01-01", "note": "customer CUST-123456"})
    assert out == {"account_holder_dob": "[REDACTED]", "note": "customer [REDACTED:custom]"}
    assert found == ["custom", "secret-key"]


def test_input_is_not_modified():
    args = {"password": "x", "list": ["jane@example.com"]}
    Redactor().redact(args)
    assert args == {"password": "x", "list": ["jane@example.com"]}
