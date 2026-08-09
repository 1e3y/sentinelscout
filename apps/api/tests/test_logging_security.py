from __future__ import annotations

import json
import logging

from app.core.logging import StructuredFormatter, redact_mapping, redact_value
from app.core.middleware import resolve_request_id


def test_secrets_are_redacted_from_logs():
    payload = redact_mapping(
        {
            "authorization": "Bearer clerk_secret_token",
            "cookie": "session=abc",
            "api_key": "k-secret",
            "txt_value": "scout-verify=supersecret",
            "domain": "safe.example",
            "authorization_status": "verified",
        }
    )
    assert payload["authorization"] == "[REDACTED]"
    assert payload["cookie"] == "[REDACTED]"
    assert payload["api_key"] == "[REDACTED]"
    assert payload["txt_value"] == "[REDACTED]"
    assert payload["domain"] == "safe.example"
    assert payload["authorization_status"] == "verified"
    assert "supersecret" not in redact_value("token scout-verify=supersecret Bearer abc.def")


def test_structured_formatter_redacts_message_fields():
    record = logging.LogRecord(
        name="scout.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="auth Authorization=Bearer secret-token cookie=abc",
        args=(),
        exc_info=None,
    )
    record.event = "test.event"
    record.authorization = "Bearer secret-token"
    formatted = StructuredFormatter().format(record)
    data = json.loads(formatted)
    assert data["event"] == "test.event"
    assert "secret-token" not in formatted
    assert data["fields"]["authorization"] == "[REDACTED]"


def test_request_id_generation_and_acceptance():
    assert resolve_request_id("req-ABC_123") == "req-ABC_123"
    generated = resolve_request_id("not safe!!!")
    assert generated
    assert " " not in generated
