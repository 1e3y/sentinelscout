from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient


def test_correlation_request_id_behavior(client):
    response = client.get("/health", headers={"X-Request-ID": "test-req-123"})
    assert response.status_code == 200
    assert response.headers.get("X-Request-ID") == "test-req-123"

    generated = client.get("/health")
    assert generated.headers.get("X-Request-ID")
    assert generated.headers["X-Request-ID"] != "test-req-123"


def test_api_errors_do_not_expose_stack_traces(client):
    response = client.get("/v1/targets")
    assert response.status_code == 401
    body = response.json()
    assert "error" in body
    assert body["error"]["code"] == "unauthorized"
    assert "request_id" in body["error"]
    assert "Traceback" not in response.text
    assert "sqlalchemy" not in response.text.lower()


def test_unhandled_errors_are_sanitized(client):
    @client.app.get("/v1/__boom__")
    def _boom():
        raise RuntimeError("secret filesystem /var/lib/postgresql/data")

    # TestClient re-raises server exceptions by default; assert the HTTP body instead.
    with TestClient(client.app, raise_server_exceptions=False) as raw:
        response = raw.get("/v1/__boom__")
    assert response.status_code == 500
    body = response.json()
    assert body["error"]["code"] == "internal_error"
    assert "RuntimeError" not in response.text
    assert "/var/lib/postgresql" not in response.text
    assert "Traceback" not in response.text


def test_required_security_headers_exist_in_web_config():
    path = (
        Path(__file__).resolve().parents[2]
        / "web"
        / "lib"
        / "security-headers.ts"
    )
    text = path.read_text(encoding="utf-8")
    for name in (
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "X-Frame-Options",
    ):
        assert name in text
    assert "clerk.accounts.dev" in text
    assert "unsafe-inline" in text
