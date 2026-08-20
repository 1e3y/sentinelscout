from __future__ import annotations

import httpx

from app.services.email_provider import EmailSendRequest, ResendEmailProvider


def _request(key: str = "11111111-1111-1111-1111-111111111111") -> EmailSendRequest:
    return EmailSendRequest(
        idempotency_key=key,
        from_email="Scout Alerts <alerts@example.test>",
        to_email="alice@example.com",
        subject="Scout alert",
        text_body="body",
        tags=(("alert_id", "abc"),),
    )


def test_resend_retry_reuses_idempotency_key_and_payload():
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"id": "re_123"})

    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport)
    provider = ResendEmailProvider(api_key="re_test", client=client)
    first = _request()
    second = _request()
    assert provider.send(first).outcome == "delivered"
    assert provider.send(second).outcome == "delivered"
    assert len(seen) == 2
    assert seen[0].headers["Idempotency-Key"] == first.idempotency_key
    assert seen[1].headers["Idempotency-Key"] == first.idempotency_key
    assert seen[0].content == seen[1].content


def test_resend_concurrent_idempotent_request_is_retryable():
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            409, json={"name": "concurrent_idempotent_requests", "message": "in progress"}
        )

    provider = ResendEmailProvider(
        api_key="re_test", client=httpx.Client(transport=httpx.MockTransport(handler))
    )
    result = provider.send(_request())
    assert result.outcome == "retryable"
    assert result.error_code == "provider_idempotency_in_progress"
    assert "in progress" not in (result.error_message or "")


def test_resend_payload_mismatch_is_permanent():
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            409, json={"name": "invalid_idempotent_request", "message": "raw dump"}
        )

    provider = ResendEmailProvider(
        api_key="re_test", client=httpx.Client(transport=httpx.MockTransport(handler))
    )
    result = provider.send(_request())
    assert result.outcome == "permanent"
    assert result.error_code == "provider_idempotency_payload_mismatch"
    assert result.error_message == "provider_idempotency_payload_mismatch"
