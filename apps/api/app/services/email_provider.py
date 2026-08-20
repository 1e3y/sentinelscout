"""Vendor-neutral email delivery. Resend is the one production adapter."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol

import httpx

from app.core.config import Settings

EmailOutcome = Literal["delivered", "retryable", "permanent"]

RESEND_EMAILS_URL = "https://api.resend.com/emails"


@dataclass(frozen=True)
class EmailSendRequest:
    idempotency_key: str
    from_email: str
    to_email: str
    subject: str
    text_body: str
    tags: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class EmailSendResult:
    outcome: EmailOutcome
    error_code: str | None = None
    error_message: str | None = None


class EmailProvider(Protocol):
    def send(self, request: EmailSendRequest) -> EmailSendResult: ...


class FakeEmailProvider:
    """In-memory provider for tests, benchmark, and local development."""

    def __init__(self) -> None:
        self.requests: list[EmailSendRequest] = []
        self.next_result: EmailSendResult | None = None

    def send(self, request: EmailSendRequest) -> EmailSendResult:
        self.requests.append(request)
        if self.next_result is not None:
            return self.next_result
        return EmailSendResult(outcome="delivered")


class ResendEmailProvider:
    """Resend HTTP adapter. Domain objects never mention Resend."""

    def __init__(
        self,
        *,
        api_key: str,
        timeout_seconds: float = 15.0,
        client: httpx.Client | None = None,
    ) -> None:
        self._api_key = api_key
        self._owns_client = client is None
        self._client = client or httpx.Client(timeout=timeout_seconds)

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def send(self, request: EmailSendRequest) -> EmailSendResult:
        payload = {
            "from": request.from_email,
            "to": [request.to_email],
            "subject": request.subject,
            "text": request.text_body,
        }
        if request.tags:
            payload["tags"] = [{"name": name, "value": value} for name, value in request.tags]
        try:
            response = self._client.post(
                RESEND_EMAILS_URL,
                headers={
                    "Authorization": f"Bearer {self._api_key}",
                    "Content-Type": "application/json",
                    "Idempotency-Key": request.idempotency_key,
                },
                json=payload,
            )
        except httpx.TimeoutException:
            return EmailSendResult(
                outcome="retryable",
                error_code="provider_timeout",
                error_message="provider_timeout",
            )
        except httpx.HTTPError:
            return EmailSendResult(
                outcome="retryable",
                error_code="provider_unavailable",
                error_message="provider_unavailable",
            )
        return _map_resend_response(response.status_code, _resend_error_name(response))


def _resend_error_name(response: httpx.Response) -> str | None:
    if response.status_code < 400:
        return None
    try:
        body = response.json()
    except ValueError:
        return None
    if not isinstance(body, dict):
        return None
    name = body.get("name")
    if isinstance(name, str) and name.strip():
        return name.strip()
    error = body.get("error")
    if isinstance(error, dict):
        nested = error.get("name")
        if isinstance(nested, str) and nested.strip():
            return nested.strip()
    return None


def _map_resend_response(status_code: int, error_name: str | None) -> EmailSendResult:
    if status_code < 400:
        return EmailSendResult(outcome="delivered")
    if error_name == "concurrent_idempotent_requests":
        return EmailSendResult(
            outcome="retryable",
            error_code="provider_idempotency_in_progress",
            error_message="provider_idempotency_in_progress",
        )
    if error_name == "invalid_idempotent_request":
        return EmailSendResult(
            outcome="permanent",
            error_code="provider_idempotency_payload_mismatch",
            error_message="provider_idempotency_payload_mismatch",
        )
    if status_code in {408, 429} or status_code >= 500:
        return EmailSendResult(
            outcome="retryable",
            error_code="provider_retryable",
            error_message="provider_retryable",
        )
    return EmailSendResult(
        outcome="permanent",
        error_code="provider_permanent_failure",
        error_message="provider_permanent_failure",
    )


def build_email_provider(settings: Settings, *, client: httpx.Client | None = None) -> EmailProvider:
    if settings.environment == "test" or settings.email_provider == "fake":
        return FakeEmailProvider()
    return ResendEmailProvider(
        api_key=settings.email_api_key,
        timeout_seconds=float(settings.notification_provider_timeout_seconds),
        client=client,
    )
