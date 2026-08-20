"""Deterministic Alert email copy, frozen at outbox insert time."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from app.models.alert import Alert

DELIVERY_SNAPSHOT_VERSION = 1

_CATEGORY_LABELS = {
    "security_regression": "security regression",
    "coverage_degradation": "coverage degradation",
    "informational": "informational",
}

_PRIORITY_LABELS = {
    "medium": "medium",
    "low": "low",
    "info": "info",
}

SECURITY_REGRESSION_FOOTER = (
    "This is a Scout monitoring signal from supported checks. "
    "It is not a complete security verdict."
)
GENERIC_FOOTER = "This is a Scout monitoring signal from supported checks."


def destination_key_for_user(user_id: UUID) -> str:
    return f"user:{user_id}"


def dashboard_url(frontend_url: str) -> str:
    return f"{frontend_url.rstrip('/')}/dashboard"


def _iso(value: datetime | None) -> str:
    if value is None:
        return "unknown"
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


def build_email_subject(*, organization_name: str, alert: Alert) -> str:
    return f"Scout alert: {alert.title} ({organization_name})"


def build_email_text(
    *,
    organization_name: str,
    target_domain: str,
    alert: Alert,
    operation_time: datetime | None,
    dashboard_url_value: str,
) -> str:
    footer = (
        SECURITY_REGRESSION_FOOTER
        if alert.category == "security_regression"
        else GENERIC_FOOTER
    )
    lines = [
        "Scout",
        "",
        f"Organization: {organization_name}",
        f"Target: {target_domain}",
        f"Title: {alert.title}",
        f"Category: {_CATEGORY_LABELS.get(alert.category, alert.category)}",
        f"Priority: {_PRIORITY_LABELS.get(alert.priority, alert.priority)}",
        "",
        alert.summary,
        "",
        f"Originating operation time: {_iso(operation_time)}",
        "",
        "Authenticated dashboard:",
        dashboard_url_value,
        "",
        footer,
    ]
    return "\n".join(lines)


def freeze_delivery_snapshot(
    *,
    recipient_user_id: UUID,
    recipient_email: str,
    from_email: str,
    subject: str,
    text_body: str,
    dashboard_url_value: str,
    alert: Alert,
) -> dict[str, Any]:
    return {
        "schema_version": DELIVERY_SNAPSHOT_VERSION,
        "recipient_user_id": str(recipient_user_id),
        "recipient_email_snapshot": recipient_email,
        "from_email_snapshot": from_email,
        "subject_snapshot": subject,
        "text_body_snapshot": text_body,
        "dashboard_url_snapshot": dashboard_url_value,
        "tags": [
            {"name": "alert_id", "value": str(alert.id)},
            {"name": "organization_id", "value": str(alert.organization_id)},
            {"name": "category", "value": alert.category},
            {"name": "priority", "value": alert.priority},
        ],
    }
