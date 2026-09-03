"""Shared delivery status / safe-reason projection (Milestones 35–36).

M35 keeps its own project_safe_reason for exact output parity.
M36 uses project_delivery_safe_reason with Correction-3 collapses.
"""

from __future__ import annotations

from typing import Literal

DeliveryCustomerState = Literal[
    "pending",
    "processing",
    "retrying",
    "delivered",
    "skipped",
    "dead",
]

DeliveryClass = Literal["alert_email", "report_delivery", "follow_up_reminder"]

DeliverySafeReasonCode = Literal[
    "recipient_unavailable",
    "recipient_changed",
    "delivery_revoked",
    "delivery_expired",
    "environment_restricted",
    "finding_resolved",
    "owner_changed",
    "due_changed",
    "follow_up_generation_changed",
    "assignee_not_current_member",
    "recipient_no_deliverable_email",
    "reminders_disabled",
    "identity_provider_unavailable",
    "delivery_temporarily_unavailable",
    "delivery_issue",
]

CUSTOMER_STATE_TO_DB_STATUS: dict[DeliveryCustomerState, str] = {
    "pending": "pending",
    "processing": "processing",
    "retrying": "failed",
    "delivered": "delivered",
    "skipped": "skipped",
    "dead": "dead",
}

_SAFE_LABELS: dict[DeliverySafeReasonCode, str] = {
    "recipient_unavailable": "The recipient is no longer available for delivery.",
    "recipient_changed": "The recipient's delivery address changed before delivery.",
    "delivery_revoked": "Delivery access was revoked before the email was sent.",
    "delivery_expired": "Delivery access expired before the email was sent.",
    "environment_restricted": "Delivery was not allowed in this environment.",
    "finding_resolved": "Finding was resolved before the reminder was sent.",
    "owner_changed": "The assigned owner changed before delivery.",
    "due_changed": "The follow-up due date changed before delivery.",
    "follow_up_generation_changed": "Follow-up details changed before delivery.",
    "assignee_not_current_member": (
        "The assignee is no longer a current organization member."
    ),
    "recipient_no_deliverable_email": (
        "The assignee has no deliverable email address."
    ),
    "reminders_disabled": "Follow-up reminders were turned off.",
    "identity_provider_unavailable": (
        "Membership or delivery-address verification is temporarily unavailable. "
        "Delivery will be retried."
    ),
    "delivery_temporarily_unavailable": (
        "Delivery is temporarily unavailable. Delivery will be retried."
    ),
    "delivery_issue": "Delivery could not be completed.",
}

# Class-specific business codes that stay specific (after rename where required).
_ALERT_BUSINESS: dict[str, DeliverySafeReasonCode] = {
    "recipient_unauthorized": "recipient_unavailable",
    "recipient_identity_changed": "recipient_changed",
}

_REPORT_BUSINESS: dict[str, DeliverySafeReasonCode] = {
    "recipient_removed": "recipient_unavailable",
    "share_revoked": "delivery_revoked",
    "share_expired": "delivery_expired",
}

_REMINDER_BUSINESS: dict[str, DeliverySafeReasonCode] = {
    "finding_resolved": "finding_resolved",
    "owner_changed": "owner_changed",
    "due_changed": "due_changed",
    "follow_up_generation_changed": "follow_up_generation_changed",
    "assignee_not_current_member": "assignee_not_current_member",
    "recipient_no_deliverable_email": "recipient_no_deliverable_email",
    "recipient_changed": "recipient_changed",
    "reminders_disabled": "reminders_disabled",
}

_INFRA_ENVIRONMENT = frozenset({"staging_destination_not_allowed"})
_INFRA_ISSUE = frozenset(
    {
        "missing_delivery_snapshot",
        "missing_encrypted_secret",
        "missing_report_delivery_secret_key",
        "decrypt_failed",
        "provider_permanent_failure",
        "max_attempts_exceeded",
        "auto_deliver_reports_disabled",
        "no_eligible_recipients",
        "report_missing",
    }
)
_INFRA_TEMPORARY_PREFIXES = ("provider_",)
_INFRA_TEMPORARY_EXACT = frozenset(
    {
        "send_error",
        "identity_provider_unavailable",  # handled specially when retrying
    }
)


def map_delivery_db_status_to_customer_state(db_status: str) -> DeliveryCustomerState:
    if db_status == "pending":
        return "pending"
    if db_status == "processing":
        return "processing"
    if db_status == "failed":
        return "retrying"
    if db_status == "delivered":
        return "delivered"
    if db_status == "skipped":
        return "skipped"
    if db_status == "dead":
        return "dead"
    return "dead"


def _business_map(delivery_class: DeliveryClass) -> dict[str, DeliverySafeReasonCode]:
    if delivery_class == "alert_email":
        return _ALERT_BUSINESS
    if delivery_class == "report_delivery":
        return _REPORT_BUSINESS
    return _REMINDER_BUSINESS


def project_delivery_safe_reason(
    *,
    delivery_class: DeliveryClass,
    customer_state: DeliveryCustomerState,
    internal_code: str | None,
) -> tuple[DeliverySafeReasonCode | None, str | None]:
    """Customer-safe reason projection for the org delivery ledger (M36).

    Never returns raw provider/staging/crypto codes.
    """
    if customer_state in {"pending", "processing", "delivered"}:
        return None, None

    code = (internal_code or "").strip() or None
    business = _business_map(delivery_class)

    if customer_state == "retrying":
        if code == "identity_provider_unavailable":
            return (
                "identity_provider_unavailable",
                _SAFE_LABELS["identity_provider_unavailable"],
            )
        if code in _INFRA_ENVIRONMENT:
            return (
                "environment_restricted",
                _SAFE_LABELS["environment_restricted"],
            )
        if code in business:
            safe = business[code]
            return safe, _SAFE_LABELS[safe]
        # send_error / provider_* / missing_* / unknown → temporary
        return (
            "delivery_temporarily_unavailable",
            _SAFE_LABELS["delivery_temporarily_unavailable"],
        )

    # skipped or dead (terminal)
    if code in _INFRA_ENVIRONMENT:
        return "environment_restricted", _SAFE_LABELS["environment_restricted"]
    if code in business:
        safe = business[code]
        return safe, _SAFE_LABELS[safe]
    if code in _INFRA_ISSUE or code is None:
        return "delivery_issue", _SAFE_LABELS["delivery_issue"]
    if code.startswith(_INFRA_TEMPORARY_PREFIXES) or code in _INFRA_TEMPORARY_EXACT:
        return "delivery_issue", _SAFE_LABELS["delivery_issue"]
    return "delivery_issue", _SAFE_LABELS["delivery_issue"]
