"""Customer-facing follow-up reminder delivery status (Milestone 35)."""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

# Single customer-facing status vocabulary (Correction 3).
ReminderCustomerState = Literal[
    "disabled",
    "not_applicable",
    "generation_unavailable",
    "scheduled_for_future",
    "awaiting_discovery",
    "pending",
    "processing",
    "retrying",
    "delivered",
    "skipped",
    "dead",
]

ReminderJobCustomerState = Literal[
    "pending",
    "processing",
    "retrying",
    "delivered",
    "skipped",
    "dead",
]

SafeReasonCode = Literal[
    "finding_resolved",
    "owner_changed",
    "due_changed",
    "follow_up_generation_changed",
    "assignee_not_current_member",
    "recipient_no_deliverable_email",
    "recipient_changed",
    "staging_destination_not_allowed",
    "missing_delivery_snapshot",
    "reminders_disabled",
    "identity_provider_unavailable",
    "max_attempts_exceeded",
    "delivery_temporarily_unavailable",
    "delivery_issue",
]


class ReminderOwnerPresentation(BaseModel):
    """Current User.name is presentation metadata, not a historical snapshot."""

    model_config = ConfigDict(extra="forbid")

    user_id: UUID
    display_name: str | None = None


class ReminderCurrentGeneration(BaseModel):
    model_config = ConfigDict(extra="forbid")

    due_at: datetime
    owner: ReminderOwnerPresentation


class ReminderDeliveryFacts(BaseModel):
    model_config = ConfigDict(extra="forbid")

    safe_reason_code: SafeReasonCode | None = None
    safe_reason_label: str | None = None
    created_at: datetime
    delivered_at: datetime | None = None


class FindingFollowUpReminderStatusResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: UUID
    reminders_enabled: bool
    email_delivery_enabled: bool
    state: ReminderCustomerState
    current_generation: ReminderCurrentGeneration | None = None
    reminder: ReminderDeliveryFacts | None = None


class FindingFollowUpReminderHistoryItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reminder_kind: Literal["due"]
    due_at: datetime
    owner: ReminderOwnerPresentation | None = None
    state: ReminderJobCustomerState
    safe_reason_code: SafeReasonCode | None = None
    safe_reason_label: str | None = None
    created_at: datetime
    delivered_at: datetime | None = None


class FindingFollowUpReminderHistoryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: UUID
    page_size: int
    next_cursor: str | None = None
    items: list[FindingFollowUpReminderHistoryItem] = Field(default_factory=list)
