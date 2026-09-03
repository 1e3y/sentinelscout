"""Organization notification delivery ledger (Milestone 36)."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.services.delivery_status import DeliveryCustomerState, DeliverySafeReasonCode

DeliveryClass = Literal["alert_email", "report_delivery", "follow_up_reminder"]

DeliveryCustomerStateLiteral = DeliveryCustomerState
DeliverySafeReasonCodeLiteral = DeliverySafeReasonCode


class DeliveryTargetRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_id: UUID
    domain: str


class OrganizationMemberRecipient(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["organization_member"] = "organization_member"
    user_id: UUID
    display_name: str | None = None


class ExternalRecipient(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["external_recipient"] = "external_recipient"


DeliveryRecipient = Annotated[
    OrganizationMemberRecipient | ExternalRecipient,
    Field(discriminator="kind"),
]


class AlertEmailDetail(BaseModel):
    model_config = ConfigDict(extra="forbid")

    delivery_class: Literal["alert_email"] = "alert_email"
    alert_id: UUID
    alert_type: str
    priority: str
    category: str


class ReportDeliveryDetail(BaseModel):
    model_config = ConfigDict(extra="forbid")

    delivery_class: Literal["report_delivery"] = "report_delivery"
    report_id: UUID
    report_version: int | None = None
    generation_origin: str | None = None


class FollowUpReminderDetail(BaseModel):
    model_config = ConfigDict(extra="forbid")

    delivery_class: Literal["follow_up_reminder"] = "follow_up_reminder"
    finding_id: UUID
    finding_title: str
    due_at: datetime


DeliveryDetail = Annotated[
    AlertEmailDetail | ReportDeliveryDetail | FollowUpReminderDetail,
    Field(discriminator="delivery_class"),
]


class NotificationDeliveryRow(BaseModel):
    model_config = ConfigDict(extra="forbid")

    delivery_class: DeliveryClass
    state: DeliveryCustomerStateLiteral
    safe_reason_code: DeliverySafeReasonCodeLiteral | None = None
    safe_reason_label: str | None = None
    created_at: datetime
    delivered_at: datetime | None = None
    target: DeliveryTargetRef | None = None
    detail: DeliveryDetail
    recipient: DeliveryRecipient | None = None


class NotificationDeliveryConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alert_email_enabled: bool
    follow_up_reminders_enabled: bool
    email_delivery_enabled: bool


class NotificationDeliveriesResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    configuration: NotificationDeliveryConfiguration
    items: list[NotificationDeliveryRow]
    next_cursor: str | None = None
