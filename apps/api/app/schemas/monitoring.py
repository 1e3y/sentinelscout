from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

AutoDeliverExpiresIn = Literal["24h", "7d", "30d"]


class UpsertMonitoringRequest(BaseModel):
    enabled: bool
    frequency: str = Field(pattern="^(daily|weekly)$")
    # None means omitted: preserve the persisted value (or false when creating).
    # Do not default to False — that would silently disable auto reports for
    # older clients that only send enabled + frequency.
    auto_generate_reports: bool | None = None
    auto_deliver_reports: bool | None = None
    auto_deliver_expires_in: AutoDeliverExpiresIn | None = None
    recipients: list[str] | None = None


class MonitoringConfigurationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID | None = None
    organization_id: UUID
    target_id: UUID
    enabled: bool
    auto_generate_reports: bool = False
    auto_deliver_reports: bool = False
    auto_deliver_expires_in: AutoDeliverExpiresIn = "7d"
    recipient_count: int = 0
    recipients: list[str] | None = None
    email_delivery_enabled: bool = False
    frequency: str
    next_run_at: datetime | None = None
    last_run_at: datetime | None = None
    disabled_reason: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None
    latest_changes: dict[str, Any] = Field(default_factory=dict)
