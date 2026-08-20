from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

DISCLAIMER = (
    "Alerts are monitoring notifications. Zero alerts does not mean this "
    "application is secure."
)


class AlertDeliveryStatusResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    channel: str
    destination_key: str
    status: str
    attempt_count: int = 0
    delivered_at: datetime | str | None = None
    last_error_code: str | None = None


class AlertResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    organization_id: str
    target_id: str
    target_domain: str | None = None
    episode_id: str
    operation_id: str
    diff_summary_id: str
    alert_type: str
    category: str
    priority: str
    semantic_key: str
    title: str
    summary: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime | str | None = None
    episode_status: str | None = None
    reopened_from_episode_id: str | None = None
    last_seen_operation_id: str | None = None
    acknowledged_at: datetime | str | None = None
    acknowledged_by_user_id: str | None = None
    read_at: datetime | str | None = None
    dismissed_at: datetime | str | None = None
    deliveries: list[AlertDeliveryStatusResponse] = Field(default_factory=list)
    disclaimer: str = DISCLAIMER


class AlertSummaryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    unread_count: int
    open_episode_count: int
    visible_alert_count: int
    by_category: dict[str, int] = Field(default_factory=dict)
    disclaimer: str = DISCLAIMER
