from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class UpsertMonitoringRequest(BaseModel):
    enabled: bool
    frequency: str = Field(pattern="^(daily|weekly)$")


class MonitoringConfigurationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID | None = None
    organization_id: UUID
    target_id: UUID
    enabled: bool
    frequency: str
    next_run_at: datetime | None = None
    last_run_at: datetime | None = None
    disabled_reason: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None
    latest_changes: dict[str, int] = Field(default_factory=dict)
