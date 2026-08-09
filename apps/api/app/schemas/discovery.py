from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class AssetResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    organization_id: UUID
    target_id: UUID
    hostname: str
    url: str
    asset_type: str
    status_code: int | None = None
    title: str | None = None
    source: str
    first_seen_at: datetime
    last_seen_at: datetime


class DiscoveryObservationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    organization_id: UUID
    operation_id: UUID
    asset_id: UUID | None = None
    observation_type: str
    summary: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    source: str
    created_at: datetime
