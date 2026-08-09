from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.audit import OperationControlSnapshotResponse


class CreateOperationRequest(BaseModel):
    target_id: UUID


class OperationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    organization_id: UUID
    target_id: UUID
    target_domain: str
    created_by_user_id: UUID
    status: str
    source: str = "manual"
    testing_profile: str = "safe_production"
    stop_requested: bool = False
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    failed_at: datetime | None = None
    stopped_at: datetime | None = None
    error_code: str | None = None
    error_message: str | None = None
    control_snapshot: OperationControlSnapshotResponse | None = None


class OperationEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    operation_id: UUID
    sequence: int
    event_type: str
    summary: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
