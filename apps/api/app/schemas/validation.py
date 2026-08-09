from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class ValidationAttemptResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    organization_id: UUID
    operation_id: UUID
    candidate_id: UUID
    asset_id: UUID
    status: str
    validation_method: str
    summary: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    completed_at: datetime | None = None
