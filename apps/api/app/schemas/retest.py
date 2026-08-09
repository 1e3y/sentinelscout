from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class RetestAttemptResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    organization_id: UUID
    finding_id: UUID
    candidate_id: UUID
    asset_id: UUID
    original_validation_attempt_id: UUID
    status: str
    method: str
    summary: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    completed_at: datetime | None = None
