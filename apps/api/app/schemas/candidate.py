from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class SecurityCandidateResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    organization_id: UUID
    operation_id: UUID
    asset_id: UUID
    asset_hostname: str | None = None
    asset_url: str | None = None
    candidate_type: str
    title: str
    summary: str
    status: str
    source: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime
