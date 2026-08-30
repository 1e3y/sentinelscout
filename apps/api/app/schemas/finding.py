from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.audit import FindingProvenanceResponse
from app.schemas.finding_follow_up import FindingFollowUpResponse


class FindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    organization_id: UUID
    operation_id: UUID
    candidate_id: UUID
    asset_id: UUID
    asset_hostname: str | None = None
    asset_url: str | None = None
    title: str
    summary: str
    severity: str
    status: str
    business_impact: str
    remediation_guidance: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    provenance: FindingProvenanceResponse | None = None
    follow_up: FindingFollowUpResponse | None = None
    created_at: datetime
    updated_at: datetime
    resolved_at: datetime | None = None
