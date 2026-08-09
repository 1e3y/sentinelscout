from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class AuditEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    organization_id: UUID
    actor_type: str
    actor_user_id: UUID | None = None
    action: str
    resource_type: str
    resource_id: UUID | None = None
    summary: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


class OperationControlSnapshotResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    operation_id: UUID
    organization_id: UUID
    target_id: UUID
    target_domain: str
    authorization_status: str
    target_authorization_id: UUID | None = None
    scope_root: str
    include_subdomains: bool
    exclusions: list[str] = Field(default_factory=list)
    operation_source: str
    testing_profile: str
    created_by_user_id: UUID
    created_at: datetime
    notes: str | None = None


class FindingProvenanceResponse(BaseModel):
    chain: list[str]
    finding_id: str
    candidate_id: str
    asset_id: str
    operation_id: str
    target_id: str | None = None
    observation_ids: list[str] = Field(default_factory=list)
    validation_attempt_id: str | None = None
    validation_method: str | None = None
    retest_attempt_id: str | None = None
    control_snapshot: dict[str, Any] | None = None
