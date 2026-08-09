from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class CreateTargetRequest(BaseModel):
    domain: str = Field(min_length=1, max_length=253)


class TargetAuthorizationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    method: str
    txt_name: str
    txt_value: str
    created_at: datetime
    last_checked_at: datetime | None = None
    verified_at: datetime | None = None


class TargetResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    organization_id: UUID
    domain: str
    status: str
    created_at: datetime
    updated_at: datetime
    verified_at: datetime | None = None
    revoked_at: datetime | None = None
    authorization: TargetAuthorizationResponse | None = None


class VerifyTargetResponse(BaseModel):
    id: UUID
    domain: str
    status: str
    verified: bool
    detail: str


class TargetScopeResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    target_id: UUID
    root_domain: str
    include_subdomains: bool
    exclusions: list[str]
    created_at: datetime
    updated_at: datetime


class UpdateTargetScopeRequest(BaseModel):
    include_subdomains: bool
    exclusions: list[str] = Field(default_factory=list)
