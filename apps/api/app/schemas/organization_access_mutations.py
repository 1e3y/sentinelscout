"""Organization access mutation DTOs (Milestone 39)."""

from __future__ import annotations

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from app.schemas.organization_access import OrganizationAccessMember

AccessMutationRole = Literal["admin", "member"]
LocalRecordingState = Literal["complete", "audit_degraded"]


class OrganizationMemberRoleUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: AccessMutationRole


class OrganizationMemberRoleUpdateResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    member: OrganizationAccessMember
    local_recording_state: LocalRecordingState = "complete"


class OrganizationMemberRemovalResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    removed_user_id: UUID
    local_recording_state: LocalRecordingState = "complete"
