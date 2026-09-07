"""Organization invitation DTOs (Milestone 40)."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

InvitationRole = Literal["admin", "member"]
InvitationRoleState = Literal["recognized", "unrecognized"]
LocalRecordingState = Literal["complete", "audit_degraded"]


class OrganizationInvitationCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str = Field(min_length=1, max_length=320)


class OrganizationInvitationCreated(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["pending"] = "pending"
    role: Literal["member"] = "member"
    role_state: Literal["recognized"] = "recognized"
    recipient_hint: str
    created_at: datetime
    expires_at: datetime | None = None
    local_recording_state: LocalRecordingState = "complete"


class OrganizationInvitation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["pending"] = "pending"
    role: InvitationRole | None = None
    role_state: InvitationRoleState
    recipient_hint: str
    created_at: datetime
    expires_at: datetime | None = None


class OrganizationInvitationsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    page_size: int
    next_cursor: str | None = None
    total_invitations: int | None = None
    items: list[OrganizationInvitation] = Field(default_factory=list)
