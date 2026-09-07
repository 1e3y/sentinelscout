"""Organization invitation DTOs (Milestones 40–41)."""

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
    invitation_ref: str
    local_recording_state: LocalRecordingState = "complete"


class OrganizationInvitation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["pending"] = "pending"
    role: InvitationRole | None = None
    role_state: InvitationRoleState
    recipient_hint: str
    created_at: datetime
    expires_at: datetime | None = None
    invitation_ref: str


class OrganizationInvitationsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    page_size: int
    next_cursor: str | None = None
    total_invitations: int | None = None
    items: list[OrganizationInvitation] = Field(default_factory=list)


class OrganizationInvitationRevokeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    invitation_ref: str = Field(min_length=1, max_length=2048)


class OrganizationInvitationRevoked(BaseModel):
    model_config = ConfigDict(extra="forbid")

    revoked: Literal[True] = True
    local_recording_state: LocalRecordingState = "complete"


HistoryInvitationStatus = Literal["accepted", "revoked", "expired"]


class OrganizationInvitationHistoryItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: HistoryInvitationStatus
    role: InvitationRole | None = None
    role_state: InvitationRoleState
    recipient_hint: str
    created_at: datetime
    expires_at: datetime | None = None


class OrganizationInvitationHistoryResponse(BaseModel):
    """Terminal invitation history page (Milestone 43).

    ``total_invitations`` is the provider total matching the current M43 history
    filter (accepted / revoked / expired / all-terminal), not an unfiltered count.
    """

    model_config = ConfigDict(extra="forbid")

    page_size: int
    next_cursor: str | None = None
    total_invitations: int
    items: list[OrganizationInvitationHistoryItem] = Field(default_factory=list)
