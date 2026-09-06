"""Organization access review response (Milestone 38)."""

from __future__ import annotations

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

AccessRole = Literal["admin", "member"]
RoleState = Literal["recognized", "unrecognized"]
AccountLinkState = Literal["linked", "not_linked"]
LocalMirrorState = Literal[
    "not_applicable",
    "missing",
    "role_matches",
    "role_differs",
]
AccessSource = Literal["authoritative_current_membership"]


class OrganizationAccessOrg(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: UUID
    name: str


class OrganizationAccessMember(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: UUID | None = None
    display_name: str | None = None
    role: AccessRole | None = None
    role_state: RoleState
    account_link_state: AccountLinkState
    local_mirror_state: LocalMirrorState


class OrganizationAccessResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    organization: OrganizationAccessOrg
    source: AccessSource = "authoritative_current_membership"
    page_size: int
    next_cursor: str | None = None
    total_members: int | None = None
    items: list[OrganizationAccessMember] = Field(default_factory=list)
