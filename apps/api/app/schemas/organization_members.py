"""Active-organization member list for finding ownership (Milestone 33)."""

from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class OrganizationMemberItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: UUID
    display_name: str | None = None


class OrganizationMembersResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    page_size: int
    next_cursor: str | None = None
    items: list[OrganizationMemberItem] = Field(default_factory=list)
