"""Finding ownership and follow-up due-date DTOs (Milestone 33)."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


class FindingOwnerResponse(BaseModel):
    """Assigned owner. Absent entirely (null) when the Finding is unassigned."""

    model_config = ConfigDict(extra="forbid")

    user_id: UUID
    display_name: str | None = None
    current_member: bool


class FindingFollowUpResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    owner: FindingOwnerResponse | None = None
    follow_up_due_at: datetime | None = None


class UpdateFindingFollowUpRequest(BaseModel):
    """Full replacement of both follow-up fields."""

    model_config = ConfigDict(extra="forbid")

    assigned_to_user_id: UUID | None = None
    follow_up_due_at: datetime | None = None

    @field_validator("follow_up_due_at")
    @classmethod
    def require_timezone_aware(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("follow_up_due_at must be timezone-aware")
        return value
