"""Finding ownership and follow-up due-date DTOs (Milestone 33)."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, field_validator, model_validator


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


class ExpectedFollowUpState(BaseModel):
    """Locked owner + due that a conditional M33 write must still observe."""

    model_config = ConfigDict(extra="forbid")

    assigned_to_user_id: UUID | None
    follow_up_due_at: datetime | None

    @field_validator("follow_up_due_at")
    @classmethod
    def require_timezone_aware(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("follow_up_due_at must be timezone-aware")
        return value


class UpdateFindingFollowUpRequest(BaseModel):
    """Full replacement of both follow-up fields.

    ``expected_follow_up`` omitted → legacy last-write-wins.
    Present object → compare against the locked Finding.
    Present JSON null → 422 (must not disable the precondition).
    """

    model_config = ConfigDict(extra="forbid")

    assigned_to_user_id: UUID | None = None
    follow_up_due_at: datetime | None = None
    expected_follow_up: ExpectedFollowUpState | None = None

    @model_validator(mode="before")
    @classmethod
    def reject_explicit_null_expected_follow_up(cls, data: object) -> object:
        if (
            isinstance(data, dict)
            and "expected_follow_up" in data
            and data["expected_follow_up"] is None
        ):
            raise ValueError("expected_follow_up must be an object when provided")
        return data

    @field_validator("follow_up_due_at")
    @classmethod
    def require_timezone_aware(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("follow_up_due_at must be timezone-aware")
        return value
