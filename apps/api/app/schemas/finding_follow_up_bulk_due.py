"""Bulk Finding follow-up due-date update DTOs (Milestone 50)."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.schemas.finding_follow_up import ExpectedFollowUpState

MAX_BULK_FOLLOW_UP_DUE_ITEMS = 50


class BulkFollowUpDueItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: UUID
    expected_follow_up: ExpectedFollowUpState

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


class BulkFollowUpDueRequest(BaseModel):
    """Set selected Findings to one non-null absolute due instant."""

    model_config = ConfigDict(extra="forbid")

    follow_up_due_at: datetime
    items: list[BulkFollowUpDueItem] = Field(
        min_length=1,
        max_length=MAX_BULK_FOLLOW_UP_DUE_ITEMS,
    )

    @field_validator("follow_up_due_at")
    @classmethod
    def require_timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("follow_up_due_at must be timezone-aware")
        return value

    @model_validator(mode="after")
    def unique_finding_ids(self) -> BulkFollowUpDueRequest:
        ids = [item.finding_id for item in self.items]
        if len(ids) != len(set(ids)):
            raise ValueError("finding_id values must be unique")
        return self


class BulkFollowUpDueResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    selected_count: int
    changed_count: int
    unchanged_count: int

    @model_validator(mode="after")
    def counts_are_consistent(self) -> BulkFollowUpDueResponse:
        if self.selected_count != self.changed_count + self.unchanged_count:
            raise ValueError("selected_count must equal changed_count + unchanged_count")
        return self
