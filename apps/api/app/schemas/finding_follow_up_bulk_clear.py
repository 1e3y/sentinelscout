"""Bulk Finding follow-up owner/due clear DTOs (Milestone 53)."""

from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.schemas.finding_follow_up import ExpectedFollowUpState

MAX_BULK_FOLLOW_UP_CLEAR_ITEMS = 50


class BulkFollowUpClearItem(BaseModel):
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


class BulkFollowUpClearRequest(BaseModel):
    """Clear selected follow-up dimensions for selected active Findings."""

    model_config = ConfigDict(extra="forbid")

    clear_owner: bool
    clear_due: bool
    items: list[BulkFollowUpClearItem] = Field(
        min_length=1,
        max_length=MAX_BULK_FOLLOW_UP_CLEAR_ITEMS,
    )

    @model_validator(mode="after")
    def require_at_least_one_clear_flag(self) -> BulkFollowUpClearRequest:
        if not self.clear_owner and not self.clear_due:
            raise ValueError("at least one of clear_owner or clear_due must be true")
        ids = [item.finding_id for item in self.items]
        if len(ids) != len(set(ids)):
            raise ValueError("finding_id values must be unique")
        return self


class BulkFollowUpClearResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    selected_count: int
    changed_count: int
    unchanged_count: int

    @model_validator(mode="after")
    def counts_are_consistent(self) -> BulkFollowUpClearResponse:
        if self.selected_count != self.changed_count + self.unchanged_count:
            raise ValueError("selected_count must equal changed_count + unchanged_count")
        return self
