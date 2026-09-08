"""Bulk Finding ownership assignment DTOs (Milestone 49)."""

from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.schemas.finding_follow_up import ExpectedFollowUpState

MAX_BULK_OWNERSHIP_ASSIGN_ITEMS = 50


class BulkOwnershipAssignItem(BaseModel):
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


class BulkOwnershipAssignRequest(BaseModel):
    """Assign selected Findings to one current organization member.

    ``assigned_to_user_id`` is required. JSON null is rejected (no bulk unassign).
    ``expected_follow_up.follow_up_due_at`` is a concurrency precondition only.
    """

    model_config = ConfigDict(extra="forbid")

    assigned_to_user_id: UUID
    items: list[BulkOwnershipAssignItem] = Field(
        min_length=1,
        max_length=MAX_BULK_OWNERSHIP_ASSIGN_ITEMS,
    )

    @model_validator(mode="after")
    def unique_finding_ids(self) -> BulkOwnershipAssignRequest:
        ids = [item.finding_id for item in self.items]
        if len(ids) != len(set(ids)):
            raise ValueError("finding_id values must be unique")
        return self


class BulkOwnershipAssignResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    selected_count: int
    changed_count: int
    unchanged_count: int

    @model_validator(mode="after")
    def counts_are_consistent(self) -> BulkOwnershipAssignResponse:
        if self.selected_count != self.changed_count + self.unchanged_count:
            raise ValueError("selected_count must equal changed_count + unchanged_count")
        return self
