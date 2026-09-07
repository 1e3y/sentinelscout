"""Finding ownership review DTOs (Milestone 44)."""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

AssignmentState = Literal["unassigned", "current_member", "not_current_member"]
ActiveFindingStatus = Literal["open", "in_progress", "ready_for_retest"]
FindingSeverity = Literal["informational", "low", "medium", "high", "critical"]


class FindingOwnershipAssignee(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: UUID
    display_name: str | None = None


class FindingOwnershipReviewItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: UUID
    target_id: UUID
    target_label: str
    title: str
    severity: FindingSeverity
    status: ActiveFindingStatus
    assignment_state: AssignmentState
    assignee: FindingOwnershipAssignee | None = None
    follow_up_due_at: datetime | None = None
    created_at: datetime


class FindingOwnershipReviewResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[FindingOwnershipReviewItem] = Field(default_factory=list)
    next_cursor: str | None = None
