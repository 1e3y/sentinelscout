"""Finding follow-up due-date review DTOs (Milestone 46)."""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

DueState = Literal["no_due_date", "upcoming", "overdue"]
ActiveFindingStatus = Literal["open", "in_progress", "ready_for_retest"]
FindingSeverity = Literal["informational", "low", "medium", "high", "critical"]


class FindingFollowUpReviewAssignee(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: UUID
    display_name: str | None = None


class FindingFollowUpReviewItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: UUID
    target_id: UUID
    target_label: str
    title: str
    severity: FindingSeverity
    status: ActiveFindingStatus
    due_state: DueState
    follow_up_due_at: datetime | None = None
    assignee: FindingFollowUpReviewAssignee | None = None
    created_at: datetime


class FindingFollowUpReviewResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evaluation_time: datetime
    items: list[FindingFollowUpReviewItem] = Field(default_factory=list)
    next_cursor: str | None = None
