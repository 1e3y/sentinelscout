"""Customer-facing, read-only history for one supported Finding."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.findings_inbox import CurrentRetestState, FindingInboxStatus

TimelineProvenance = Literal[
    "finding_record",
    "human_workflow",
    "human_remediation",
    "scout_retest",
]
TimelineActorType = Literal["user", "worker"]
RetestAttemptStatus = Literal[
    "pending", "running", "passed", "failed", "inconclusive", "error"
]
TerminalRetestStatus = Literal["passed", "failed", "inconclusive", "error"]
HistoryGapCode = Literal[
    "remediation_started_timestamp_unavailable",
    "ready_for_retest_timestamp_unavailable",
    "resolution_timestamp_unavailable",
    "resolution_retest_link_unavailable",
    "retest_completion_timestamp_unavailable",
    "workflow_transition_ambiguous",
]


class TimelineActor(BaseModel):
    model_config = ConfigDict(extra="forbid")

    actor_type: TimelineActorType
    user_id: UUID | None = None
    display_name: str | None = None


class SupportedFindingPromotedDetails(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: UUID


class WorkflowTransitionDetails(BaseModel):
    model_config = ConfigDict(extra="forbid")

    from_status: FindingInboxStatus
    to_status: FindingInboxStatus


class RemediationRevisionDetails(BaseModel):
    model_config = ConfigDict(extra="forbid")

    revision_id: UUID
    revision_number: int
    summary: str


class RetestQueuedDetails(BaseModel):
    model_config = ConfigDict(extra="forbid")

    retest_attempt_id: UUID
    status_at_read: RetestAttemptStatus
    queued_at: datetime


class RetestCompletedDetails(BaseModel):
    model_config = ConfigDict(extra="forbid")

    retest_attempt_id: UUID
    status: TerminalRetestStatus
    completed_at: datetime
    method: str
    summary: str


class FindingResolvedDetails(BaseModel):
    model_config = ConfigDict(extra="forbid")

    resolution_basis: Literal["passing_retest", "link_unavailable"]
    resolving_retest_attempt_id: UUID | None = None
    statement: str


class TimelineEventBase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str
    occurred_at: datetime
    actor: TimelineActor | None = None
    title: str


class SupportedFindingPromotedEvent(TimelineEventBase):
    event_type: Literal["SUPPORTED_FINDING_PROMOTED"]
    provenance: Literal["finding_record"]
    details: SupportedFindingPromotedDetails


class RemediationStartedEvent(TimelineEventBase):
    event_type: Literal["REMEDIATION_STARTED"]
    provenance: Literal["human_workflow"]
    details: WorkflowTransitionDetails


class RemediationRevisionRecordedEvent(TimelineEventBase):
    event_type: Literal["REMEDIATION_REVISION_RECORDED"]
    provenance: Literal["human_remediation"]
    details: RemediationRevisionDetails


class ReadyForRetestEvent(TimelineEventBase):
    event_type: Literal["READY_FOR_RETEST"]
    provenance: Literal["human_workflow"]
    details: WorkflowTransitionDetails


class RetestQueuedEvent(TimelineEventBase):
    event_type: Literal["RETEST_QUEUED"]
    provenance: Literal["human_workflow"]
    details: RetestQueuedDetails


class RetestCompletedEvent(TimelineEventBase):
    event_type: Literal["RETEST_COMPLETED"]
    provenance: Literal["scout_retest"]
    details: RetestCompletedDetails


class FindingResolvedEvent(TimelineEventBase):
    event_type: Literal["FINDING_RESOLVED"]
    provenance: Literal["finding_record"]
    details: FindingResolvedDetails


FindingTimelineEvent = Annotated[
    SupportedFindingPromotedEvent
    | RemediationStartedEvent
    | RemediationRevisionRecordedEvent
    | ReadyForRetestEvent
    | RetestQueuedEvent
    | RetestCompletedEvent
    | FindingResolvedEvent,
    Field(discriminator="event_type"),
]


class FindingTimelineResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: UUID
    current_status: FindingInboxStatus
    current_retest_state: CurrentRetestState
    remediation_revision_count: int
    history_completeness: Literal["complete", "partial"]
    history_gaps: list[HistoryGapCode] = Field(default_factory=list)
    page_size: int
    next_cursor: str | None = None
    events: list[FindingTimelineEvent] = Field(default_factory=list)
