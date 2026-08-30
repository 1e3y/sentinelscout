"""Truthful, bounded activity history for one supported Finding."""

from __future__ import annotations

import binascii
from base64 import urlsafe_b64decode, urlsafe_b64encode
from datetime import datetime, timezone
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import (
    DateTime,
    Integer,
    String,
    Text,
    and_,
    cast,
    func,
    literal,
    or_,
    select,
    true,
    union_all,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Session

from app.models.audit import AuditEvent
from app.models.finding import Finding
from app.models.finding_follow_up import FindingFollowUpChange
from app.models.finding_remediation import FindingRemediationRevision
from app.models.retest import ACTIVE_RETEST_STATUSES, RetestAttempt
from app.models.user import User
from app.schemas.finding_timeline import (
    FindingResolvedDetails,
    FindingResolvedEvent,
    FindingTimelineEvent,
    FindingTimelineResponse,
    FollowUpChangedDetails,
    FollowUpChangedEvent,
    FollowUpOwnerRef,
    ReadyForRetestEvent,
    RemediationRevisionDetails,
    RemediationRevisionRecordedEvent,
    RemediationStartedEvent,
    RetestCompletedDetails,
    RetestCompletedEvent,
    RetestQueuedDetails,
    RetestQueuedEvent,
    SupportedFindingPromotedDetails,
    SupportedFindingPromotedEvent,
    TimelineActor,
    WorkflowTransitionDetails,
)
from app.services.findings.retest_state import current_retest_state

DEFAULT_TIMELINE_PAGE_SIZE = 20
MAX_TIMELINE_PAGE_SIZE = 50
TIMELINE_CURSOR_VERSION = "v1"
INVALID_TIMELINE_CURSOR_DETAIL = "Invalid finding timeline cursor"

EVENT_RANKS = {
    "SUPPORTED_FINDING_PROMOTED": 10,
    "REMEDIATION_STARTED": 20,
    "FOLLOW_UP_CHANGED": 25,
    "REMEDIATION_REVISION_RECORDED": 30,
    "READY_FOR_RETEST": 40,
    "RETEST_QUEUED": 50,
    "RETEST_COMPLETED": 60,
    "FINDING_RESOLVED": 70,
}
VALID_EVENT_RANKS = frozenset(EVENT_RANKS.values())
ACTIVE_STATUS_LIST = sorted(ACTIVE_RETEST_STATUSES)
TERMINAL_STATUS_LIST = ["error", "failed", "inconclusive", "passed"]

GAP_REMEDIATION_STARTED = "remediation_started_timestamp_unavailable"
GAP_READY_FOR_RETEST = "ready_for_retest_timestamp_unavailable"
GAP_RESOLUTION_TIMESTAMP = "resolution_timestamp_unavailable"
GAP_RESOLUTION_LINK = "resolution_retest_link_unavailable"
GAP_RETEST_COMPLETION = "retest_completion_timestamp_unavailable"
GAP_WORKFLOW_AMBIGUOUS = "workflow_transition_ambiguous"

PASSING_RETEST_STATEMENT = (
    "Passing retest confirmed the condition was no longer observed."
)
UNLINKED_RESOLUTION_STATEMENT = (
    "The Finding is stored as resolved, but the historical passing-retest "
    "link is unavailable."
)


def encode_timeline_cursor(
    *, occurred_at: datetime, event_rank: int, source_uuid: UUID
) -> str:
    payload = (
        f"{TIMELINE_CURSOR_VERSION}|{occurred_at.isoformat()}|"
        f"{event_rank}|{source_uuid}"
    )
    return urlsafe_b64encode(payload.encode("utf-8")).decode("ascii").rstrip("=")


def _invalid_cursor() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=INVALID_TIMELINE_CURSOR_DETAIL,
    )


def decode_timeline_cursor(raw: str) -> tuple[datetime, int, UUID]:
    if not raw or not raw.strip():
        raise _invalid_cursor()
    padded = raw + ("=" * (-len(raw) % 4))
    try:
        decoded = urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
        raise _invalid_cursor() from exc
    parts = decoded.split("|")
    if len(parts) != 4 or parts[0] != TIMELINE_CURSOR_VERSION:
        raise _invalid_cursor()
    try:
        occurred_at = datetime.fromisoformat(parts[1])
        event_rank = int(parts[2])
        source_uuid = UUID(parts[3])
    except (TypeError, ValueError) as exc:
        raise _invalid_cursor() from exc
    if occurred_at.tzinfo is None or event_rank not in VALID_EVENT_RANKS:
        raise _invalid_cursor()
    return occurred_at, event_rank, source_uuid


def _cursor_condition(
    *,
    occurred_at,
    event_rank: int,
    source_uuid,
    cursor_position: tuple[datetime, int, UUID] | None,
):
    if cursor_position is None:
        return true()
    cursor_at, cursor_rank, cursor_uuid = cursor_position
    return or_(
        occurred_at < cursor_at,
        and_(occurred_at == cursor_at, event_rank < cursor_rank),
        and_(
            occurred_at == cursor_at,
            event_rank == cursor_rank,
            source_uuid < cursor_uuid,
        ),
    )


def _null_uuid():
    return cast(literal(None), PG_UUID(as_uuid=True))


def _null_string():
    return cast(literal(None), String())


def _null_text():
    return cast(literal(None), Text())


def _null_int():
    return cast(literal(None), Integer())


def _null_timestamptz():
    return cast(literal(None), DateTime(timezone=True))


def _normalized_select(
    *,
    occurred_at,
    event_rank: int,
    source_uuid,
    event_type: str,
    actor_type,
    actor_user_id,
    from_status=None,
    to_status=None,
    revision_number=None,
    remediation_summary=None,
    retest_status=None,
    retest_method=None,
    retest_summary=None,
    resolving_retest_id=None,
    previous_assigned_to_user_id=None,
    new_assigned_to_user_id=None,
    previous_due_at=None,
    new_due_at=None,
):
    return select(
        occurred_at.label("occurred_at"),
        literal(event_rank).label("event_rank"),
        source_uuid.label("source_uuid"),
        literal(event_type).label("event_type"),
        actor_type.label("actor_type"),
        actor_user_id.label("actor_user_id"),
        (from_status if from_status is not None else _null_string()).label(
            "from_status"
        ),
        (to_status if to_status is not None else _null_string()).label("to_status"),
        (
            revision_number if revision_number is not None else _null_int()
        ).label("revision_number"),
        (
            remediation_summary
            if remediation_summary is not None
            else _null_text()
        ).label("remediation_summary"),
        (retest_status if retest_status is not None else _null_string()).label(
            "retest_status"
        ),
        (retest_method if retest_method is not None else _null_string()).label(
            "retest_method"
        ),
        (retest_summary if retest_summary is not None else _null_text()).label(
            "retest_summary"
        ),
        (
            resolving_retest_id
            if resolving_retest_id is not None
            else _null_uuid()
        ).label("resolving_retest_id"),
        (
            previous_assigned_to_user_id
            if previous_assigned_to_user_id is not None
            else _null_uuid()
        ).label("previous_assigned_to_user_id"),
        (
            new_assigned_to_user_id
            if new_assigned_to_user_id is not None
            else _null_uuid()
        ).label("new_assigned_to_user_id"),
        (
            previous_due_at if previous_due_at is not None else _null_timestamptz()
        ).label("previous_due_at"),
        (new_due_at if new_due_at is not None else _null_timestamptz()).label(
            "new_due_at"
        ),
    )


def _apply_bound(
    statement,
    *,
    event_rank: int,
    size: int,
    cursor_position: tuple[datetime, int, UUID] | None,
):
    source = statement.subquery()
    return (
        select(source)
        .where(
            _cursor_condition(
                occurred_at=source.c.occurred_at,
                event_rank=event_rank,
                source_uuid=source.c.source_uuid,
                cursor_position=cursor_position,
            )
        )
        .order_by(
            source.c.occurred_at.desc(),
            source.c.event_rank.desc(),
            source.c.source_uuid.desc(),
        )
        .limit(size + 1)
        .subquery()
    )


def _valid_workflow_conditions(
    *,
    organization_id: UUID,
    finding_id: UUID,
    promoted_at: datetime,
    action: str,
    previous_status: str,
    new_status: str,
):
    return (
        AuditEvent.organization_id == organization_id,
        AuditEvent.resource_type == "finding",
        AuditEvent.resource_id == finding_id,
        AuditEvent.action == action,
        AuditEvent.actor_type == "user",
        AuditEvent.created_at >= promoted_at,
        AuditEvent.event_metadata["previous_status"].as_string() == previous_status,
        AuditEvent.event_metadata["new_status"].as_string() == new_status,
    )


def _timeline_statement(
    *,
    finding_id: UUID,
    organization_id: UUID,
    promoted_at: datetime,
    size: int,
    cursor_position: tuple[datetime, int, UUID] | None,
):
    promotion_actor = (
        select(AuditEvent.actor_user_id)
        .where(
            AuditEvent.organization_id == organization_id,
            AuditEvent.resource_type == "finding",
            AuditEvent.resource_id == finding_id,
            AuditEvent.action == "finding.created",
            AuditEvent.actor_type == "user",
            AuditEvent.created_at >= promoted_at,
        )
        .order_by(AuditEvent.created_at.asc(), AuditEvent.id.asc())
        .limit(1)
        .scalar_subquery()
    )
    promotion = _apply_bound(
        _normalized_select(
            occurred_at=Finding.created_at,
            event_rank=EVENT_RANKS["SUPPORTED_FINDING_PROMOTED"],
            source_uuid=Finding.id,
            event_type="SUPPORTED_FINDING_PROMOTED",
            actor_type=literal("user"),
            actor_user_id=promotion_actor,
        ).where(
            Finding.id == finding_id,
            Finding.organization_id == organization_id,
        ),
        event_rank=EVENT_RANKS["SUPPORTED_FINDING_PROMOTED"],
        size=size,
        cursor_position=cursor_position,
    )

    def workflow_branch(
        *,
        action: str,
        event_type: str,
        previous_status: str,
        new_status: str,
    ):
        canonical = (
            _normalized_select(
                occurred_at=AuditEvent.created_at,
                event_rank=EVENT_RANKS[event_type],
                source_uuid=AuditEvent.id,
                event_type=event_type,
                actor_type=literal("user"),
                actor_user_id=AuditEvent.actor_user_id,
                from_status=literal(previous_status),
                to_status=literal(new_status),
            )
            .where(
                *_valid_workflow_conditions(
                    organization_id=organization_id,
                    finding_id=finding_id,
                    promoted_at=promoted_at,
                    action=action,
                    previous_status=previous_status,
                    new_status=new_status,
                )
            )
            .order_by(AuditEvent.created_at.asc(), AuditEvent.id.asc())
            .limit(1)
        )
        return _apply_bound(
            canonical,
            event_rank=EVENT_RANKS[event_type],
            size=size,
            cursor_position=cursor_position,
        )

    remediation_started = workflow_branch(
        action="finding.remediation_started",
        event_type="REMEDIATION_STARTED",
        previous_status="open",
        new_status="in_progress",
    )
    ready_for_retest = workflow_branch(
        action="finding.ready_for_retest",
        event_type="READY_FOR_RETEST",
        previous_status="in_progress",
        new_status="ready_for_retest",
    )

    follow_up_changed = _apply_bound(
        _normalized_select(
            occurred_at=FindingFollowUpChange.created_at,
            event_rank=EVENT_RANKS["FOLLOW_UP_CHANGED"],
            source_uuid=FindingFollowUpChange.id,
            event_type="FOLLOW_UP_CHANGED",
            actor_type=literal("user"),
            actor_user_id=FindingFollowUpChange.changed_by_user_id,
            previous_assigned_to_user_id=FindingFollowUpChange.previous_assigned_to_user_id,
            new_assigned_to_user_id=FindingFollowUpChange.new_assigned_to_user_id,
            previous_due_at=FindingFollowUpChange.previous_due_at,
            new_due_at=FindingFollowUpChange.new_due_at,
        ).where(
            FindingFollowUpChange.finding_id == finding_id,
            FindingFollowUpChange.organization_id == organization_id,
        ),
        event_rank=EVENT_RANKS["FOLLOW_UP_CHANGED"],
        size=size,
        cursor_position=cursor_position,
    )

    remediation = _apply_bound(
        _normalized_select(
            occurred_at=FindingRemediationRevision.created_at,
            event_rank=EVENT_RANKS["REMEDIATION_REVISION_RECORDED"],
            source_uuid=FindingRemediationRevision.id,
            event_type="REMEDIATION_REVISION_RECORDED",
            actor_type=literal("user"),
            actor_user_id=FindingRemediationRevision.created_by_user_id,
            revision_number=FindingRemediationRevision.revision_number,
            remediation_summary=FindingRemediationRevision.summary,
        ).where(
            FindingRemediationRevision.finding_id == finding_id,
            FindingRemediationRevision.organization_id == organization_id,
        ),
        event_rank=EVENT_RANKS["REMEDIATION_REVISION_RECORDED"],
        size=size,
        cursor_position=cursor_position,
    )

    queued_source = (
        select(
            RetestAttempt.id,
            RetestAttempt.created_at,
            RetestAttempt.status,
        )
        .where(
            RetestAttempt.finding_id == finding_id,
            RetestAttempt.organization_id == organization_id,
            _cursor_condition(
                occurred_at=RetestAttempt.created_at,
                event_rank=EVENT_RANKS["RETEST_QUEUED"],
                source_uuid=RetestAttempt.id,
                cursor_position=cursor_position,
            ),
        )
        .order_by(RetestAttempt.created_at.desc(), RetestAttempt.id.desc())
        .limit(size + 1)
        .subquery("bounded_retest_requests")
    )
    exact_request = (
        select(AuditEvent.actor_user_id)
        .where(
            AuditEvent.organization_id == organization_id,
            AuditEvent.resource_type == "retest_attempt",
            AuditEvent.resource_id == queued_source.c.id,
            AuditEvent.action == "retest.requested",
            AuditEvent.actor_type == "user",
            AuditEvent.event_metadata["retest_id"].as_string()
            == cast(queued_source.c.id, String),
            AuditEvent.created_at >= queued_source.c.created_at,
        )
        .order_by(AuditEvent.created_at.asc(), AuditEvent.id.asc())
        .limit(1)
        .lateral("exact_retest_request")
    )
    queued = (
        _normalized_select(
            occurred_at=queued_source.c.created_at,
            event_rank=EVENT_RANKS["RETEST_QUEUED"],
            source_uuid=queued_source.c.id,
            event_type="RETEST_QUEUED",
            actor_type=literal("user"),
            actor_user_id=exact_request.c.actor_user_id,
            retest_status=queued_source.c.status,
        )
        .select_from(queued_source.outerjoin(exact_request, true()))
        .subquery()
    )

    completed = _apply_bound(
        _normalized_select(
            occurred_at=RetestAttempt.completed_at,
            event_rank=EVENT_RANKS["RETEST_COMPLETED"],
            source_uuid=RetestAttempt.id,
            event_type="RETEST_COMPLETED",
            actor_type=literal("worker"),
            actor_user_id=_null_uuid(),
            retest_status=RetestAttempt.status,
            retest_method=RetestAttempt.method,
            retest_summary=RetestAttempt.summary,
        ).where(
            RetestAttempt.finding_id == finding_id,
            RetestAttempt.organization_id == organization_id,
            RetestAttempt.status.in_(TERMINAL_STATUS_LIST),
            RetestAttempt.completed_at.is_not(None),
        ),
        event_rank=EVENT_RANKS["RETEST_COMPLETED"],
        size=size,
        cursor_position=cursor_position,
    )

    resolving_id_text = Finding.evidence["resolving_retest_id"].as_string()
    resolution = _apply_bound(
        _normalized_select(
            occurred_at=Finding.resolved_at,
            event_rank=EVENT_RANKS["FINDING_RESOLVED"],
            source_uuid=Finding.id,
            event_type="FINDING_RESOLVED",
            actor_type=literal("worker"),
            actor_user_id=_null_uuid(),
            resolving_retest_id=RetestAttempt.id,
        )
        .select_from(Finding)
        .outerjoin(
            RetestAttempt,
            and_(
                RetestAttempt.finding_id == Finding.id,
                RetestAttempt.organization_id == Finding.organization_id,
                RetestAttempt.status == "passed",
                cast(RetestAttempt.id, String) == resolving_id_text,
            ),
        )
        .where(
            Finding.id == finding_id,
            Finding.organization_id == organization_id,
            Finding.status == "resolved",
            Finding.resolved_at.is_not(None),
        ),
        event_rank=EVENT_RANKS["FINDING_RESOLVED"],
        size=size,
        cursor_position=cursor_position,
    )

    combined = union_all(
        select(promotion),
        select(remediation_started),
        select(follow_up_changed),
        select(remediation),
        select(ready_for_retest),
        select(queued),
        select(completed),
        select(resolution),
    ).subquery("finding_timeline_events")
    return (
        select(combined, User.name.label("actor_display_name"))
        .outerjoin(User, User.id == combined.c.actor_user_id)
        .order_by(
            combined.c.occurred_at.desc(),
            combined.c.event_rank.desc(),
            combined.c.source_uuid.desc(),
        )
        .limit(size + 1)
    )


def _actor(row) -> TimelineActor | None:
    if row.actor_type == "worker":
        return TimelineActor(actor_type="worker")
    if row.actor_user_id is None:
        return None
    return TimelineActor(
        actor_type="user",
        user_id=row.actor_user_id,
        display_name=row.actor_display_name,
    )


def _follow_up_title(
    *,
    previous_owner_name: str | None,
    new_owner_name: str | None,
    previous_assigned_to_user_id: UUID | None,
    new_assigned_to_user_id: UUID | None,
    previous_due_at: datetime | None,
    new_due_at: datetime | None,
) -> str:
    owner_changed = previous_assigned_to_user_id != new_assigned_to_user_id
    due_changed = previous_due_at != new_due_at
    parts: list[str] = []
    if owner_changed:
        if previous_assigned_to_user_id is None and new_assigned_to_user_id is not None:
            label = new_owner_name or "an organization member"
            parts.append(f"Assigned to {label}")
        elif previous_assigned_to_user_id is not None and new_assigned_to_user_id is None:
            parts.append("Follow-up assignment cleared")
        else:
            from_label = previous_owner_name or "an organization member"
            to_label = new_owner_name or "an organization member"
            parts.append(f"Owner changed from {from_label} to {to_label}")
    if due_changed:
        if previous_due_at is None and new_due_at is not None:
            due_label = new_due_at.astimezone(timezone.utc).strftime(
                "%Y-%m-%d %H:%M UTC"
            )
            parts.append(f"Follow-up due date set to {due_label}")
        elif previous_due_at is not None and new_due_at is None:
            parts.append("Follow-up due date cleared")
        else:
            parts.append("Follow-up due date updated")
    return "; ".join(parts) if parts else "Follow-up updated"


def _event_from_row(
    row, *, owner_names: dict[UUID, str | None] | None = None
) -> FindingTimelineEvent:
    actor = _actor(row)
    names = owner_names or {}
    if row.event_type == "SUPPORTED_FINDING_PROMOTED":
        return SupportedFindingPromotedEvent(
            event_id="supported-finding-promoted",
            event_type=row.event_type,
            occurred_at=row.occurred_at,
            provenance="finding_record",
            actor=actor,
            title="Supported finding promoted",
            details=SupportedFindingPromotedDetails(finding_id=row.source_uuid),
        )
    if row.event_type == "REMEDIATION_STARTED":
        return RemediationStartedEvent(
            event_id="remediation-started",
            event_type=row.event_type,
            occurred_at=row.occurred_at,
            provenance="human_workflow",
            actor=actor,
            title="Remediation workflow started",
            details=WorkflowTransitionDetails(
                from_status=row.from_status, to_status=row.to_status
            ),
        )
    if row.event_type == "FOLLOW_UP_CHANGED":
        previous_owner = None
        if row.previous_assigned_to_user_id is not None:
            previous_owner = FollowUpOwnerRef(
                user_id=row.previous_assigned_to_user_id,
                display_name=names.get(row.previous_assigned_to_user_id),
            )
        new_owner = None
        if row.new_assigned_to_user_id is not None:
            new_owner = FollowUpOwnerRef(
                user_id=row.new_assigned_to_user_id,
                display_name=names.get(row.new_assigned_to_user_id),
            )
        return FollowUpChangedEvent(
            event_id=f"follow-up-changed:{row.source_uuid}",
            event_type=row.event_type,
            occurred_at=row.occurred_at,
            provenance="human_workflow",
            actor=actor,
            title=_follow_up_title(
                previous_owner_name=(
                    previous_owner.display_name if previous_owner else None
                ),
                new_owner_name=new_owner.display_name if new_owner else None,
                previous_assigned_to_user_id=row.previous_assigned_to_user_id,
                new_assigned_to_user_id=row.new_assigned_to_user_id,
                previous_due_at=row.previous_due_at,
                new_due_at=row.new_due_at,
            ),
            details=FollowUpChangedDetails(
                previous_owner=previous_owner,
                new_owner=new_owner,
                previous_due_at=row.previous_due_at,
                new_due_at=row.new_due_at,
            ),
        )
    if row.event_type == "REMEDIATION_REVISION_RECORDED":
        return RemediationRevisionRecordedEvent(
            event_id=f"remediation-revision:{row.source_uuid}",
            event_type=row.event_type,
            occurred_at=row.occurred_at,
            provenance="human_remediation",
            actor=actor,
            title=f"Remediation revision {row.revision_number} recorded",
            details=RemediationRevisionDetails(
                revision_id=row.source_uuid,
                revision_number=row.revision_number,
                summary=row.remediation_summary,
            ),
        )
    if row.event_type == "READY_FOR_RETEST":
        return ReadyForRetestEvent(
            event_id="ready-for-retest",
            event_type=row.event_type,
            occurred_at=row.occurred_at,
            provenance="human_workflow",
            actor=actor,
            title="Finding marked ready for retest",
            details=WorkflowTransitionDetails(
                from_status=row.from_status, to_status=row.to_status
            ),
        )
    if row.event_type == "RETEST_QUEUED":
        return RetestQueuedEvent(
            event_id=f"retest-queued:{row.source_uuid}",
            event_type=row.event_type,
            occurred_at=row.occurred_at,
            provenance="human_workflow",
            actor=actor,
            title="Retest requested",
            details=RetestQueuedDetails(
                retest_attempt_id=row.source_uuid,
                status_at_read=row.retest_status,
                queued_at=row.occurred_at,
            ),
        )
    if row.event_type == "RETEST_COMPLETED":
        status_label = row.retest_status.replace("_", " ").title()
        return RetestCompletedEvent(
            event_id=f"retest-completed:{row.source_uuid}",
            event_type=row.event_type,
            occurred_at=row.occurred_at,
            provenance="scout_retest",
            actor=actor,
            title=f"Retest completed: {status_label}",
            details=RetestCompletedDetails(
                retest_attempt_id=row.source_uuid,
                status=row.retest_status,
                completed_at=row.occurred_at,
                method=row.retest_method,
                summary=row.retest_summary,
            ),
        )
    linked = row.resolving_retest_id is not None
    return FindingResolvedEvent(
        event_id="finding-resolved",
        event_type="FINDING_RESOLVED",
        occurred_at=row.occurred_at,
        provenance="finding_record",
        actor=actor if linked else None,
        title="Finding resolved",
        details=FindingResolvedDetails(
            resolution_basis="passing_retest" if linked else "link_unavailable",
            resolving_retest_attempt_id=row.resolving_retest_id,
            statement=(
                PASSING_RETEST_STATEMENT if linked else UNLINKED_RESOLUTION_STATEMENT
            ),
        ),
    )


def _current_state(
    db: Session, *, finding_id: UUID, organization_id: UUID
) -> tuple[str, int]:
    active_exists = (
        select(RetestAttempt.id)
        .where(
            RetestAttempt.finding_id == finding_id,
            RetestAttempt.organization_id == organization_id,
            RetestAttempt.status.in_(ACTIVE_STATUS_LIST),
        )
        .exists()
    )
    latest_terminal = (
        select(RetestAttempt.status)
        .where(
            RetestAttempt.finding_id == finding_id,
            RetestAttempt.organization_id == organization_id,
            RetestAttempt.status.not_in(ACTIVE_STATUS_LIST),
        )
        .order_by(
            RetestAttempt.completed_at.desc().nullslast(),
            RetestAttempt.created_at.desc(),
            RetestAttempt.id.desc(),
        )
        .limit(1)
        .scalar_subquery()
    )
    revision_count = (
        select(func.count())
        .select_from(FindingRemediationRevision)
        .where(
            FindingRemediationRevision.finding_id == finding_id,
            FindingRemediationRevision.organization_id == organization_id,
        )
        .scalar_subquery()
    )
    row = db.execute(
        select(
            active_exists.label("has_active"),
            latest_terminal.label("latest_terminal_status"),
            revision_count.label("revision_count"),
        )
    ).one()
    return (
        current_retest_state(
            has_active=bool(row.has_active),
            latest_terminal_status=row.latest_terminal_status,
        ),
        int(row.revision_count or 0),
    )


def _history_gaps(
    db: Session,
    *,
    finding_id: UUID,
    organization_id: UUID,
    finding_status: str,
    promoted_at: datetime,
    resolved_at: datetime | None,
) -> list[str]:
    start_count = (
        select(func.count())
        .select_from(AuditEvent)
        .where(
            *_valid_workflow_conditions(
                organization_id=organization_id,
                finding_id=finding_id,
                promoted_at=promoted_at,
                action="finding.remediation_started",
                previous_status="open",
                new_status="in_progress",
            )
        )
        .scalar_subquery()
    )
    ready_count = (
        select(func.count())
        .select_from(AuditEvent)
        .where(
            *_valid_workflow_conditions(
                organization_id=organization_id,
                finding_id=finding_id,
                promoted_at=promoted_at,
                action="finding.ready_for_retest",
                previous_status="in_progress",
                new_status="ready_for_retest",
            )
        )
        .scalar_subquery()
    )
    missing_completion_count = (
        select(func.count())
        .select_from(RetestAttempt)
        .where(
            RetestAttempt.finding_id == finding_id,
            RetestAttempt.organization_id == organization_id,
            RetestAttempt.status.in_(TERMINAL_STATUS_LIST),
            RetestAttempt.completed_at.is_(None),
        )
        .scalar_subquery()
    )
    exact_resolution_link = (
        select(RetestAttempt.id)
        .join(Finding, Finding.id == RetestAttempt.finding_id)
        .where(
            Finding.id == finding_id,
            Finding.organization_id == organization_id,
            RetestAttempt.organization_id == organization_id,
            RetestAttempt.status == "passed",
            cast(RetestAttempt.id, String)
            == Finding.evidence["resolving_retest_id"].as_string(),
        )
        .exists()
    )
    row = db.execute(
        select(
            start_count.label("start_count"),
            ready_count.label("ready_count"),
            missing_completion_count.label("missing_completion_count"),
            exact_resolution_link.label("has_resolution_link"),
        )
    ).one()

    gaps: list[str] = []
    if (
        finding_status in {"in_progress", "ready_for_retest", "resolved"}
        and int(row.start_count or 0) == 0
    ):
        gaps.append(GAP_REMEDIATION_STARTED)
    if (
        finding_status in {"ready_for_retest", "resolved"}
        and int(row.ready_count or 0) == 0
    ):
        gaps.append(GAP_READY_FOR_RETEST)
    if int(row.start_count or 0) > 1 or int(row.ready_count or 0) > 1:
        gaps.append(GAP_WORKFLOW_AMBIGUOUS)
    if int(row.missing_completion_count or 0) > 0:
        gaps.append(GAP_RETEST_COMPLETION)
    if finding_status == "resolved":
        if resolved_at is None:
            gaps.append(GAP_RESOLUTION_TIMESTAMP)
        elif not bool(row.has_resolution_link):
            gaps.append(GAP_RESOLUTION_LINK)
    return gaps


def list_finding_timeline(
    db: Session,
    *,
    finding_id: UUID,
    organization_id: UUID,
    page_size: int = DEFAULT_TIMELINE_PAGE_SIZE,
    cursor: str | None = None,
) -> FindingTimelineResponse:
    """Read the authorized finding's durable history without mutating anything."""
    finding = db.execute(
        select(
            Finding.id,
            Finding.organization_id,
            Finding.status,
            Finding.created_at.label("promoted_at"),
            Finding.resolved_at,
        ).where(
            Finding.id == finding_id,
            Finding.organization_id == organization_id,
        )
    ).one_or_none()
    if finding is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found"
        )

    size = min(max(page_size, 1), MAX_TIMELINE_PAGE_SIZE)
    cursor_position = decode_timeline_cursor(cursor) if cursor else None
    current_state, revision_count = _current_state(
        db,
        finding_id=finding.id,
        organization_id=finding.organization_id,
    )
    gaps = _history_gaps(
        db,
        finding_id=finding.id,
        organization_id=finding.organization_id,
        finding_status=finding.status,
        promoted_at=finding.promoted_at,
        resolved_at=finding.resolved_at,
    )
    rows = list(
        db.execute(
            _timeline_statement(
                finding_id=finding.id,
                organization_id=finding.organization_id,
                promoted_at=finding.promoted_at,
                size=size,
                cursor_position=cursor_position,
            )
        ).all()
    )
    has_more = len(rows) > size
    page = rows[:size]
    next_cursor = None
    if has_more and page:
        last = page[-1]
        next_cursor = encode_timeline_cursor(
            occurred_at=last.occurred_at,
            event_rank=last.event_rank,
            source_uuid=last.source_uuid,
        )
    owner_ids: set[UUID] = set()
    for row in page:
        if row.event_type != "FOLLOW_UP_CHANGED":
            continue
        if row.previous_assigned_to_user_id is not None:
            owner_ids.add(row.previous_assigned_to_user_id)
        if row.new_assigned_to_user_id is not None:
            owner_ids.add(row.new_assigned_to_user_id)
    owner_names: dict[UUID, str | None] = {}
    if owner_ids:
        owner_names = {
            user.id: user.name
            for user in db.scalars(select(User).where(User.id.in_(owner_ids))).all()
        }
    return FindingTimelineResponse(
        finding_id=finding.id,
        current_status=finding.status,
        current_retest_state=current_state,
        remediation_revision_count=revision_count,
        history_completeness="partial" if gaps else "complete",
        history_gaps=gaps,
        page_size=size,
        next_cursor=next_cursor,
        events=[_event_from_row(row, owner_names=owner_names) for row in page],
    )
