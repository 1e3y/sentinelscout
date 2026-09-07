"""Organization finding follow-up due-date review (Milestone 46).

Read-only and DB-only. Classifies active Findings against one frozen UTC
evaluation_time. No Clerk/provider dependency. Never mutates follow-up data.
"""

from __future__ import annotations

import binascii
from base64 import urlsafe_b64decode, urlsafe_b64encode
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.finding import OPEN_FINDING_STATUSES, Finding
from app.models.organization import Organization
from app.models.target import AuthorizedTarget
from app.models.user import User
from app.schemas.finding_follow_up_review import (
    DueState,
    FindingFollowUpReviewAssignee,
    FindingFollowUpReviewItem,
    FindingFollowUpReviewResponse,
)

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 100
CURSOR_VERSION = "v1"
INVALID_CURSOR_DETAIL = "Invalid finding follow-up review cursor"
UNAVAILABLE_DETAIL = "Finding follow-up review could not be loaded."
OPEN_STATUS_LIST = sorted(OPEN_FINDING_STATUSES)
PUBLIC_DUE_STATES = frozenset({"no_due_date", "upcoming", "overdue"})
CURSOR_DUE_FILTERS = frozenset({"all", "no_due_date", "upcoming", "overdue"})
EVALUATION_SNAPSHOT_MAX_AGE = timedelta(hours=1)
CLOCK_SKEW_TOLERANCE = timedelta(seconds=5)


@dataclass(frozen=True)
class FollowUpReviewCursor:
    due_filter: str
    evaluation_time: datetime
    created_at: datetime
    finding_id: UUID


def raise_follow_up_review_unavailable() -> None:
    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail=UNAVAILABLE_DETAIL,
    )


def _invalid_cursor() -> None:
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=INVALID_CURSOR_DETAIL,
    )


def canonicalize_cursor_instant(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        _invalid_cursor()
    return value.astimezone(timezone.utc)


def format_cursor_instant(value: datetime) -> str:
    return canonicalize_cursor_instant(value).isoformat()


def parse_cursor_instant(raw: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        _invalid_cursor()
    return canonicalize_cursor_instant(parsed)


def normalize_due_filter(due_state: str | None) -> str:
    if due_state is None:
        return "all"
    if due_state not in PUBLIC_DUE_STATES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Invalid due_state",
        )
    return due_state


def classify_due_state(
    follow_up_due_at: datetime | None,
    evaluation_time: datetime,
) -> DueState:
    if follow_up_due_at is None:
        return "no_due_date"
    if follow_up_due_at.tzinfo is None or follow_up_due_at.utcoffset() is None:
        raise_follow_up_review_unavailable()
    due = follow_up_due_at.astimezone(timezone.utc)
    moment = canonicalize_cursor_instant(evaluation_time)
    if due <= moment:
        return "overdue"
    return "upcoming"


def encode_follow_up_review_cursor(
    *,
    due_filter: str,
    evaluation_time: datetime,
    created_at: datetime,
    finding_id: UUID,
) -> str:
    payload = "|".join(
        (
            CURSOR_VERSION,
            due_filter,
            format_cursor_instant(evaluation_time),
            format_cursor_instant(created_at),
            str(finding_id),
        )
    )
    return urlsafe_b64encode(payload.encode("utf-8")).decode("ascii").rstrip("=")


def decode_follow_up_review_cursor(raw: str) -> FollowUpReviewCursor:
    if not raw or not raw.strip():
        _invalid_cursor()
    padded = raw + ("=" * (-len(raw) % 4))
    try:
        decoded = urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        _invalid_cursor()
    parts = decoded.split("|")
    if len(parts) != 5 or parts[0] != CURSOR_VERSION:
        _invalid_cursor()
    due_filter, evaluation_raw, created_raw, finding_raw = parts[1:]
    if due_filter not in CURSOR_DUE_FILTERS:
        _invalid_cursor()
    try:
        finding_id = UUID(finding_raw)
    except (TypeError, ValueError):
        _invalid_cursor()
    return FollowUpReviewCursor(
        due_filter=due_filter,
        evaluation_time=parse_cursor_instant(evaluation_raw),
        created_at=parse_cursor_instant(created_raw),
        finding_id=finding_id,
    )


def validate_evaluation_snapshot(
    evaluation_time: datetime,
    request_now: datetime,
) -> datetime:
    moment = canonicalize_cursor_instant(request_now)
    snapshot = canonicalize_cursor_instant(evaluation_time)
    if snapshot > moment + CLOCK_SKEW_TOLERANCE:
        _invalid_cursor()
    if moment - snapshot > EVALUATION_SNAPSHOT_MAX_AGE:
        _invalid_cursor()
    return snapshot


def resolve_follow_up_review_cursor(
    cursor: str | None,
    *,
    due_filter: str,
    request_now: datetime,
) -> tuple[datetime, datetime | None, UUID | None]:
    """Validate cursor/filter/age. Returns evaluation_time and keyset position."""
    request_now = canonicalize_cursor_instant(request_now)
    if cursor is None:
        return request_now, None, None
    decoded = decode_follow_up_review_cursor(cursor)
    if decoded.due_filter != due_filter:
        _invalid_cursor()
    evaluation_time = validate_evaluation_snapshot(decoded.evaluation_time, request_now)
    return evaluation_time, decoded.created_at, decoded.finding_id


def _due_predicate(due_filter: str, evaluation_time: datetime):
    if due_filter == "all":
        return None
    if due_filter == "no_due_date":
        return Finding.follow_up_due_at.is_(None)
    if due_filter == "overdue":
        return and_(
            Finding.follow_up_due_at.is_not(None),
            Finding.follow_up_due_at <= evaluation_time,
        )
    if due_filter == "upcoming":
        return and_(
            Finding.follow_up_due_at.is_not(None),
            Finding.follow_up_due_at > evaluation_time,
        )
    raise HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        detail="Invalid due_state",
    )


def list_finding_follow_up_review(
    db: Session,
    *,
    organization: Organization,
    due_filter: str,
    evaluation_time: datetime,
    page_size: int = DEFAULT_PAGE_SIZE,
    cursor_created_at: datetime | None = None,
    cursor_finding_id: UUID | None = None,
) -> FindingFollowUpReviewResponse:
    size = min(max(page_size, 1), MAX_PAGE_SIZE)
    moment = canonicalize_cursor_instant(evaluation_time)
    stmt = (
        select(
            Finding.id.label("finding_id"),
            Finding.title,
            Finding.severity,
            Finding.status,
            Finding.assigned_to_user_id,
            Finding.follow_up_due_at,
            Finding.created_at,
            AuthorizedTarget.id.label("target_id"),
            AuthorizedTarget.domain.label("target_label"),
        )
        .join(Asset, Asset.id == Finding.asset_id)
        .join(AuthorizedTarget, AuthorizedTarget.id == Asset.target_id)
        .where(
            Finding.organization_id == organization.id,
            AuthorizedTarget.organization_id == organization.id,
            Finding.status.in_(OPEN_STATUS_LIST),
        )
        .order_by(Finding.created_at.desc(), Finding.id.desc())
        .limit(size + 1)
    )
    due_clause = _due_predicate(due_filter, moment)
    if due_clause is not None:
        stmt = stmt.where(due_clause)
    if cursor_created_at is not None and cursor_finding_id is not None:
        cursor_created = canonicalize_cursor_instant(cursor_created_at)
        stmt = stmt.where(
            or_(
                Finding.created_at < cursor_created,
                and_(
                    Finding.created_at == cursor_created,
                    Finding.id < cursor_finding_id,
                ),
            )
        )

    raw_rows = list(db.execute(stmt).all())
    has_more = len(raw_rows) > size
    visible_rows = raw_rows[:size]

    assignee_ids = sorted(
        {
            row.assigned_to_user_id
            for row in visible_rows
            if row.assigned_to_user_id is not None
        }
    )
    users_by_id: dict[UUID, str | None] = {}
    if assignee_ids:
        user_rows = db.execute(
            select(User.id, User.name).where(User.id.in_(assignee_ids))
        ).all()
        if len(user_rows) != len(assignee_ids):
            raise_follow_up_review_unavailable()
        for user_id, name in user_rows:
            users_by_id[user_id] = name

    items: list[FindingFollowUpReviewItem] = []
    for row in visible_rows:
        if row.status not in OPEN_FINDING_STATUSES:
            raise_follow_up_review_unavailable()
        if row.created_at is None or row.created_at.tzinfo is None:
            raise_follow_up_review_unavailable()
        label = row.target_label
        if not isinstance(label, str) or not label.strip():
            raise_follow_up_review_unavailable()
        if row.follow_up_due_at is not None and (
            row.follow_up_due_at.tzinfo is None or row.follow_up_due_at.utcoffset() is None
        ):
            raise_follow_up_review_unavailable()
        assignee: FindingFollowUpReviewAssignee | None = None
        if row.assigned_to_user_id is not None:
            if row.assigned_to_user_id not in users_by_id:
                raise_follow_up_review_unavailable()
            assignee = FindingFollowUpReviewAssignee(
                user_id=row.assigned_to_user_id,
                display_name=users_by_id[row.assigned_to_user_id],
            )
        items.append(
            FindingFollowUpReviewItem(
                finding_id=row.finding_id,
                target_id=row.target_id,
                target_label=label,
                title=row.title,
                severity=row.severity,
                status=row.status,
                due_state=classify_due_state(row.follow_up_due_at, moment),
                follow_up_due_at=row.follow_up_due_at,
                assignee=assignee,
                created_at=row.created_at,
            )
        )

    next_cursor = None
    if has_more and visible_rows:
        last = visible_rows[-1]
        next_cursor = encode_follow_up_review_cursor(
            due_filter=due_filter,
            evaluation_time=moment,
            created_at=last.created_at,
            finding_id=last.finding_id,
        )

    return FindingFollowUpReviewResponse(
        evaluation_time=moment,
        items=items,
        next_cursor=next_cursor,
    )
