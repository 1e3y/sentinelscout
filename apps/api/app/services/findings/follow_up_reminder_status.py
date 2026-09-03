"""Read-only follow-up reminder delivery status (Milestone 35).

DB-only. Never calls Clerk, providers, discovery, claim, or audit.
OrganizationMembership is NOT used as an authoritative membership claim.
display_name is current User.name presentation metadata only.
"""

from __future__ import annotations

import binascii
from base64 import urlsafe_b64decode, urlsafe_b64encode
from datetime import datetime, timezone
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session, load_only

from app.core.config import get_settings
from app.models.finding import Finding
from app.models.finding_follow_up_reminder import (
    REMINDER_KIND_DUE,
    FindingFollowUpReminderJob,
)
from app.models.notification import OrganizationNotificationSettings
from app.models.user import User
from app.schemas.finding_follow_up_reminder_status import (
    FindingFollowUpReminderHistoryItem,
    FindingFollowUpReminderHistoryResponse,
    FindingFollowUpReminderStatusResponse,
    ReminderCurrentGeneration,
    ReminderDeliveryFacts,
    ReminderOwnerPresentation,
    ReminderCustomerState,
    ReminderJobCustomerState,
    SafeReasonCode,
)
from app.services.delivery_status import map_delivery_db_status_to_customer_state
from app.services.findings.follow_up_reminders import resolve_current_follow_up_generation
from app.services.findings.remediation import get_finding_or_404

DEFAULT_HISTORY_PAGE_SIZE = 20
MAX_HISTORY_PAGE_SIZE = 50
HISTORY_CURSOR_VERSION = "v1"
INVALID_HISTORY_CURSOR_DETAIL = "Invalid follow-up reminder history cursor"

# Business skip codes that may surface specifically when skipped/dead.
_BUSINESS_SKIP_CODES: frozenset[str] = frozenset(
    {
        "finding_resolved",
        "owner_changed",
        "due_changed",
        "follow_up_generation_changed",
        "assignee_not_current_member",
        "recipient_no_deliverable_email",
        "recipient_changed",
        "staging_destination_not_allowed",
        "missing_delivery_snapshot",
        "reminders_disabled",
    }
)

_SAFE_LABELS: dict[SafeReasonCode, str] = {
    "finding_resolved": "Finding was resolved before the reminder was sent.",
    "owner_changed": "The assigned owner changed before delivery.",
    "due_changed": "The follow-up due date changed before delivery.",
    "follow_up_generation_changed": "Follow-up details changed before delivery.",
    "assignee_not_current_member": (
        "The assignee is no longer a current organization member."
    ),
    "recipient_no_deliverable_email": (
        "The assignee has no deliverable email address."
    ),
    "recipient_changed": (
        "The assignee's delivery address changed before retry."
    ),
    "staging_destination_not_allowed": (
        "Delivery was not allowed in this environment."
    ),
    "missing_delivery_snapshot": (
        "Reminder delivery could not continue safely."
    ),
    "reminders_disabled": "Follow-up reminders were turned off.",
    "identity_provider_unavailable": (
        "Membership or delivery-address verification is temporarily unavailable. "
        "Delivery will be retried."
    ),
    "max_attempts_exceeded": "Delivery attempts were exhausted.",
    "delivery_temporarily_unavailable": (
        "Reminder delivery is temporarily unavailable. Delivery will be retried."
    ),
    "delivery_issue": "Reminder delivery could not be completed.",
}

# Explicit columns — never load delivery_snapshot / last_error / processing_token.
_JOB_LOAD_COLUMNS = (
    FindingFollowUpReminderJob.id,
    FindingFollowUpReminderJob.organization_id,
    FindingFollowUpReminderJob.finding_id,
    FindingFollowUpReminderJob.follow_up_change_id,
    FindingFollowUpReminderJob.assigned_to_user_id,
    FindingFollowUpReminderJob.due_at,
    FindingFollowUpReminderJob.reminder_kind,
    FindingFollowUpReminderJob.status,
    FindingFollowUpReminderJob.last_error_code,
    FindingFollowUpReminderJob.created_at,
    FindingFollowUpReminderJob.delivered_at,
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def encode_reminder_history_cursor(*, created_at: datetime, job_id: UUID) -> str:
    payload = f"{HISTORY_CURSOR_VERSION}|{created_at.isoformat()}|{job_id}"
    return urlsafe_b64encode(payload.encode("utf-8")).decode("ascii").rstrip("=")


def decode_reminder_history_cursor(raw: str) -> tuple[datetime, UUID]:
    if not raw or not raw.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=INVALID_HISTORY_CURSOR_DETAIL,
        )
    padded = raw + ("=" * (-len(raw) % 4))
    try:
        decoded = urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=INVALID_HISTORY_CURSOR_DETAIL,
        ) from exc
    parts = decoded.split("|")
    if len(parts) != 3 or parts[0] != HISTORY_CURSOR_VERSION:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=INVALID_HISTORY_CURSOR_DETAIL,
        )
    try:
        created_at = datetime.fromisoformat(parts[1])
        job_id = UUID(parts[2])
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=INVALID_HISTORY_CURSOR_DETAIL,
        ) from exc
    if created_at.tzinfo is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=INVALID_HISTORY_CURSOR_DETAIL,
        )
    return created_at, job_id


def map_job_status_to_customer_state(db_status: str) -> ReminderJobCustomerState:
    """Thin wrapper over shared mapper — M35 output vocabulary unchanged."""
    return map_delivery_db_status_to_customer_state(db_status)


def project_safe_reason(
    *,
    customer_state: ReminderCustomerState | ReminderJobCustomerState,
    last_error_code: str | None,
) -> tuple[SafeReasonCode | None, str | None]:
    """State-aware safe reason (Correction 4). Never returns raw last_error."""
    if customer_state in {
        "disabled",
        "not_applicable",
        "generation_unavailable",
        "scheduled_for_future",
        "awaiting_discovery",
        "pending",
        "processing",
        "delivered",
    }:
        return None, None

    code = (last_error_code or "").strip() or None

    if customer_state == "retrying":
        if code == "identity_provider_unavailable":
            return (
                "identity_provider_unavailable",
                _SAFE_LABELS["identity_provider_unavailable"],
            )
        if code in _BUSINESS_SKIP_CODES:
            safe = code  # type: ignore[assignment]
            return safe, _SAFE_LABELS[safe]  # type: ignore[index]
        # provider_* / unknown / None → temporary
        return (
            "delivery_temporarily_unavailable",
            _SAFE_LABELS["delivery_temporarily_unavailable"],
        )

    # skipped or dead (terminal)
    if code == "max_attempts_exceeded":
        return "max_attempts_exceeded", _SAFE_LABELS["max_attempts_exceeded"]
    if code in _BUSINESS_SKIP_CODES:
        safe = code  # type: ignore[assignment]
        return safe, _SAFE_LABELS[safe]  # type: ignore[index]
    # identity_provider_unavailable / provider_* / unknown when terminal
    return "delivery_issue", _SAFE_LABELS["delivery_issue"]


def _reminders_enabled(db: Session, *, organization_id: UUID) -> bool:
    settings = db.scalar(
        select(OrganizationNotificationSettings).where(
            OrganizationNotificationSettings.organization_id == organization_id
        )
    )
    if settings is None:
        return False
    return bool(settings.finding_follow_up_reminders_enabled)


def _owner_presentation(
    db: Session, *, user_id: UUID | None
) -> ReminderOwnerPresentation | None:
    if user_id is None:
        return None
    user = db.scalar(
        select(User).options(load_only(User.id, User.name)).where(User.id == user_id)
    )
    if user is None:
        return ReminderOwnerPresentation(user_id=user_id, display_name=None)
    return ReminderOwnerPresentation(user_id=user.id, display_name=user.name)


def _load_current_job(
    db: Session, *, finding_id: UUID, follow_up_change_id: UUID
) -> FindingFollowUpReminderJob | None:
    return db.scalar(
        select(FindingFollowUpReminderJob)
        .options(load_only(*_JOB_LOAD_COLUMNS))
        .where(
            FindingFollowUpReminderJob.finding_id == finding_id,
            FindingFollowUpReminderJob.follow_up_change_id == follow_up_change_id,
            FindingFollowUpReminderJob.reminder_kind == REMINDER_KIND_DUE,
        )
    )


def get_finding_follow_up_reminder_status(
    db: Session,
    *,
    finding_id: UUID,
    user_id: UUID,
    organization_id: UUID,
) -> FindingFollowUpReminderStatusResponse:
    finding = get_finding_or_404(db, finding_id=finding_id, user_id=user_id)
    if finding.organization_id != organization_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found"
        )

    reminders_enabled = _reminders_enabled(db, organization_id=organization_id)
    email_delivery_enabled = bool(get_settings().email_delivery_enabled)
    now = _now()

    generation = resolve_current_follow_up_generation(db, finding)
    current_generation: ReminderCurrentGeneration | None = None
    if finding.assigned_to_user_id is not None and finding.follow_up_due_at is not None:
        owner = _owner_presentation(db, user_id=finding.assigned_to_user_id)
        if owner is not None:
            current_generation = ReminderCurrentGeneration(
                due_at=finding.follow_up_due_at,
                owner=owner,
            )

    reminder_facts: ReminderDeliveryFacts | None = None
    state: ReminderCustomerState

    if not reminders_enabled:
        state = "disabled"
    elif finding.status == "resolved":
        state = "not_applicable"
    elif finding.assigned_to_user_id is None or finding.follow_up_due_at is None:
        state = "not_applicable"
    elif generation is None:
        # Correction 2: owner+due but no resolvable M33 generation.
        state = "generation_unavailable"
    else:
        job = _load_current_job(
            db, finding_id=finding.id, follow_up_change_id=generation.id
        )
        if job is None:
            if finding.follow_up_due_at > now:
                state = "scheduled_for_future"
            else:
                state = "awaiting_discovery"
        else:
            state = map_job_status_to_customer_state(job.status)
            reason_code, reason_label = project_safe_reason(
                customer_state=state,
                last_error_code=job.last_error_code,
            )
            reminder_facts = ReminderDeliveryFacts(
                safe_reason_code=reason_code,
                safe_reason_label=reason_label,
                created_at=job.created_at,
                delivered_at=job.delivered_at,
            )

    return FindingFollowUpReminderStatusResponse(
        finding_id=finding.id,
        reminders_enabled=reminders_enabled,
        email_delivery_enabled=email_delivery_enabled,
        state=state,
        current_generation=current_generation,
        reminder=reminder_facts,
    )


def list_finding_follow_up_reminders(
    db: Session,
    *,
    finding_id: UUID,
    user_id: UUID,
    organization_id: UUID,
    page_size: int = DEFAULT_HISTORY_PAGE_SIZE,
    cursor: str | None = None,
) -> FindingFollowUpReminderHistoryResponse:
    finding = get_finding_or_404(db, finding_id=finding_id, user_id=user_id)
    if finding.organization_id != organization_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found"
        )

    size = min(max(page_size, 1), MAX_HISTORY_PAGE_SIZE)
    stmt = (
        select(FindingFollowUpReminderJob)
        .options(load_only(*_JOB_LOAD_COLUMNS))
        .where(
            FindingFollowUpReminderJob.finding_id == finding.id,
            FindingFollowUpReminderJob.organization_id == organization_id,
        )
        .order_by(
            FindingFollowUpReminderJob.created_at.desc(),
            FindingFollowUpReminderJob.id.desc(),
        )
        .limit(size + 1)
    )
    if cursor:
        cursor_at, cursor_id = decode_reminder_history_cursor(cursor)
        stmt = stmt.where(
            or_(
                FindingFollowUpReminderJob.created_at < cursor_at,
                and_(
                    FindingFollowUpReminderJob.created_at == cursor_at,
                    FindingFollowUpReminderJob.id < cursor_id,
                ),
            )
        )

    rows = list(db.scalars(stmt).all())
    has_more = len(rows) > size
    page = rows[:size]
    next_cursor = None
    if has_more and page:
        last = page[-1]
        next_cursor = encode_reminder_history_cursor(
            created_at=last.created_at, job_id=last.id
        )

    owner_ids = {row.assigned_to_user_id for row in page}
    users_by_id: dict[UUID, User] = {}
    if owner_ids:
        users_by_id = {
            user.id: user
            for user in db.scalars(
                select(User)
                .options(load_only(User.id, User.name))
                .where(User.id.in_(owner_ids))
            ).all()
        }

    items: list[FindingFollowUpReminderHistoryItem] = []
    for row in page:
        customer_state = map_job_status_to_customer_state(row.status)
        reason_code, reason_label = project_safe_reason(
            customer_state=customer_state,
            last_error_code=row.last_error_code,
        )
        user = users_by_id.get(row.assigned_to_user_id)
        owner = ReminderOwnerPresentation(
            user_id=row.assigned_to_user_id,
            display_name=user.name if user is not None else None,
        )
        items.append(
            FindingFollowUpReminderHistoryItem(
                reminder_kind="due",
                due_at=row.due_at,
                owner=owner,
                state=customer_state,
                safe_reason_code=reason_code,
                safe_reason_label=reason_label,
                created_at=row.created_at,
                delivered_at=row.delivered_at,
            )
        )

    return FindingFollowUpReminderHistoryResponse(
        finding_id=finding.id,
        page_size=size,
        next_cursor=next_cursor,
        items=items,
    )
