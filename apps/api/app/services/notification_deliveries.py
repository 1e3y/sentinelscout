"""Organization notification delivery ledger (Milestone 36).

Admin-only, read-only, DB-only. Mixed-source keyset pagination with
org/state/cursor predicates pushed into each branch before LIMIT.
"""

from __future__ import annotations

import binascii
from base64 import urlsafe_b64decode, urlsafe_b64encode
from datetime import datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import String, and_, cast, false, literal, or_, select, true, union_all
from sqlalchemy.dialects.postgresql import TIMESTAMP
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Session, load_only

from app.core.config import get_settings
from app.models.alert import Alert, NotificationOutbox
from app.models.asset import Asset
from app.models.finding import Finding
from app.models.finding_follow_up_reminder import FindingFollowUpReminderJob
from app.models.notification import OrganizationNotificationSettings
from app.models.report import AssessmentReport
from app.models.report_delivery import AssessmentReportDeliveryOutbox
from app.models.target import AuthorizedTarget
from app.models.user import User
from app.schemas.notification_deliveries import (
    AlertEmailDetail,
    DeliveryClass,
    DeliveryTargetRef,
    ExternalRecipient,
    FollowUpReminderDetail,
    NotificationDeliveriesResponse,
    NotificationDeliveryConfiguration,
    NotificationDeliveryRow,
    OrganizationMemberRecipient,
    ReportDeliveryDetail,
)
from app.services.delivery_status import (
    CUSTOMER_STATE_TO_DB_STATUS,
    DeliveryCustomerState,
    map_delivery_db_status_to_customer_state,
    project_delivery_safe_reason,
)

DEFAULT_PAGE_SIZE = 20
MAX_PAGE_SIZE = 50
CURSOR_VERSION = "v1"
INVALID_CURSOR_DETAIL = "Invalid notification delivery cursor"

CLASS_RANKS: dict[DeliveryClass, int] = {
    "alert_email": 30,
    "report_delivery": 20,
    "follow_up_reminder": 10,
}
VALID_RANKS = frozenset(CLASS_RANKS.values())


def encode_delivery_cursor(
    *, created_at: datetime, class_rank: int, source_uuid: UUID
) -> str:
    payload = f"{CURSOR_VERSION}|{created_at.isoformat()}|{class_rank}|{source_uuid}"
    return urlsafe_b64encode(payload.encode("utf-8")).decode("ascii").rstrip("=")


def decode_delivery_cursor(raw: str) -> tuple[datetime, int, UUID]:
    if not raw or not raw.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=INVALID_CURSOR_DETAIL,
        )
    padded = raw + ("=" * (-len(raw) % 4))
    try:
        decoded = urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=INVALID_CURSOR_DETAIL,
        ) from exc
    parts = decoded.split("|")
    if len(parts) != 4 or parts[0] != CURSOR_VERSION:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=INVALID_CURSOR_DETAIL,
        )
    try:
        created_at = datetime.fromisoformat(parts[1])
        class_rank = int(parts[2])
        source_uuid = UUID(parts[3])
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=INVALID_CURSOR_DETAIL,
        ) from exc
    if created_at.tzinfo is None or class_rank not in VALID_RANKS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=INVALID_CURSOR_DETAIL,
        )
    return created_at, class_rank, source_uuid


def _cursor_condition(
    *,
    created_at,
    class_rank: int,
    source_uuid,
    cursor_position: tuple[datetime, int, UUID] | None,
):
    """Lexicographic keyset predicate. class_rank is the branch constant (int)."""
    if cursor_position is None:
        return true()
    cursor_at, cursor_rank, cursor_uuid = cursor_position
    return or_(
        created_at < cursor_at,
        and_(created_at == cursor_at, class_rank < cursor_rank),
        and_(
            created_at == cursor_at,
            class_rank == cursor_rank,
            source_uuid < cursor_uuid,
        ),
    )


def _null_uuid():
    return cast(literal(None), PG_UUID(as_uuid=True))


def _null_string():
    return cast(literal(None), String())


def _null_timestamptz():
    return cast(literal(None), TIMESTAMP(timezone=True))


def _state_filter(column, state: DeliveryCustomerState | None):
    if state is None:
        return true()
    return column == CUSTOMER_STATE_TO_DB_STATUS[state]


def _normalized_branch(
    *,
    created_at,
    class_rank: int,
    source_uuid,
    delivery_class: str,
    db_status,
    last_error_code,
    delivered_at,
    alert_id=None,
    report_id=None,
    finding_id=None,
    recipient_user_id=None,
    due_at=None,
    frozen_target_domain=None,
):
    return select(
        created_at.label("created_at"),
        literal(class_rank).label("class_rank"),
        source_uuid.label("source_uuid"),
        literal(delivery_class).label("delivery_class"),
        db_status.label("db_status"),
        last_error_code.label("last_error_code"),
        delivered_at.label("delivered_at"),
        (alert_id if alert_id is not None else _null_uuid()).label("alert_id"),
        (report_id if report_id is not None else _null_uuid()).label("report_id"),
        (finding_id if finding_id is not None else _null_uuid()).label("finding_id"),
        (
            recipient_user_id if recipient_user_id is not None else _null_uuid()
        ).label("recipient_user_id"),
        (due_at if due_at is not None else _null_timestamptz()).label("due_at"),
        (
            frozen_target_domain
            if frozen_target_domain is not None
            else _null_string()
        ).label("frozen_target_domain"),
    )


def _bound_branch(statement, *, class_rank: int, size: int, cursor_position, order_cols):
    """Apply cursor + order + LIMIT inside the branch (before UNION)."""
    source = statement.subquery()
    return (
        select(source)
        .where(
            _cursor_condition(
                created_at=source.c.created_at,
                class_rank=class_rank,
                source_uuid=source.c.source_uuid,
                cursor_position=cursor_position,
            )
        )
        .order_by(*order_cols(source))
        .limit(size + 1)
        .subquery()
    )


def build_notification_deliveries_statement(
    *,
    organization_id: UUID,
    size: int,
    cursor_position: tuple[datetime, int, UUID] | None,
    delivery_class: DeliveryClass | None,
    state: DeliveryCustomerState | None,
):
    """One compiled UNION ALL (or single-branch) statement with pushed filters."""

    branches = []

    include_alert = delivery_class in (None, "alert_email")
    include_report = delivery_class in (None, "report_delivery")
    include_reminder = delivery_class in (None, "follow_up_reminder")

    if include_alert:
        alert_rank = CLASS_RANKS["alert_email"]
        alert_base = _normalized_branch(
            created_at=NotificationOutbox.created_at,
            class_rank=alert_rank,
            source_uuid=NotificationOutbox.id,
            delivery_class="alert_email",
            db_status=NotificationOutbox.status,
            last_error_code=NotificationOutbox.last_error_code,
            delivered_at=NotificationOutbox.delivered_at,
            alert_id=NotificationOutbox.alert_id,
            recipient_user_id=NotificationOutbox.recipient_user_id,
        ).where(
            NotificationOutbox.organization_id == organization_id,
            NotificationOutbox.channel == "email",
            _state_filter(NotificationOutbox.status, state),
        )
        branches.append(
            _bound_branch(
                alert_base,
                class_rank=alert_rank,
                size=size,
                cursor_position=cursor_position,
                order_cols=lambda s: (
                    s.c.created_at.desc(),
                    s.c.source_uuid.desc(),
                ),
            )
        )

    if include_report:
        report_rank = CLASS_RANKS["report_delivery"]
        report_base = _normalized_branch(
            created_at=AssessmentReportDeliveryOutbox.created_at,
            class_rank=report_rank,
            source_uuid=AssessmentReportDeliveryOutbox.id,
            delivery_class="report_delivery",
            db_status=AssessmentReportDeliveryOutbox.status,
            last_error_code=AssessmentReportDeliveryOutbox.last_error_code,
            delivered_at=AssessmentReportDeliveryOutbox.delivered_at,
            report_id=AssessmentReportDeliveryOutbox.report_id,
            frozen_target_domain=AssessmentReportDeliveryOutbox.frozen_target_domain,
        ).where(
            AssessmentReportDeliveryOutbox.organization_id == organization_id,
            _state_filter(AssessmentReportDeliveryOutbox.status, state),
        )
        branches.append(
            _bound_branch(
                report_base,
                class_rank=report_rank,
                size=size,
                cursor_position=cursor_position,
                order_cols=lambda s: (
                    s.c.created_at.desc(),
                    s.c.source_uuid.desc(),
                ),
            )
        )

    if include_reminder:
        reminder_rank = CLASS_RANKS["follow_up_reminder"]
        reminder_base = _normalized_branch(
            created_at=FindingFollowUpReminderJob.created_at,
            class_rank=reminder_rank,
            source_uuid=FindingFollowUpReminderJob.id,
            delivery_class="follow_up_reminder",
            db_status=FindingFollowUpReminderJob.status,
            last_error_code=FindingFollowUpReminderJob.last_error_code,
            delivered_at=FindingFollowUpReminderJob.delivered_at,
            finding_id=FindingFollowUpReminderJob.finding_id,
            recipient_user_id=FindingFollowUpReminderJob.assigned_to_user_id,
            due_at=FindingFollowUpReminderJob.due_at,
        ).where(
            FindingFollowUpReminderJob.organization_id == organization_id,
            _state_filter(FindingFollowUpReminderJob.status, state),
        )
        branches.append(
            _bound_branch(
                reminder_base,
                class_rank=reminder_rank,
                size=size,
                cursor_position=cursor_position,
                order_cols=lambda s: (
                    s.c.created_at.desc(),
                    s.c.source_uuid.desc(),
                ),
            )
        )

    if not branches:
        empty = _normalized_branch(
            created_at=NotificationOutbox.created_at,
            class_rank=0,
            source_uuid=NotificationOutbox.id,
            delivery_class="alert_email",
            db_status=NotificationOutbox.status,
            last_error_code=NotificationOutbox.last_error_code,
            delivered_at=NotificationOutbox.delivered_at,
        ).where(false())
        return select(empty.subquery()).limit(0)

    if len(branches) == 1:
        combined = select(branches[0]).subquery("notification_deliveries")
    else:
        combined = union_all(*(select(b) for b in branches)).subquery(
            "notification_deliveries"
        )

    return (
        select(combined)
        .order_by(
            combined.c.created_at.desc(),
            combined.c.class_rank.desc(),
            combined.c.source_uuid.desc(),
        )
        .limit(size + 1)
    )


def _configuration(db: Session, *, organization_id: UUID) -> NotificationDeliveryConfiguration:
    settings = db.scalar(
        select(OrganizationNotificationSettings).options(
            load_only(
                OrganizationNotificationSettings.organization_id,
                OrganizationNotificationSettings.email_enabled,
                OrganizationNotificationSettings.finding_follow_up_reminders_enabled,
            )
        ).where(OrganizationNotificationSettings.organization_id == organization_id)
    )
    return NotificationDeliveryConfiguration(
        alert_email_enabled=bool(settings.email_enabled) if settings else False,
        follow_up_reminders_enabled=(
            bool(settings.finding_follow_up_reminders_enabled) if settings else False
        ),
        email_delivery_enabled=bool(get_settings().email_delivery_enabled),
    )


def _enrich_page(
    db: Session,
    *,
    organization_id: UUID,
    rows: list[Any],
) -> list[NotificationDeliveryRow]:
    alert_ids = {r.alert_id for r in rows if r.alert_id is not None}
    report_ids = {r.report_id for r in rows if r.report_id is not None}
    finding_ids = {r.finding_id for r in rows if r.finding_id is not None}
    user_ids = {r.recipient_user_id for r in rows if r.recipient_user_id is not None}

    alerts: dict[UUID, Alert] = {}
    if alert_ids:
        for alert in db.scalars(
            select(Alert)
            .options(
                load_only(
                    Alert.id,
                    Alert.organization_id,
                    Alert.target_id,
                    Alert.alert_type,
                    Alert.priority,
                    Alert.category,
                )
            )
            .where(
                Alert.organization_id == organization_id,
                Alert.id.in_(alert_ids),
            )
        ).all():
            alerts[alert.id] = alert

    reports: dict[UUID, AssessmentReport] = {}
    if report_ids:
        for report in db.scalars(
            select(AssessmentReport)
            .options(
                load_only(
                    AssessmentReport.id,
                    AssessmentReport.organization_id,
                    AssessmentReport.target_id,
                    AssessmentReport.report_version,
                    AssessmentReport.generation_origin,
                    AssessmentReport.target_domain,
                )
            )
            .where(
                AssessmentReport.organization_id == organization_id,
                AssessmentReport.id.in_(report_ids),
            )
        ).all():
            reports[report.id] = report

    findings: dict[UUID, Finding] = {}
    asset_ids: set[UUID] = set()
    if finding_ids:
        for finding in db.scalars(
            select(Finding)
            .options(
                load_only(
                    Finding.id,
                    Finding.organization_id,
                    Finding.asset_id,
                    Finding.title,
                )
            )
            .where(
                Finding.organization_id == organization_id,
                Finding.id.in_(finding_ids),
            )
        ).all():
            findings[finding.id] = finding
            asset_ids.add(finding.asset_id)

    assets: dict[UUID, Asset] = {}
    target_ids: set[UUID] = set()
    if asset_ids:
        for asset in db.scalars(
            select(Asset)
            .options(load_only(Asset.id, Asset.target_id, Asset.organization_id))
            .where(
                Asset.organization_id == organization_id,
                Asset.id.in_(asset_ids),
            )
        ).all():
            assets[asset.id] = asset
            target_ids.add(asset.target_id)

    for alert in alerts.values():
        target_ids.add(alert.target_id)
    for report in reports.values():
        target_ids.add(report.target_id)

    targets: dict[UUID, AuthorizedTarget] = {}
    if target_ids:
        for target in db.scalars(
            select(AuthorizedTarget)
            .options(
                load_only(
                    AuthorizedTarget.id,
                    AuthorizedTarget.organization_id,
                    AuthorizedTarget.domain,
                )
            )
            .where(
                AuthorizedTarget.organization_id == organization_id,
                AuthorizedTarget.id.in_(target_ids),
            )
        ).all():
            targets[target.id] = target

    users: dict[UUID, User] = {}
    if user_ids:
        for user in db.scalars(
            select(User)
            .options(load_only(User.id, User.name))
            .where(User.id.in_(user_ids))
        ).all():
            users[user.id] = user

    items: list[NotificationDeliveryRow] = []
    for row in rows:
        delivery_class: DeliveryClass = row.delivery_class  # type: ignore[assignment]
        customer_state = map_delivery_db_status_to_customer_state(row.db_status)
        safe_code, safe_label = project_delivery_safe_reason(
            delivery_class=delivery_class,
            customer_state=customer_state,
            internal_code=row.last_error_code,
        )

        target_ref: DeliveryTargetRef | None = None
        detail: AlertEmailDetail | ReportDeliveryDetail | FollowUpReminderDetail
        recipient = None

        if delivery_class == "alert_email":
            alert = alerts.get(row.alert_id) if row.alert_id else None
            if alert is None:
                continue
            target = targets.get(alert.target_id)
            if target is not None:
                target_ref = DeliveryTargetRef(
                    target_id=target.id, domain=target.domain
                )
            detail = AlertEmailDetail(
                alert_id=alert.id,
                alert_type=alert.alert_type,
                priority=alert.priority,
                category=alert.category,
            )
            if row.recipient_user_id is not None:
                user = users.get(row.recipient_user_id)
                recipient = OrganizationMemberRecipient(
                    user_id=row.recipient_user_id,
                    display_name=user.name if user is not None else None,
                )
        elif delivery_class == "report_delivery":
            report = reports.get(row.report_id) if row.report_id else None
            domain = row.frozen_target_domain
            target_id = report.target_id if report is not None else None
            if target_id is not None:
                target = targets.get(target_id)
                if target is not None:
                    target_ref = DeliveryTargetRef(
                        target_id=target.id, domain=target.domain
                    )
                elif domain:
                    # Domain from outbox freeze is enough when target row missing.
                    target_ref = DeliveryTargetRef(
                        target_id=target_id, domain=domain
                    )
            elif domain and report is not None:
                target_ref = DeliveryTargetRef(
                    target_id=report.target_id, domain=domain
                )
            detail = ReportDeliveryDetail(
                report_id=row.report_id,
                report_version=report.report_version if report else None,
                generation_origin=report.generation_origin if report else None,
            )
            recipient = ExternalRecipient()
        else:
            finding = findings.get(row.finding_id) if row.finding_id else None
            if finding is None:
                continue
            asset = assets.get(finding.asset_id)
            if asset is not None:
                target = targets.get(asset.target_id)
                if target is not None:
                    target_ref = DeliveryTargetRef(
                        target_id=target.id, domain=target.domain
                    )
            detail = FollowUpReminderDetail(
                finding_id=finding.id,
                finding_title=finding.title,
                due_at=row.due_at,
            )
            if row.recipient_user_id is not None:
                user = users.get(row.recipient_user_id)
                recipient = OrganizationMemberRecipient(
                    user_id=row.recipient_user_id,
                    display_name=user.name if user is not None else None,
                )

        items.append(
            NotificationDeliveryRow(
                delivery_class=delivery_class,
                state=customer_state,
                safe_reason_code=safe_code,
                safe_reason_label=safe_label,
                created_at=row.created_at,
                delivered_at=row.delivered_at,
                target=target_ref,
                detail=detail,
                recipient=recipient,
            )
        )
    return items


def list_notification_deliveries(
    db: Session,
    *,
    organization_id: UUID,
    page_size: int = DEFAULT_PAGE_SIZE,
    cursor: str | None = None,
    delivery_class: DeliveryClass | None = None,
    state: DeliveryCustomerState | None = None,
) -> NotificationDeliveriesResponse:
    size = page_size
    cursor_position = decode_delivery_cursor(cursor) if cursor else None
    statement = build_notification_deliveries_statement(
        organization_id=organization_id,
        size=size,
        cursor_position=cursor_position,
        delivery_class=delivery_class,
        state=state,
    )
    raw_rows = list(db.execute(statement).all())
    has_more = len(raw_rows) > size
    page_rows = raw_rows[:size]
    items = _enrich_page(db, organization_id=organization_id, rows=page_rows)

    next_cursor = None
    if has_more and page_rows:
        last = page_rows[-1]
        next_cursor = encode_delivery_cursor(
            created_at=last.created_at,
            class_rank=int(last.class_rank),
            source_uuid=last.source_uuid,
        )

    return NotificationDeliveriesResponse(
        configuration=_configuration(db, organization_id=organization_id),
        items=items,
        next_cursor=next_cursor,
    )


def compile_notification_deliveries_sql(
    *,
    organization_id: UUID,
    size: int = 20,
    cursor_position: tuple[datetime, int, UUID] | None = None,
    delivery_class: DeliveryClass | None = None,
    state: DeliveryCustomerState | None = None,
) -> str:
    """Compile statement to SQL string for tests / EXPLAIN helpers."""
    from sqlalchemy.dialects import postgresql

    statement = build_notification_deliveries_statement(
        organization_id=organization_id,
        size=size,
        cursor_position=cursor_position,
        delivery_class=delivery_class,
        state=state,
    )
    return str(
        statement.compile(
            dialect=postgresql.dialect(),
            compile_kwargs={"literal_binds": True},
        )
    )
