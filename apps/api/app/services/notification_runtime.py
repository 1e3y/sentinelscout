"""Email outbox enqueue, SKIP LOCKED claim, lease fencing, and send."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Literal
from uuid import UUID, uuid4

from sqlalchemy import or_, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings, get_settings
from app.models.alert import Alert, NotificationOutbox
from app.models.notification import OrganizationEmailRecipient
from app.models.operation import Operation
from app.models.organization import Organization, OrganizationMembership
from app.models.target import AuthorizedTarget
from app.models.user import User
from app.services.email_content import (
    build_email_subject,
    build_email_text,
    dashboard_url,
    destination_key_for_user,
    freeze_delivery_snapshot,
)
from app.services.email_provider import EmailProvider, EmailSendRequest, build_email_provider
from app.services.notification_settings import (
    email_should_enqueue,
    get_or_default_settings,
)

logger = logging.getLogger("scout.notification_worker")

CHANNEL_EMAIL = "email"
MAX_ATTEMPTS = 8
BACKOFF_BASE_SECONDS = 60
BACKOFF_CAP_SECONDS = 3600

SKIP_RECIPIENT_UNAUTHORIZED = "recipient_unauthorized"
SKIP_RECIPIENT_IDENTITY_CHANGED = "recipient_identity_changed"
SKIP_STAGING_DESTINATION = "staging_destination_not_allowed"
SKIP_MISSING_SNAPSHOT = "missing_delivery_snapshot"

DeliveryRuntimeStatus = Literal["paused", "ready", "not_ready"]


class NotificationWorkerNotReady(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class DeliveryReadiness:
    status: DeliveryRuntimeStatus
    reason: str | None = None


def _now() -> datetime:
    return datetime.now(timezone.utc)


def normalize_email(value: str | None) -> str:
    return (value or "").strip().lower()


def email_delivery_readiness(settings: Any) -> DeliveryReadiness:
    if not settings.email_delivery_enabled:
        return DeliveryReadiness(status="paused", reason="email_delivery_disabled")
    provider = settings.email_provider
    if settings.environment == "test" and provider == "fake":
        return DeliveryReadiness(status="ready")
    if provider == "fake":
        if settings.environment in {"staging", "production"}:
            return DeliveryReadiness(status="not_ready", reason="invalid_email_provider")
        return DeliveryReadiness(status="ready")
    if provider != "resend":
        return DeliveryReadiness(status="not_ready", reason="invalid_email_provider")
    if not settings.email_api_key.strip() or not settings.email_from.strip():
        return DeliveryReadiness(status="not_ready", reason="invalid_email_provider_config")
    if settings.environment == "staging" and not settings.staging_email_allowlist:
        return DeliveryReadiness(status="not_ready", reason="missing_staging_allowlist")
    return DeliveryReadiness(status="ready")


def retry_delay_seconds(attempt_count: int) -> int:
    exponent = max(attempt_count - 1, 0)
    return min(BACKOFF_BASE_SECONDS * (2**exponent), BACKOFF_CAP_SECONDS)


def enqueue_email_outbox(db: Session, alert: Alert, *, settings: Settings | None = None) -> None:
    cfg = settings or get_settings()
    org_settings = get_or_default_settings(db, organization_id=alert.organization_id)
    if org_settings is None or not org_settings.email_enabled:
        return
    if not email_should_enqueue(alert.priority, org_settings.email_min_priority):
        return
    recipients = list(
        db.execute(
            select(OrganizationEmailRecipient, User)
            .join(User, User.id == OrganizationEmailRecipient.user_id)
            .where(OrganizationEmailRecipient.organization_id == alert.organization_id)
        ).all()
    )
    if not recipients:
        return
    organization = db.get(Organization, alert.organization_id)
    target = db.get(AuthorizedTarget, alert.target_id)
    operation = db.get(Operation, alert.operation_id)
    if organization is None or target is None:
        return
    org_name = organization.name
    target_domain = target.domain
    operation_time = operation.completed_at if operation is not None else None
    dash = dashboard_url(cfg.frontend_url)
    from_email = cfg.email_from
    now = _now()
    for _row, user in recipients:
        if not user.email_verified or not user.email:
            continue
        dest = destination_key_for_user(user.id)
        subject = build_email_subject(organization_name=org_name, alert=alert)
        text_body = build_email_text(
            organization_name=org_name,
            target_domain=target_domain,
            alert=alert,
            operation_time=operation_time,
            dashboard_url_value=dash,
        )
        snapshot = freeze_delivery_snapshot(
            recipient_user_id=user.id,
            recipient_email=user.email,
            from_email=from_email,
            subject=subject,
            text_body=text_body,
            dashboard_url_value=dash,
            alert=alert,
        )
        db.execute(
            pg_insert(NotificationOutbox)
            .values(
                id=uuid4(),
                organization_id=alert.organization_id,
                alert_id=alert.id,
                channel=CHANNEL_EMAIL,
                destination_key=dest,
                status="pending",
                payload={},
                delivery_snapshot=snapshot,
                recipient_user_id=user.id,
                attempt_count=0,
                last_error=None,
                last_error_code=None,
                available_at=now,
                created_at=now,
                delivered_at=None,
            )
            .on_conflict_do_nothing(constraint="uq_notification_outbox_destination")
        )


def request_from_snapshot(outbox_id: UUID, snapshot: dict[str, Any]) -> EmailSendRequest:
    tags_raw = snapshot.get("tags") or []
    tags: list[tuple[str, str]] = []
    if isinstance(tags_raw, list):
        for item in tags_raw:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            value = item.get("value")
            if isinstance(name, str) and isinstance(value, str):
                tags.append((name, value))
    return EmailSendRequest(
        idempotency_key=str(outbox_id),
        from_email=str(snapshot.get("from_email_snapshot") or ""),
        to_email=str(snapshot.get("recipient_email_snapshot") or ""),
        subject=str(snapshot.get("subject_snapshot") or ""),
        text_body=str(snapshot.get("text_body_snapshot") or ""),
        tags=tuple(tags),
    )


def claim_email_outbox(
    db: Session,
    *,
    now: datetime | None = None,
    lease_seconds: int = 300,
) -> tuple[NotificationOutbox, UUID] | None:
    moment = now or _now()
    row = db.scalar(
        select(NotificationOutbox)
        .where(
            NotificationOutbox.channel == CHANNEL_EMAIL,
            or_(
                (
                    NotificationOutbox.status.in_(("pending", "failed"))
                    & (NotificationOutbox.available_at <= moment)
                ),
                (
                    (NotificationOutbox.status == "processing")
                    & (NotificationOutbox.lease_expires_at.is_not(None))
                    & (NotificationOutbox.lease_expires_at <= moment)
                ),
            ),
        )
        .order_by(NotificationOutbox.available_at.asc())
        .with_for_update(skip_locked=True)
        .limit(1)
    )
    if row is None:
        return None
    token = uuid4()
    row.status = "processing"
    row.processing_token = token
    row.lease_expires_at = moment + timedelta(seconds=lease_seconds)
    row.attempt_count = int(row.attempt_count or 0) + 1
    row.last_attempt_at = moment
    db.commit()
    db.refresh(row)
    return row, token


def complete_claimed_outbox(
    db: Session,
    *,
    outbox_id: UUID,
    processing_token: UUID,
    values: dict[str, Any],
) -> bool:
    payload = {
        "processing_token": None,
        "lease_expires_at": None,
        **values,
    }
    result = db.execute(
        update(NotificationOutbox)
        .where(
            NotificationOutbox.id == outbox_id,
            NotificationOutbox.status == "processing",
            NotificationOutbox.processing_token == processing_token,
        )
        .values(**payload)
    )
    db.commit()
    return int(result.rowcount or 0) == 1


def _authorize_send(
    db: Session,
    row: NotificationOutbox,
    snapshot: dict[str, Any],
    *,
    settings: Any,
) -> str | None:
    recipient_user_id = row.recipient_user_id
    if recipient_user_id is None:
        raw = snapshot.get("recipient_user_id")
        try:
            recipient_user_id = UUID(str(raw))
        except (TypeError, ValueError):
            return SKIP_RECIPIENT_UNAUTHORIZED
    membership = db.scalar(
        select(OrganizationMembership).where(
            OrganizationMembership.organization_id == row.organization_id,
            OrganizationMembership.user_id == recipient_user_id,
        )
    )
    if membership is None:
        return SKIP_RECIPIENT_UNAUTHORIZED
    configured = db.scalar(
        select(OrganizationEmailRecipient).where(
            OrganizationEmailRecipient.organization_id == row.organization_id,
            OrganizationEmailRecipient.user_id == recipient_user_id,
        )
    )
    if configured is None:
        return SKIP_RECIPIENT_UNAUTHORIZED
    user = db.get(User, recipient_user_id)
    frozen_email = normalize_email(str(snapshot.get("recipient_email_snapshot") or ""))
    if (
        user is None
        or not user.email_verified
        or not frozen_email
        or normalize_email(user.email) != frozen_email
    ):
        return SKIP_RECIPIENT_IDENTITY_CHANGED
    if settings.environment == "staging":
        allowlist = settings.staging_email_allowlist
        if frozen_email not in allowlist:
            return SKIP_STAGING_DESTINATION
    return None


def process_one_email_delivery(
    session_factory: sessionmaker[Session],
    *,
    provider: EmailProvider | None = None,
    settings: Any = None,
    now: datetime | None = None,
) -> NotificationOutbox | None:
    cfg = settings or get_settings()
    readiness = email_delivery_readiness(cfg)
    if readiness.status == "paused":
        return None
    if readiness.status != "ready":
        raise NotificationWorkerNotReady(readiness.reason or "not_ready")
    mailer = provider or build_email_provider(cfg)
    moment = now or _now()
    db = session_factory()
    claimed: tuple[NotificationOutbox, UUID] | None = None
    try:
        claimed = claim_email_outbox(
            db, now=moment, lease_seconds=int(cfg.notification_lease_seconds)
        )
        if claimed is None:
            return None
        row, token = claimed
        snapshot = dict(row.delivery_snapshot or {})
        skip_reason = None
        if not snapshot:
            skip_reason = SKIP_MISSING_SNAPSHOT
        else:
            skip_reason = _authorize_send(db, row, snapshot, settings=cfg)
        if skip_reason:
            owned = complete_claimed_outbox(
                db,
                outbox_id=row.id,
                processing_token=token,
                values={
                    "status": "skipped",
                    "last_error_code": skip_reason,
                    "last_error": skip_reason,
                },
            )
            if owned:
                logger.info(
                    "email delivery skipped",
                    extra={
                        "event": "notification.email.skipped",
                        "outbox_id": str(row.id),
                        "alert_id": str(row.alert_id),
                        "organization_id": str(row.organization_id),
                        "last_error_code": skip_reason,
                    },
                )
            return row if owned else None
        request = request_from_snapshot(row.id, snapshot)
        result = mailer.send(request)
        if result.outcome == "delivered":
            owned = complete_claimed_outbox(
                db,
                outbox_id=row.id,
                processing_token=token,
                values={
                    "status": "delivered",
                    "delivered_at": moment,
                    "last_error": None,
                    "last_error_code": None,
                },
            )
            if owned:
                logger.info(
                    "email delivery delivered",
                    extra={
                        "event": "notification.email.delivered",
                        "outbox_id": str(row.id),
                        "alert_id": str(row.alert_id),
                        "organization_id": str(row.organization_id),
                        "attempt_count": row.attempt_count,
                    },
                )
            return row if owned else None
        error_code = result.error_code or "provider_retryable"
        if result.outcome == "permanent" or row.attempt_count >= MAX_ATTEMPTS:
            status = "dead"
            values = {
                "status": status,
                "last_error_code": (
                    error_code if result.outcome == "permanent" else "max_attempts_exceeded"
                ),
                "last_error": (
                    error_code if result.outcome == "permanent" else "max_attempts_exceeded"
                ),
            }
        else:
            values = {
                "status": "failed",
                "last_error_code": error_code,
                "last_error": error_code,
                "available_at": moment + timedelta(seconds=retry_delay_seconds(row.attempt_count)),
            }
        owned = complete_claimed_outbox(
            db,
            outbox_id=row.id,
            processing_token=token,
            values=values,
        )
        if owned:
            logger.info(
                "email delivery unfinished",
                extra={
                    "event": "notification.email.unfinished",
                    "outbox_id": str(row.id),
                    "alert_id": str(row.alert_id),
                    "organization_id": str(row.organization_id),
                    "status": values["status"],
                    "last_error_code": values["last_error_code"],
                    "attempt_count": row.attempt_count,
                },
            )
        return row if owned else None
    finally:
        db.close()
