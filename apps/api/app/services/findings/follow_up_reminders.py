"""Finding follow-up reminder discovery, claim, revalidation, and delivery (M34).

Email freshness:
  ``User.email`` / ``email_verified`` are only refreshed when that user
  authenticates (``sync_user_from_clerk``) or is warmed via member listing.
  That is NOT a freshness guarantee suitable for outbound reminder delivery.
  M34 therefore resolves deliverable email exclusively from Clerk
  ``get_user`` / ``primary_email_info``. Transient Clerk failures retry;
  local ``User.email`` is never used as a send fallback.

Legacy generations:
  Discovery requires a current M33 ``finding_follow_up_changes`` row whose
  ``new_assigned_to_user_id`` / ``new_due_at`` match the Finding's current
  owner/due. Findings with owner/due but no matching history row are skipped
  (no invented ``follow_up_change_id``).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Literal
from uuid import UUID, uuid4

from fastapi import HTTPException
from sqlalchemy import and_, or_, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.models.asset import Asset
from app.models.finding import Finding
from app.models.finding_follow_up import FindingFollowUpChange
from app.models.finding_follow_up_reminder import (
    REMINDER_KIND_DUE,
    FindingFollowUpReminderJob,
)
from app.models.notification import OrganizationNotificationSettings
from app.models.organization import Organization
from app.models.target import AuthorizedTarget
from app.models.user import User
from app.services.clerk import ClerkDirectory, HttpClerkDirectory
from app.services.email_content import dashboard_url
from app.services.email_provider import EmailProvider, EmailSendRequest, build_email_provider
from app.services.findings.follow_up import due_instants_equal
from app.services.notification_runtime import (
    MAX_ATTEMPTS,
    NotificationWorkerNotReady,
    email_delivery_readiness,
    normalize_email,
    retry_delay_seconds,
)
from app.services.organization_members import clerk_user_is_org_member
from app.services.reports.summary import OPEN_FINDING_STATUSES

logger = logging.getLogger("scout.follow_up_reminders")

REMINDER_SNAPSHOT_VERSION = 1

SKIP_FINDING_RESOLVED = "finding_resolved"
SKIP_OWNER_CHANGED = "owner_changed"
SKIP_DUE_CHANGED = "due_changed"
SKIP_GENERATION_CHANGED = "follow_up_generation_changed"
SKIP_ASSIGNEE_NOT_MEMBER = "assignee_not_current_member"
SKIP_NO_DELIVERABLE_EMAIL = "recipient_no_deliverable_email"
SKIP_RECIPIENT_CHANGED = "recipient_changed"
SKIP_STAGING_DESTINATION = "staging_destination_not_allowed"
SKIP_MISSING_SNAPSHOT = "missing_delivery_snapshot"
SKIP_ORG_DISABLED = "reminders_disabled"  # used only if we ever terminal-skip; soft-wait preferred

RETRY_IDENTITY_PROVIDER_UNAVAILABLE = "identity_provider_unavailable"

MembershipOutcome = Literal["member", "not_member", "unavailable"]
EmailOutcome = Literal["deliverable", "no_email", "unavailable"]


@dataclass(frozen=True)
class MembershipResult:
    outcome: MembershipOutcome


@dataclass(frozen=True)
class EmailResult:
    outcome: EmailOutcome
    email: str | None = None


def _now() -> datetime:
    return datetime.now(timezone.utc)


def resolve_current_follow_up_generation(
    db: Session, finding: Finding
) -> FindingFollowUpChange | None:
    """Return the latest M33 history row only when it matches current Finding state.

    Does not invent a generation for owner/due state lacking history.
    """
    if finding.assigned_to_user_id is None or finding.follow_up_due_at is None:
        return None
    change = db.scalar(
        select(FindingFollowUpChange)
        .where(FindingFollowUpChange.finding_id == finding.id)
        .order_by(
            FindingFollowUpChange.created_at.desc(),
            FindingFollowUpChange.id.desc(),
        )
        .execution_options(populate_existing=True)
        .limit(1)
    )
    if change is None:
        return None
    if change.new_assigned_to_user_id != finding.assigned_to_user_id:
        return None
    if not due_instants_equal(change.new_due_at, finding.follow_up_due_at):
        return None
    return change


def discover_follow_up_reminder_jobs(
    db: Session,
    *,
    now: datetime | None = None,
    batch_size: int = 100,
) -> int:
    """Insert pending due-reminder intents for eligible Findings. DB-only; no Clerk/provider."""
    moment = now or _now()
    open_statuses = sorted(OPEN_FINDING_STATUSES)
    enabled_org_ids = list(
        db.scalars(
            select(OrganizationNotificationSettings.organization_id).where(
                OrganizationNotificationSettings.finding_follow_up_reminders_enabled.is_(True)
            )
        ).all()
    )
    if not enabled_org_ids:
        return 0

    findings = list(
        db.scalars(
            select(Finding)
            .where(
                Finding.organization_id.in_(enabled_org_ids),
                Finding.status.in_(open_statuses),
                Finding.assigned_to_user_id.is_not(None),
                Finding.follow_up_due_at.is_not(None),
                Finding.follow_up_due_at <= moment,
            )
            .order_by(Finding.follow_up_due_at.asc(), Finding.id.asc())
            .execution_options(populate_existing=True)
            .limit(batch_size)
        ).all()
    )
    inserted = 0
    for finding in findings:
        generation = resolve_current_follow_up_generation(db, finding)
        if generation is None:
            continue
        assert finding.assigned_to_user_id is not None
        assert finding.follow_up_due_at is not None
        result = db.execute(
            pg_insert(FindingFollowUpReminderJob)
            .values(
                id=uuid4(),
                organization_id=finding.organization_id,
                finding_id=finding.id,
                follow_up_change_id=generation.id,
                assigned_to_user_id=finding.assigned_to_user_id,
                due_at=finding.follow_up_due_at,
                reminder_kind=REMINDER_KIND_DUE,
                status="pending",
                available_at=finding.follow_up_due_at,
                attempt_count=0,
                last_error=None,
                last_error_code=None,
                delivery_snapshot=None,
                created_at=moment,
                updated_at=moment,
                delivered_at=None,
            )
            .on_conflict_do_nothing(
                constraint="uq_finding_follow_up_reminder_generation"
            )
            .returning(FindingFollowUpReminderJob.id)
        )
        if result.scalar_one_or_none() is not None:
            inserted += 1
    if inserted:
        db.commit()
    else:
        db.rollback()
    return inserted


def check_membership(
    directory: ClerkDirectory,
    *,
    clerk_user_id: str,
    clerk_org_id: str,
) -> MembershipResult:
    try:
        is_member = clerk_user_is_org_member(
            directory,
            clerk_user_id=clerk_user_id,
            clerk_org_id=clerk_org_id,
        )
    except HTTPException as exc:
        if exc.status_code >= 500:
            return MembershipResult(outcome="unavailable")
        # Unexpected client-facing errors from Clerk adapter → treat as unavailable
        # so we do not permanently skip on transient misconfiguration edges.
        return MembershipResult(outcome="unavailable")
    except Exception:
        return MembershipResult(outcome="unavailable")
    if is_member:
        return MembershipResult(outcome="member")
    return MembershipResult(outcome="not_member")


def resolve_deliverable_email(
    directory: ClerkDirectory,
    *,
    clerk_user_id: str,
) -> EmailResult:
    """Authoritative Clerk email only — never fall back to local User.email."""
    try:
        info = directory.get_user(clerk_user_id)
    except HTTPException as exc:
        if exc.status_code == 404:
            return EmailResult(outcome="no_email")
        if exc.status_code >= 500:
            return EmailResult(outcome="unavailable")
        return EmailResult(outcome="unavailable")
    except KeyError:
        # FakeClerk missing user — treat as authoritative absence in tests.
        return EmailResult(outcome="no_email")
    except Exception:
        return EmailResult(outcome="unavailable")
    email = normalize_email(info.email)
    if not email or not info.email_verified:
        return EmailResult(outcome="no_email")
    return EmailResult(outcome="deliverable", email=email)


def build_reminder_subject(*, finding_title: str) -> str:
    return f"Follow-up reminder for {finding_title}"


def build_reminder_text(
    *,
    finding_title: str,
    target_domain: str,
    severity: str,
    due_at: datetime,
    owner_display_name: str | None,
    dashboard_url_value: str,
) -> str:
    due_iso = due_at.astimezone(timezone.utc).isoformat()
    owner_line = owner_display_name or "Assigned organization member"
    lines = [
        "Sentinel Scout",
        "",
        f"Follow-up reminder: {finding_title} is due {due_iso}.",
        "",
        f"Finding: {finding_title}",
        f"Target: {target_domain}",
        f"Severity: {severity}",
        f"Due: {due_iso}",
        f"Assigned to: {owner_line}",
        "",
        "This is a follow-up date chosen by your organization.",
        "Recorded remediation is not verification. A passing retest is required for resolution.",
        "",
        "Open Sentinel Scout:",
        dashboard_url_value,
    ]
    return "\n".join(lines)


def freeze_reminder_snapshot(
    *,
    recipient_user_id: UUID,
    recipient_email: str,
    from_email: str,
    subject: str,
    text_body: str,
    dashboard_url_value: str,
    finding_id: UUID,
    organization_id: UUID,
    follow_up_change_id: UUID,
) -> dict[str, Any]:
    return {
        "schema_version": REMINDER_SNAPSHOT_VERSION,
        "recipient_user_id": str(recipient_user_id),
        "recipient_email_snapshot": recipient_email,
        "from_email_snapshot": from_email,
        "subject_snapshot": subject,
        "text_body_snapshot": text_body,
        "dashboard_url_snapshot": dashboard_url_value,
        "tags": [
            {"name": "kind", "value": "finding_follow_up_reminder"},
            {"name": "finding_id", "value": str(finding_id)},
            {"name": "organization_id", "value": str(organization_id)},
            {"name": "follow_up_change_id", "value": str(follow_up_change_id)},
        ],
    }


def request_from_reminder_snapshot(job_id: UUID, snapshot: dict[str, Any]) -> EmailSendRequest:
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
        idempotency_key=str(job_id),
        from_email=str(snapshot.get("from_email_snapshot") or ""),
        to_email=str(snapshot.get("recipient_email_snapshot") or ""),
        subject=str(snapshot.get("subject_snapshot") or ""),
        text_body=str(snapshot.get("text_body_snapshot") or ""),
        tags=tuple(tags),
    )


def claim_follow_up_reminder_job(
    db: Session,
    *,
    now: datetime | None = None,
    lease_seconds: int = 300,
) -> tuple[FindingFollowUpReminderJob, UUID] | None:
    """Claim one due reminder for an org with reminders enabled."""
    moment = now or _now()
    row = db.scalar(
        select(FindingFollowUpReminderJob)
        .join(
            OrganizationNotificationSettings,
            OrganizationNotificationSettings.organization_id
            == FindingFollowUpReminderJob.organization_id,
        )
        .where(
            OrganizationNotificationSettings.finding_follow_up_reminders_enabled.is_(True),
            or_(
                and_(
                    FindingFollowUpReminderJob.status.in_(("pending", "failed")),
                    FindingFollowUpReminderJob.available_at <= moment,
                ),
                and_(
                    FindingFollowUpReminderJob.status == "processing",
                    FindingFollowUpReminderJob.lease_expires_at.is_not(None),
                    FindingFollowUpReminderJob.lease_expires_at <= moment,
                ),
            ),
        )
        .order_by(FindingFollowUpReminderJob.available_at.asc())
        .with_for_update(skip_locked=True, of=FindingFollowUpReminderJob)
        .limit(1)
    )
    if row is None:
        return None
    token = uuid4()
    row.status = "processing"
    row.processing_token = token
    row.lease_expires_at = moment + timedelta(seconds=lease_seconds)
    row.attempt_count = int(row.attempt_count or 0) + 1
    row.updated_at = moment
    db.commit()
    db.refresh(row)
    return row, token


def complete_claimed_reminder_job(
    db: Session,
    *,
    job_id: UUID,
    processing_token: UUID,
    values: dict[str, Any],
) -> bool:
    payload = {
        "processing_token": None,
        "lease_expires_at": None,
        "updated_at": _now(),
        **values,
    }
    result = db.execute(
        update(FindingFollowUpReminderJob)
        .where(
            FindingFollowUpReminderJob.id == job_id,
            FindingFollowUpReminderJob.status == "processing",
            FindingFollowUpReminderJob.processing_token == processing_token,
        )
        .values(**payload)
    )
    db.commit()
    return int(result.rowcount or 0) == 1


@dataclass(frozen=True)
class AuthorizeOutcome:
    kind: Literal["ok", "skip", "retry"]
    code: str | None = None
    email: str | None = None
    snapshot: dict[str, Any] | None = None


def authorize_reminder_send(
    db: Session,
    job: FindingFollowUpReminderJob,
    *,
    directory: ClerkDirectory,
    settings: Any,
) -> AuthorizeOutcome:
    """Current-state authorization. Does not call the email provider."""
    org_settings = db.scalar(
        select(OrganizationNotificationSettings).where(
            OrganizationNotificationSettings.organization_id == job.organization_id
        )
    )
    if org_settings is None or not org_settings.finding_follow_up_reminders_enabled:
        # Soft-wait: caller should release back to pending without consuming identity.
        return AuthorizeOutcome(kind="retry", code="reminders_disabled_soft")

    finding = db.get(Finding, job.finding_id)
    if finding is None:
        return AuthorizeOutcome(kind="skip", code=SKIP_FINDING_RESOLVED)
    if finding.status not in OPEN_FINDING_STATUSES:
        return AuthorizeOutcome(kind="skip", code=SKIP_FINDING_RESOLVED)

    generation = resolve_current_follow_up_generation(db, finding)
    if generation is None or generation.id != job.follow_up_change_id:
        return AuthorizeOutcome(kind="skip", code=SKIP_GENERATION_CHANGED)
    if finding.assigned_to_user_id != job.assigned_to_user_id:
        return AuthorizeOutcome(kind="skip", code=SKIP_OWNER_CHANGED)
    if not due_instants_equal(finding.follow_up_due_at, job.due_at):
        return AuthorizeOutcome(kind="skip", code=SKIP_DUE_CHANGED)

    organization = db.get(Organization, job.organization_id)
    user = db.get(User, job.assigned_to_user_id)
    if organization is None or user is None:
        return AuthorizeOutcome(kind="skip", code=SKIP_ASSIGNEE_NOT_MEMBER)

    membership = check_membership(
        directory,
        clerk_user_id=user.clerk_user_id,
        clerk_org_id=organization.clerk_org_id,
    )
    if membership.outcome == "unavailable":
        return AuthorizeOutcome(kind="retry", code=RETRY_IDENTITY_PROVIDER_UNAVAILABLE)
    if membership.outcome == "not_member":
        return AuthorizeOutcome(kind="skip", code=SKIP_ASSIGNEE_NOT_MEMBER)

    email_result = resolve_deliverable_email(
        directory, clerk_user_id=user.clerk_user_id
    )
    if email_result.outcome == "unavailable":
        return AuthorizeOutcome(kind="retry", code=RETRY_IDENTITY_PROVIDER_UNAVAILABLE)
    if email_result.outcome == "no_email" or not email_result.email:
        return AuthorizeOutcome(kind="skip", code=SKIP_NO_DELIVERABLE_EMAIL)

    current_email = normalize_email(email_result.email)
    if settings.environment == "staging":
        allowlist = settings.staging_email_allowlist
        if current_email not in allowlist:
            return AuthorizeOutcome(kind="skip", code=SKIP_STAGING_DESTINATION)

    existing = dict(job.delivery_snapshot or {}) if job.delivery_snapshot else {}
    if existing:
        frozen = normalize_email(str(existing.get("recipient_email_snapshot") or ""))
        if not frozen:
            return AuthorizeOutcome(kind="skip", code=SKIP_MISSING_SNAPSHOT)
        if frozen != current_email:
            return AuthorizeOutcome(kind="skip", code=SKIP_RECIPIENT_CHANGED)
        return AuthorizeOutcome(kind="ok", email=current_email, snapshot=existing)

    asset = db.get(Asset, finding.asset_id)
    target = db.get(AuthorizedTarget, asset.target_id) if asset is not None else None
    target_domain = (
        target.domain
        if target is not None
        else (asset.hostname if asset is not None else "unknown")
    )
    dash = dashboard_url(settings.frontend_url)
    subject = build_reminder_subject(finding_title=finding.title)
    text_body = build_reminder_text(
        finding_title=finding.title,
        target_domain=target_domain,
        severity=finding.severity,
        due_at=job.due_at,
        owner_display_name=user.name,
        dashboard_url_value=dash,
    )
    snapshot = freeze_reminder_snapshot(
        recipient_user_id=user.id,
        recipient_email=current_email,
        from_email=settings.email_from,
        subject=subject,
        text_body=text_body,
        dashboard_url_value=dash,
        finding_id=finding.id,
        organization_id=job.organization_id,
        follow_up_change_id=job.follow_up_change_id,
    )
    return AuthorizeOutcome(kind="ok", email=current_email, snapshot=snapshot)


def process_one_follow_up_reminder(
    session_factory: sessionmaker[Session],
    *,
    provider: EmailProvider | None = None,
    settings: Any = None,
    directory: ClerkDirectory | None = None,
    now: datetime | None = None,
) -> FindingFollowUpReminderJob | None:
    cfg = settings or get_settings()
    readiness = email_delivery_readiness(cfg)
    if readiness.status == "paused":
        return None
    if readiness.status != "ready":
        raise NotificationWorkerNotReady(readiness.reason or "not_ready")
    mailer = provider or build_email_provider(cfg)
    clerk = directory or HttpClerkDirectory(cfg)
    moment = now or _now()

    db = session_factory()
    claimed: tuple[FindingFollowUpReminderJob, UUID] | None = None
    owns_clerk = directory is None and isinstance(clerk, HttpClerkDirectory)
    try:
        claimed = claim_follow_up_reminder_job(
            db, now=moment, lease_seconds=int(cfg.notification_lease_seconds)
        )
        if claimed is None:
            return None
        job, token = claimed
        # End claim transaction before Clerk / provider I/O.
        auth = authorize_reminder_send(db, job, directory=clerk, settings=cfg)

        if auth.kind == "retry" and auth.code == "reminders_disabled_soft":
            complete_claimed_reminder_job(
                db,
                job_id=job.id,
                processing_token=token,
                values={
                    "status": "pending",
                    "available_at": moment + timedelta(seconds=300),
                    "last_error_code": None,
                    "last_error": None,
                    "attempt_count": max(int(job.attempt_count or 1) - 1, 0),
                },
            )
            return job

        if auth.kind == "skip":
            owned = complete_claimed_reminder_job(
                db,
                job_id=job.id,
                processing_token=token,
                values={
                    "status": "skipped",
                    "last_error_code": auth.code,
                    "last_error": auth.code,
                },
            )
            if owned:
                logger.info(
                    "follow-up reminder skipped",
                    extra={
                        "event": "follow_up_reminder.skipped",
                        "reminder_id": str(job.id),
                        "finding_id": str(job.finding_id),
                        "organization_id": str(job.organization_id),
                        "follow_up_change_id": str(job.follow_up_change_id),
                        "assigned_to_user_id": str(job.assigned_to_user_id),
                        "last_error_code": auth.code,
                    },
                )
            return job if owned else None

        if auth.kind == "retry":
            error_code = auth.code or RETRY_IDENTITY_PROVIDER_UNAVAILABLE
            if job.attempt_count >= MAX_ATTEMPTS:
                values = {
                    "status": "dead",
                    "last_error_code": "max_attempts_exceeded",
                    "last_error": "max_attempts_exceeded",
                }
            else:
                values = {
                    "status": "failed",
                    "last_error_code": error_code,
                    "last_error": error_code,
                    "available_at": moment
                    + timedelta(seconds=retry_delay_seconds(job.attempt_count)),
                }
            owned = complete_claimed_reminder_job(
                db, job_id=job.id, processing_token=token, values=values
            )
            if owned:
                logger.info(
                    "follow-up reminder identity retry",
                    extra={
                        "event": "follow_up_reminder.unfinished",
                        "reminder_id": str(job.id),
                        "finding_id": str(job.finding_id),
                        "organization_id": str(job.organization_id),
                        "status": values["status"],
                        "last_error_code": values["last_error_code"],
                        "attempt_count": job.attempt_count,
                    },
                )
            return job if owned else None

        assert auth.snapshot is not None
        # Persist frozen snapshot (immutable thereafter) before provider call.
        if not job.delivery_snapshot:
            frozen_ok = complete_claimed_reminder_job(
                db,
                job_id=job.id,
                processing_token=token,
                values={
                    "status": "processing",
                    "processing_token": token,
                    "lease_expires_at": job.lease_expires_at,
                    "delivery_snapshot": auth.snapshot,
                },
            )
            if not frozen_ok:
                return None
            job.delivery_snapshot = auth.snapshot

        snapshot = dict(job.delivery_snapshot or auth.snapshot)
        # Re-check frozen destination vs current email already done in authorize.
        request = request_from_reminder_snapshot(job.id, snapshot)
        result = mailer.send(request)

        if result.outcome == "delivered":
            owned = complete_claimed_reminder_job(
                db,
                job_id=job.id,
                processing_token=token,
                values={
                    "status": "delivered",
                    "delivered_at": moment,
                    "last_error": None,
                    "last_error_code": None,
                    "delivery_snapshot": snapshot,
                },
            )
            if owned:
                logger.info(
                    "follow-up reminder delivered",
                    extra={
                        "event": "follow_up_reminder.delivered",
                        "reminder_id": str(job.id),
                        "finding_id": str(job.finding_id),
                        "organization_id": str(job.organization_id),
                        "follow_up_change_id": str(job.follow_up_change_id),
                        "assigned_to_user_id": str(job.assigned_to_user_id),
                        "attempt_count": job.attempt_count,
                    },
                )
            return job if owned else None

        error_code = result.error_code or "provider_retryable"
        if result.outcome == "permanent" or job.attempt_count >= MAX_ATTEMPTS:
            values = {
                "status": "dead",
                "last_error_code": (
                    error_code if result.outcome == "permanent" else "max_attempts_exceeded"
                ),
                "last_error": (
                    error_code if result.outcome == "permanent" else "max_attempts_exceeded"
                ),
                "delivery_snapshot": snapshot,
            }
        else:
            values = {
                "status": "failed",
                "last_error_code": error_code,
                "last_error": error_code,
                "available_at": moment
                + timedelta(seconds=retry_delay_seconds(job.attempt_count)),
                "delivery_snapshot": snapshot,
            }
        owned = complete_claimed_reminder_job(
            db, job_id=job.id, processing_token=token, values=values
        )
        if owned:
            logger.info(
                "follow-up reminder unfinished",
                extra={
                    "event": "follow_up_reminder.unfinished",
                    "reminder_id": str(job.id),
                    "finding_id": str(job.finding_id),
                    "organization_id": str(job.organization_id),
                    "status": values["status"],
                    "last_error_code": values["last_error_code"],
                    "attempt_count": job.attempt_count,
                },
            )
        return job if owned else None
    finally:
        db.close()
        if owns_clerk:
            clerk.close()
