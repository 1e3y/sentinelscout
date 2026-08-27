"""Automatic scheduled-report delivery: intent, share materialization, encrypted outbox.

Scout worker inserts a delivery INTENT in the same transaction as automatic
report success. The notification worker later materializes one M25 share and one
encrypted outbox row per eligible recipient, then sends mail. The plaintext
share secret and fragment URL exist only in memory at send time.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any, Literal
from uuid import UUID, uuid4

from email_validator import EmailNotValidError, validate_email
from fastapi import HTTPException, status
from sqlalchemy import or_, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings, get_settings
from app.models.monitoring import (
    AUTO_DELIVER_EXPIRES_IN,
    MAX_REPORT_DELIVERY_RECIPIENTS,
    MonitoringConfiguration,
    MonitoringReportDeliveryRecipient,
)
from app.models.operation import Operation
from app.models.report import AssessmentReport
from app.models.report_delivery import (
    AssessmentReportDeliveryJob,
    AssessmentReportDeliveryOutbox,
)
from app.models.report_share import (
    SHARE_CREATION_ORIGIN_SCHEDULED_AUTOMATIC,
    AssessmentReportShare,
)
from app.models.target import AuthorizedTarget
from app.services.audit import record_audit
from app.services.email_provider import EmailProvider, EmailSendRequest, build_email_provider
from app.services.notification_runtime import (
    NotificationWorkerNotReady,
    email_delivery_readiness,
)
from app.services.reports.delivery_crypto import (
    ReportDeliveryCryptoError,
    decrypt_share_secret,
    encrypt_share_secret,
    parse_report_delivery_key,
    report_delivery_crypto_ready,
)
from app.services.reports.share import (
    _EXPIRY_DELTAS,
    generate_share_secret,
    hash_share_secret,
)

logger = logging.getLogger("scout.notification_worker")

MAX_ATTEMPTS = 8
BACKOFF_BASE_SECONDS = 60
BACKOFF_CAP_SECONDS = 3600
DEFAULT_LEASE_SECONDS = 300

SKIP_RECIPIENT_REMOVED = "recipient_removed"
SKIP_SHARE_REVOKED = "share_revoked"
SKIP_SHARE_EXPIRED = "share_expired"
SKIP_STAGING_DESTINATION = "staging_destination_not_allowed"
SKIP_MISSING_CREDENTIAL = "missing_encrypted_secret"
SKIP_AUTO_DELIVERY_DISABLED = "auto_deliver_reports_disabled"
SKIP_NO_ELIGIBLE_RECIPIENTS = "no_eligible_recipients"

AuthzOutcome = Literal["proceed", "skip", "fail"]


def _now() -> datetime:
    return datetime.now(UTC)


def retry_delay_seconds(attempt_count: int) -> int:
    exponent = max(attempt_count - 1, 0)
    return min(BACKOFF_BASE_SECONDS * (2**exponent), BACKOFF_CAP_SECONDS)


def destination_key_for_email(email_normalized: str) -> str:
    return f"email:{email_normalized}"


def normalize_delivery_email(value: str) -> str:
    try:
        result = validate_email(value.strip(), check_deliverability=False)
    except EmailNotValidError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid recipient email",
        ) from exc
    return str(result.normalized).lower()


def normalize_recipient_list(values: list[str]) -> list[str]:
    unique: list[str] = []
    seen: set[str] = set()
    for raw in values:
        if not isinstance(raw, str):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid recipient email",
            )
        normalized = normalize_delivery_email(raw)
        if normalized in seen:
            continue
        seen.add(normalized)
        unique.append(normalized)
    if len(unique) > MAX_REPORT_DELIVERY_RECIPIENTS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"At most {MAX_REPORT_DELIVERY_RECIPIENTS} delivery recipients are allowed",
        )
    return unique


def list_configured_delivery_emails(db: Session, *, target_id: UUID) -> list[str]:
    rows = list(
        db.scalars(
            select(MonitoringReportDeliveryRecipient.email_normalized)
            .join(
                MonitoringConfiguration,
                MonitoringConfiguration.id
                == MonitoringReportDeliveryRecipient.monitoring_configuration_id,
            )
            .where(MonitoringConfiguration.target_id == target_id)
            .order_by(MonitoringReportDeliveryRecipient.email_normalized.asc())
        ).all()
    )
    return [str(item) for item in rows]


def _frozen_recipient_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for item in value:
        if isinstance(item, str) and item:
            out.append(item)
    return out


def enqueue_automatic_report_delivery(
    db: Session,
    *,
    operation: Operation,
    report: AssessmentReport,
    generation_job_id: UUID,
) -> None:
    """Insert one delivery intent. Duplicate operation_id is a no-op.

    Caller must invoke this in the same transaction that persists a succeeded
    automatic report. Does not mint shares or outbox rows.
    """
    if operation.source != "scheduled":
        return
    if operation.status != "completed":
        return
    if report.organization_id != operation.organization_id:
        return
    config = db.scalar(
        select(MonitoringConfiguration).where(
            MonitoringConfiguration.target_id == operation.target_id
        )
    )
    if config is None or not bool(config.auto_deliver_reports):
        return
    recipients = list_configured_delivery_emails(db, target_id=operation.target_id)
    if not recipients:
        return
    expires_in = config.auto_deliver_expires_in
    if expires_in not in AUTO_DELIVER_EXPIRES_IN:
        expires_in = "7d"
    now = _now()
    db.execute(
        pg_insert(AssessmentReportDeliveryJob)
        .values(
            id=uuid4(),
            organization_id=operation.organization_id,
            operation_id=operation.id,
            generation_job_id=generation_job_id,
            report_id=report.id,
            target_id=operation.target_id,
            status="pending",
            attempt_count=0,
            available_at=now,
            processing_token=None,
            lease_expires_at=None,
            last_error_code=None,
            frozen_recipients=recipients,
            frozen_expires_in=expires_in,
            created_at=now,
            updated_at=now,
        )
        .on_conflict_do_nothing(constraint="uq_assessment_report_delivery_job_operation")
    )


def claim_delivery_job(
    db: Session,
    *,
    now: datetime | None = None,
    lease_seconds: int = DEFAULT_LEASE_SECONDS,
) -> tuple[AssessmentReportDeliveryJob, UUID] | None:
    moment = now or _now()
    row = db.scalar(
        select(AssessmentReportDeliveryJob)
        .where(
            or_(
                (
                    (AssessmentReportDeliveryJob.status == "pending")
                    & (AssessmentReportDeliveryJob.available_at <= moment)
                ),
                (
                    (AssessmentReportDeliveryJob.status == "processing")
                    & (AssessmentReportDeliveryJob.lease_expires_at.is_not(None))
                    & (AssessmentReportDeliveryJob.lease_expires_at <= moment)
                ),
            )
        )
        .order_by(AssessmentReportDeliveryJob.available_at.asc())
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
    row.updated_at = moment
    db.commit()
    db.refresh(row)
    return row, token


def complete_claimed_delivery_job(
    db: Session,
    *,
    job_id: UUID,
    processing_token: UUID,
    values: dict[str, Any],
    commit: bool = True,
) -> bool:
    payload = {
        "processing_token": None,
        "lease_expires_at": None,
        "updated_at": _now(),
        **values,
    }
    result = db.execute(
        update(AssessmentReportDeliveryJob)
        .where(
            AssessmentReportDeliveryJob.id == job_id,
            AssessmentReportDeliveryJob.status == "processing",
            AssessmentReportDeliveryJob.processing_token == processing_token,
        )
        .values(**payload)
    )
    if commit:
        db.commit()
    return int(result.rowcount or 0) == 1


def claim_delivery_outbox(
    db: Session,
    *,
    now: datetime | None = None,
    lease_seconds: int = DEFAULT_LEASE_SECONDS,
) -> tuple[AssessmentReportDeliveryOutbox, UUID] | None:
    moment = now or _now()
    row = db.scalar(
        select(AssessmentReportDeliveryOutbox)
        .where(
            or_(
                (
                    AssessmentReportDeliveryOutbox.status.in_(("pending", "failed"))
                    & (AssessmentReportDeliveryOutbox.available_at <= moment)
                ),
                (
                    (AssessmentReportDeliveryOutbox.status == "processing")
                    & (AssessmentReportDeliveryOutbox.lease_expires_at.is_not(None))
                    & (AssessmentReportDeliveryOutbox.lease_expires_at <= moment)
                ),
            )
        )
        .order_by(AssessmentReportDeliveryOutbox.available_at.asc())
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
    row.updated_at = moment
    db.commit()
    db.refresh(row)
    return row, token


def complete_claimed_delivery_outbox(
    db: Session,
    *,
    outbox_id: UUID,
    processing_token: UUID,
    values: dict[str, Any],
    commit: bool = True,
) -> bool:
    payload = {
        "processing_token": None,
        "lease_expires_at": None,
        "updated_at": _now(),
        **values,
    }
    result = db.execute(
        update(AssessmentReportDeliveryOutbox)
        .where(
            AssessmentReportDeliveryOutbox.id == outbox_id,
            AssessmentReportDeliveryOutbox.status == "processing",
            AssessmentReportDeliveryOutbox.processing_token == processing_token,
        )
        .values(**payload)
    )
    if commit:
        db.commit()
    return int(result.rowcount or 0) == 1


def _scrub_secret_values() -> dict[str, Any]:
    return {
        "encrypted_secret": None,
        "encrypted_secret_nonce": None,
        "encryption_key_version": None,
    }


def _revoke_automatic_share(db: Session, share: AssessmentReportShare) -> None:
    if share.revoked_at is not None:
        return
    share.revoked_at = _now()
    record_audit(
        db,
        organization_id=share.organization_id,
        actor_type="worker",
        actor_user_id=None,
        action="assessment_report_share.revoked",
        resource_type="assessment_report_share",
        resource_id=share.id,
        summary="Automatic assessment report share revoked.",
        metadata={
            "share_id": str(share.id),
            "report_id": str(share.report_id),
            "creation_origin": SHARE_CREATION_ORIGIN_SCHEDULED_AUTOMATIC,
            "reason": SKIP_RECIPIENT_REMOVED,
        },
    )


def _materialize_one_recipient(
    db: Session,
    *,
    job: AssessmentReportDeliveryJob,
    report: AssessmentReport,
    email: str,
    settings: Settings,
    key: bytes,
    key_version: str,
    now: datetime,
) -> AssessmentReportDeliveryOutbox:
    dest = destination_key_for_email(email)
    existing = db.scalar(
        select(AssessmentReportDeliveryOutbox).where(
            AssessmentReportDeliveryOutbox.delivery_job_id == job.id,
            AssessmentReportDeliveryOutbox.destination_key == dest,
        )
    )
    if existing is not None:
        return existing

    origin = str(settings.frontend_url).rstrip("/")
    from_email = str(settings.email_from or "").strip()
    subject = f"Assessment report for {report.target_domain}"
    outbox = AssessmentReportDeliveryOutbox(
        organization_id=job.organization_id,
        delivery_job_id=job.id,
        report_id=report.id,
        share_id=None,
        destination_key=dest,
        recipient_email_normalized=email,
        status="pending",
        attempt_count=0,
        available_at=now,
        processing_token=None,
        lease_expires_at=None,
        last_error_code=None,
        frozen_frontend_origin=origin,
        frozen_from_email=from_email,
        frozen_subject=subject[:256],
        frozen_target_domain=report.target_domain,
        created_at=now,
        updated_at=now,
    )
    db.add(outbox)
    db.flush()

    secret = generate_share_secret()
    encrypted = encrypt_share_secret(secret, key=key, key_version=key_version)
    expires_in = job.frozen_expires_in if job.frozen_expires_in in _EXPIRY_DELTAS else "7d"
    share = AssessmentReportShare(
        organization_id=report.organization_id,
        report_id=report.id,
        created_by_user_id=None,
        creation_origin=SHARE_CREATION_ORIGIN_SCHEDULED_AUTOMATIC,
        delivery_outbox_id=outbox.id,
        secret_hash=hash_share_secret(secret),
        created_at=now,
        expires_at=now + _EXPIRY_DELTAS[expires_in],
        revoked_at=None,
    )
    db.add(share)
    db.flush()
    outbox.share_id = share.id
    outbox.encrypted_secret = encrypted.ciphertext
    outbox.encrypted_secret_nonce = encrypted.nonce
    outbox.encryption_key_version = encrypted.key_version
    record_audit(
        db,
        organization_id=report.organization_id,
        actor_type="worker",
        actor_user_id=None,
        action="assessment_report_share.created",
        resource_type="assessment_report_share",
        resource_id=share.id,
        summary="Automatic assessment report share created.",
        metadata={
            "share_id": str(share.id),
            "report_id": str(report.id),
            "delivery_job_id": str(job.id),
            "outbox_id": str(outbox.id),
            "creation_origin": SHARE_CREATION_ORIGIN_SCHEDULED_AUTOMATIC,
            "expires_at": share.expires_at.isoformat(),
        },
    )
    return outbox


def _authorize_delivery_job(db: Session, job: AssessmentReportDeliveryJob) -> tuple[str, str | None]:
    operation = db.get(Operation, job.operation_id)
    if operation is None:
        return "fail", "operation_missing"
    if job.organization_id != operation.organization_id:
        return "fail", "organization_mismatch"
    report = db.get(AssessmentReport, job.report_id)
    if report is None:
        return "fail", "report_missing"
    if report.organization_id != job.organization_id:
        return "fail", "report_organization_mismatch"
    if report.operation_id != job.operation_id:
        return "fail", "report_operation_mismatch"
    target = db.get(AuthorizedTarget, job.target_id)
    if target is None or target.organization_id != job.organization_id:
        return "fail", "target_organization_mismatch"
    if operation.source != "scheduled":
        return "fail", "operation_not_scheduled"
    if operation.status != "completed":
        return "fail", "operation_not_completed"
    config = db.scalar(
        select(MonitoringConfiguration).where(
            MonitoringConfiguration.target_id == job.target_id
        )
    )
    if config is None or not bool(config.auto_deliver_reports):
        return "skip", SKIP_AUTO_DELIVERY_DISABLED
    return "proceed", None


def _eligible_recipients(db: Session, job: AssessmentReportDeliveryJob) -> list[str]:
    frozen = set(_frozen_recipient_list(job.frozen_recipients))
    current = set(list_configured_delivery_emails(db, target_id=job.target_id))
    return sorted(frozen.intersection(current))


def _record_delivery_queued(db: Session, *, job: AssessmentReportDeliveryJob, recipient_count: int) -> None:
    record_audit(
        db,
        organization_id=job.organization_id,
        actor_type="worker",
        actor_user_id=None,
        action="assessment_report_delivery.queued",
        resource_type="assessment_report_delivery_job",
        resource_id=job.id,
        summary="Automatic assessment report delivery queued.",
        metadata={
            "delivery_job_id": str(job.id),
            "job_id": str(job.id),
            "report_id": str(job.report_id),
            "recipient_count": recipient_count,
        },
    )


def _record_delivery_terminal_failure(
    db: Session, *, job: AssessmentReportDeliveryJob, error_code: str
) -> None:
    record_audit(
        db,
        organization_id=job.organization_id,
        actor_type="worker",
        actor_user_id=None,
        action="assessment_report_delivery.failed",
        resource_type="assessment_report_delivery_job",
        resource_id=job.id,
        summary="Automatic assessment report delivery failed after max attempts.",
        metadata={
            "delivery_job_id": str(job.id),
            "job_id": str(job.id),
            "report_id": str(job.report_id),
            "last_error_code": error_code,
        },
    )


def _retry_or_fail_job(
    db: Session,
    *,
    job_id: UUID,
    processing_token: UUID,
    attempt_count: int,
    error_code: str,
) -> bool:
    moment = _now()
    if attempt_count >= MAX_ATTEMPTS:
        owned = complete_claimed_delivery_job(
            db,
            job_id=job_id,
            processing_token=processing_token,
            values={"status": "failed", "last_error_code": "max_attempts_exceeded"},
            commit=False,
        )
        if owned:
            job = db.get(AssessmentReportDeliveryJob, job_id)
            if job is not None:
                _record_delivery_terminal_failure(db, job=job, error_code=error_code)
            db.commit()
        else:
            db.rollback()
        return owned
    return complete_claimed_delivery_job(
        db,
        job_id=job_id,
        processing_token=processing_token,
        values={
            "status": "pending",
            "last_error_code": error_code,
            "available_at": moment + timedelta(seconds=retry_delay_seconds(attempt_count)),
        },
        commit=True,
    )


def _process_claimed_delivery_job(
    db: Session,
    *,
    job_id: UUID,
    processing_token: UUID,
    settings: Settings,
) -> AssessmentReportDeliveryJob | None:
    job = db.get(AssessmentReportDeliveryJob, job_id)
    if (
        job is None
        or job.status != "processing"
        or job.processing_token != processing_token
    ):
        return None

    outcome, code = _authorize_delivery_job(db, job)
    if outcome == "skip":
        owned = complete_claimed_delivery_job(
            db,
            job_id=job_id,
            processing_token=processing_token,
            values={"status": "skipped", "last_error_code": code},
        )
        return db.get(AssessmentReportDeliveryJob, job_id) if owned else None
    if outcome == "fail":
        owned = complete_claimed_delivery_job(
            db,
            job_id=job_id,
            processing_token=processing_token,
            values={"status": "failed", "last_error_code": code},
        )
        return db.get(AssessmentReportDeliveryJob, job_id) if owned else None

    from_email = str(settings.email_from or "").strip()
    if not from_email:
        _retry_or_fail_job(
            db,
            job_id=job_id,
            processing_token=processing_token,
            attempt_count=int(job.attempt_count or 0),
            error_code="missing_email_from",
        )
        return db.get(AssessmentReportDeliveryJob, job_id)

    key = parse_report_delivery_key(settings.report_delivery_secret_key)
    if key is None:
        _retry_or_fail_job(
            db,
            job_id=job_id,
            processing_token=processing_token,
            attempt_count=int(job.attempt_count or 0),
            error_code="missing_report_delivery_secret_key",
        )
        return db.get(AssessmentReportDeliveryJob, job_id)

    eligible = _eligible_recipients(db, job)
    if not eligible:
        owned = complete_claimed_delivery_job(
            db,
            job_id=job_id,
            processing_token=processing_token,
            values={"status": "skipped", "last_error_code": SKIP_NO_ELIGIBLE_RECIPIENTS},
        )
        return db.get(AssessmentReportDeliveryJob, job_id) if owned else None

    report = db.get(AssessmentReport, job.report_id)
    if report is None:
        owned = complete_claimed_delivery_job(
            db,
            job_id=job_id,
            processing_token=processing_token,
            values={"status": "failed", "last_error_code": "report_missing"},
        )
        return db.get(AssessmentReportDeliveryJob, job_id) if owned else None

    now = _now()
    key_version = str(settings.report_delivery_secret_key_version or "v1").strip() or "v1"
    try:
        created = 0
        for email in eligible:
            before = db.scalar(
                select(AssessmentReportDeliveryOutbox.id).where(
                    AssessmentReportDeliveryOutbox.delivery_job_id == job.id,
                    AssessmentReportDeliveryOutbox.destination_key
                    == destination_key_for_email(email),
                )
            )
            _materialize_one_recipient(
                db,
                job=job,
                report=report,
                email=email,
                settings=settings,
                key=key,
                key_version=key_version,
                now=now,
            )
            if before is None:
                created += 1
        owned = complete_claimed_delivery_job(
            db,
            job_id=job_id,
            processing_token=processing_token,
            values={"status": "succeeded", "last_error_code": None},
            commit=False,
        )
        if not owned:
            db.rollback()
            return None
        if created:
            _record_delivery_queued(db, job=job, recipient_count=created)
        db.commit()
        db.refresh(job)
        logger.info(
            "automatic report delivery materialized",
            extra={
                "event": "report.delivery.materialized",
                "delivery_job_id": str(job_id),
                "report_id": str(report.id),
                "recipient_count": len(eligible),
            },
        )
        return job
    except ReportDeliveryCryptoError:
        db.rollback()
        _retry_or_fail_job(
            db,
            job_id=job_id,
            processing_token=processing_token,
            attempt_count=int(job.attempt_count or 0),
            error_code="invalid_report_delivery_secret_key",
        )
        return db.get(AssessmentReportDeliveryJob, job_id)
    except Exception:
        logger.exception(
            "automatic report delivery materialization failed",
            extra={
                "event": "report.delivery.materialize_error",
                "delivery_job_id": str(job_id),
            },
        )
        db.rollback()
        _retry_or_fail_job(
            db,
            job_id=job_id,
            processing_token=processing_token,
            attempt_count=int(job.attempt_count or 0),
            error_code="materialization_error",
        )
        return db.get(AssessmentReportDeliveryJob, job_id)


def process_one_delivery_intent(
    session_factory: sessionmaker,
    *,
    settings: Any = None,
    now: datetime | None = None,
    lease_seconds: int = DEFAULT_LEASE_SECONDS,
) -> AssessmentReportDeliveryJob | None:
    cfg = settings or get_settings()
    readiness = email_delivery_readiness(cfg)
    if readiness.status == "paused":
        return None
    if readiness.status != "ready":
        raise NotificationWorkerNotReady(readiness.reason or "not_ready")
    crypto_ok, crypto_reason = report_delivery_crypto_ready(cfg)
    if not crypto_ok:
        logger.error(
            "report delivery crypto not ready; leaving delivery intents pending",
            extra={
                "event": "report.delivery.crypto_not_ready",
                "reason": crypto_reason,
            },
        )
        return None

    db = session_factory()
    try:
        claimed = claim_delivery_job(db, now=now, lease_seconds=lease_seconds)
        if claimed is None:
            return None
        job, token = claimed
        job_id = job.id
    finally:
        db.close()

    db = session_factory()
    try:
        return _process_claimed_delivery_job(
            db, job_id=job_id, processing_token=token, settings=cfg
        )
    finally:
        db.close()


def _share_url_in_memory(*, origin: str, share_id: UUID, secret: str) -> str:
    return f"{origin.rstrip('/')}/share/{share_id}#{secret}"


def _email_text(*, domain: str, share_url: str) -> str:
    return (
        f"An automatic assessment report for {domain} is ready.\n\n"
        f"Open this revocable, expiring link to view the report:\n{share_url}\n\n"
        "This link can be revoked. Do not forward it if you did not expect this message.\n"
    )


def _configured_recipient_exists(db: Session, *, target_id: UUID, email: str) -> bool:
    row = db.scalar(
        select(MonitoringReportDeliveryRecipient.id)
        .join(
            MonitoringConfiguration,
            MonitoringConfiguration.id
            == MonitoringReportDeliveryRecipient.monitoring_configuration_id,
        )
        .where(
            MonitoringConfiguration.target_id == target_id,
            MonitoringReportDeliveryRecipient.email_normalized == email,
        )
    )
    return row is not None


def _retry_or_dead_outbox(
    db: Session,
    *,
    row: AssessmentReportDeliveryOutbox,
    processing_token: UUID,
    error_code: str,
    permanent: bool,
    now: datetime,
) -> bool:
    if permanent or int(row.attempt_count or 0) >= MAX_ATTEMPTS:
        values = {
            "status": "dead",
            "last_error_code": (
                error_code if permanent else "max_attempts_exceeded"
            ),
            **_scrub_secret_values(),
        }
    else:
        values = {
            "status": "failed",
            "last_error_code": error_code,
            "available_at": now + timedelta(seconds=retry_delay_seconds(int(row.attempt_count or 0))),
        }
    return complete_claimed_delivery_outbox(
        db,
        outbox_id=row.id,
        processing_token=processing_token,
        values=values,
    )


def _process_claimed_delivery_outbox(
    db: Session,
    *,
    row: AssessmentReportDeliveryOutbox,
    processing_token: UUID,
    provider: EmailProvider,
    settings: Settings,
    now: datetime,
) -> AssessmentReportDeliveryOutbox | None:
    job = db.get(AssessmentReportDeliveryJob, row.delivery_job_id)
    share = db.get(AssessmentReportShare, row.share_id) if row.share_id else None

    def _skip(reason: str, *, revoke: bool = False) -> AssessmentReportDeliveryOutbox | None:
        if revoke and share is not None:
            _revoke_automatic_share(db, share)
        owned = complete_claimed_delivery_outbox(
            db,
            outbox_id=row.id,
            processing_token=processing_token,
            values={"status": "skipped", "last_error_code": reason, **_scrub_secret_values()},
            commit=False,
        )
        if owned:
            db.commit()
            logger.info(
                "report delivery skipped",
                extra={
                    "event": "report.delivery.skipped",
                    "outbox_id": str(row.id),
                    "delivery_job_id": str(row.delivery_job_id),
                    "last_error_code": reason,
                },
            )
            return row
        db.rollback()
        return None

    if job is None or share is None or row.share_id is None:
        return _skip(SKIP_MISSING_CREDENTIAL)

    if not _configured_recipient_exists(
        db, target_id=job.target_id, email=row.recipient_email_normalized
    ):
        return _skip(SKIP_RECIPIENT_REMOVED, revoke=True)

    if share.revoked_at is not None:
        return _skip(SKIP_SHARE_REVOKED)

    expires = share.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=UTC)
    if expires <= now:
        return _skip(SKIP_SHARE_EXPIRED)

    if (
        settings.environment == "staging"
        and row.recipient_email_normalized not in settings.staging_email_allowlist
    ):
        return _skip(SKIP_STAGING_DESTINATION)

    if not row.encrypted_secret or not row.encrypted_secret_nonce:
        return _skip(SKIP_MISSING_CREDENTIAL)

    key = parse_report_delivery_key(settings.report_delivery_secret_key)
    if key is None:
        owned = _retry_or_dead_outbox(
            db,
            row=row,
            processing_token=processing_token,
            error_code="missing_report_delivery_secret_key",
            permanent=False,
            now=now,
        )
        return row if owned else None

    try:
        secret = decrypt_share_secret(
            nonce=bytes(row.encrypted_secret_nonce),
            ciphertext=bytes(row.encrypted_secret),
            key=key,
        )
        share_url = _share_url_in_memory(
            origin=row.frozen_frontend_origin,
            share_id=share.id,
            secret=secret,
        )
        request = EmailSendRequest(
            idempotency_key=str(row.id),
            from_email=row.frozen_from_email,
            to_email=row.recipient_email_normalized,
            subject=row.frozen_subject,
            text_body=_email_text(domain=row.frozen_target_domain, share_url=share_url),
            tags=(("kind", "report_delivery"),),
        )
        result = provider.send(request)
        del secret
        del share_url
    except ReportDeliveryCryptoError:
        owned = _retry_or_dead_outbox(
            db,
            row=row,
            processing_token=processing_token,
            error_code="decrypt_failed",
            permanent=False,
            now=now,
        )
        return row if owned else None
    except Exception:
        logger.exception(
            "report delivery send failed",
            extra={
                "event": "report.delivery.send_error",
                "outbox_id": str(row.id),
            },
        )
        owned = _retry_or_dead_outbox(
            db,
            row=row,
            processing_token=processing_token,
            error_code="send_error",
            permanent=False,
            now=now,
        )
        return row if owned else None

    if result.outcome == "delivered":
        owned = complete_claimed_delivery_outbox(
            db,
            outbox_id=row.id,
            processing_token=processing_token,
            values={
                "status": "delivered",
                "delivered_at": now,
                "last_error_code": None,
                **_scrub_secret_values(),
            },
        )
        if owned:
            logger.info(
                "report delivery delivered",
                extra={
                    "event": "report.delivery.delivered",
                    "outbox_id": str(row.id),
                    "delivery_job_id": str(row.delivery_job_id),
                    "share_id": str(share.id),
                },
            )
        return row if owned else None

    error_code = result.error_code or "provider_retryable"
    owned = _retry_or_dead_outbox(
        db,
        row=row,
        processing_token=processing_token,
        error_code=error_code,
        permanent=result.outcome == "permanent",
        now=now,
    )
    return row if owned else None


def process_one_report_delivery_email(
    session_factory: sessionmaker,
    *,
    provider: EmailProvider | None = None,
    settings: Any = None,
    now: datetime | None = None,
) -> AssessmentReportDeliveryOutbox | None:
    cfg = settings or get_settings()
    readiness = email_delivery_readiness(cfg)
    if readiness.status == "paused":
        return None
    if readiness.status != "ready":
        raise NotificationWorkerNotReady(readiness.reason or "not_ready")
    crypto_ok, crypto_reason = report_delivery_crypto_ready(cfg)
    if not crypto_ok:
        logger.error(
            "report delivery crypto not ready; leaving encrypted outbox pending",
            extra={
                "event": "report.delivery.crypto_not_ready",
                "reason": crypto_reason,
            },
        )
        return None

    mailer = provider or build_email_provider(cfg)
    moment = now or _now()
    db = session_factory()
    claimed: tuple[AssessmentReportDeliveryOutbox, UUID] | None = None
    try:
        claimed = claim_delivery_outbox(
            db, now=moment, lease_seconds=int(cfg.notification_lease_seconds)
        )
        if claimed is None:
            return None
        row, token = claimed
        return _process_claimed_delivery_outbox(
            db,
            row=row,
            processing_token=token,
            provider=mailer,
            settings=cfg,
            now=moment,
        )
    finally:
        db.close()


def automatic_delivery_status(db: Session, *, report_id: UUID) -> dict[str, Any] | None:
    job = db.scalar(
        select(AssessmentReportDeliveryJob).where(
            AssessmentReportDeliveryJob.report_id == report_id
        )
    )
    if job is None:
        return None
    outbox_rows = list(
        db.scalars(
            select(AssessmentReportDeliveryOutbox).where(
                AssessmentReportDeliveryOutbox.delivery_job_id == job.id
            )
        ).all()
    )
    counts = {"pending": 0, "delivered": 0, "skipped": 0, "failed": 0, "dead": 0, "processing": 0}
    for row in outbox_rows:
        if row.status in counts:
            counts[row.status] += 1
    return {
        "job_status": job.status,
        "last_error_code": job.last_error_code,
        "frozen_recipient_count": len(_frozen_recipient_list(job.frozen_recipients)),
        "outbox_count": len(outbox_rows),
        "delivered_count": counts["delivered"],
        "skipped_count": counts["skipped"],
        "pending_count": counts["pending"] + counts["failed"] + counts["processing"],
    }
