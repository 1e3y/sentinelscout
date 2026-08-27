"""Automatic immutable reports after scheduled assessment completion.

Enqueue happens in the same transaction that freezes a *completed* scheduled
operation, and only when ``monitoring.auto_generate_reports`` is already true.
Generation runs later on the existing worker. Live-at-generation M22 follow-up
(finding / remediation / retest state) is frozen when this job actually builds
the report, after that completion transaction has committed. It does not wait
for later user-triggered validation or retest workflows.

Authority is the trusted worker plus the durable job created from an
admin-approved persisted monitoring flag. There is no ``AuthorizedOrgActor``,
no fake ``org:admin``, and no human JWT.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal
from uuid import UUID, uuid4

from fastapi import HTTPException
from sqlalchemy import or_, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session, sessionmaker

from app.models.monitoring import MonitoringConfiguration
from app.models.operation import Operation
from app.models.report import GENERATION_ORIGIN_SCHEDULED_AUTOMATIC
from app.models.report_generation_job import AssessmentReportGenerationJob
from app.models.target import AuthorizedTarget
from app.services.audit import record_audit
from app.services.reports.generate import (
    build_report_digest_for_operation,
    persist_assessment_report,
)

logger = logging.getLogger("scout.report_generation_worker")

MAX_ATTEMPTS = 8
BACKOFF_BASE_SECONDS = 60
BACKOFF_CAP_SECONDS = 3600
DEFAULT_LEASE_SECONDS = 300

AuthzOutcome = Literal["proceed", "skip", "fail"]


@dataclass(frozen=True)
class AutomaticJobAuthz:
    outcome: AuthzOutcome
    code: str | None = None
    operation: Operation | None = None


def _now() -> datetime:
    return datetime.now(UTC)


def retry_delay_seconds(attempt_count: int) -> int:
    exponent = max(attempt_count - 1, 0)
    return min(BACKOFF_BASE_SECONDS * (2**exponent), BACKOFF_CAP_SECONDS)


def enqueue_automatic_report_job(db: Session, operation: Operation) -> None:
    """Insert a unique pending job. Duplicate ``operation_id`` is a no-op.

    Caller must invoke this in the same transaction that finalizes a completed
    scheduled operation, after coverage / diff / alert freeze and before commit.
    """
    if operation.source != "scheduled":
        return
    if operation.status != "completed":
        return
    config = db.scalar(
        select(MonitoringConfiguration).where(
            MonitoringConfiguration.target_id == operation.target_id
        )
    )
    if config is None or not bool(config.auto_generate_reports):
        return
    now = _now()
    db.execute(
        pg_insert(AssessmentReportGenerationJob)
        .values(
            id=uuid4(),
            organization_id=operation.organization_id,
            operation_id=operation.id,
            status="pending",
            attempt_count=0,
            available_at=now,
            processing_token=None,
            lease_expires_at=None,
            last_error_code=None,
            report_id=None,
            created_at=now,
            updated_at=now,
        )
        .on_conflict_do_nothing(constraint="uq_assessment_report_generation_job_operation")
    )


def claim_report_generation_job(
    db: Session,
    *,
    now: datetime | None = None,
    lease_seconds: int = DEFAULT_LEASE_SECONDS,
) -> tuple[AssessmentReportGenerationJob, UUID] | None:
    moment = now or _now()
    row = db.scalar(
        select(AssessmentReportGenerationJob)
        .where(
            or_(
                (
                    (AssessmentReportGenerationJob.status == "pending")
                    & (AssessmentReportGenerationJob.available_at <= moment)
                ),
                (
                    (AssessmentReportGenerationJob.status == "processing")
                    & (AssessmentReportGenerationJob.lease_expires_at.is_not(None))
                    & (AssessmentReportGenerationJob.lease_expires_at <= moment)
                ),
            )
        )
        .order_by(AssessmentReportGenerationJob.available_at.asc())
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


def complete_claimed_job(
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
        update(AssessmentReportGenerationJob)
        .where(
            AssessmentReportGenerationJob.id == job_id,
            AssessmentReportGenerationJob.status == "processing",
            AssessmentReportGenerationJob.processing_token == processing_token,
        )
        .values(**payload)
    )
    if commit:
        db.commit()
    return int(result.rowcount or 0) == 1


def authorize_automatic_job(
    db: Session, job: AssessmentReportGenerationJob
) -> AutomaticJobAuthz:
    """Fail closed on org / source / status inconsistency. Skip if auto reports disabled."""
    operation = db.get(Operation, job.operation_id)
    if operation is None:
        return AutomaticJobAuthz(outcome="fail", code="operation_missing")
    if job.organization_id != operation.organization_id:
        return AutomaticJobAuthz(outcome="fail", code="organization_mismatch")
    target = db.get(AuthorizedTarget, operation.target_id)
    if target is None or target.organization_id != job.organization_id:
        return AutomaticJobAuthz(outcome="fail", code="target_organization_mismatch")
    if operation.source != "scheduled":
        return AutomaticJobAuthz(outcome="fail", code="operation_not_scheduled")
    if operation.status != "completed":
        return AutomaticJobAuthz(outcome="fail", code="operation_not_completed")
    config = db.scalar(
        select(MonitoringConfiguration).where(
            MonitoringConfiguration.target_id == operation.target_id
        )
    )
    if config is None or not bool(config.auto_generate_reports):
        return AutomaticJobAuthz(
            outcome="skip", code="auto_generate_reports_disabled", operation=operation
        )
    return AutomaticJobAuthz(outcome="proceed", operation=operation)


def _record_terminal_failure(
    db: Session, *, job: AssessmentReportGenerationJob, error_code: str
) -> None:
    record_audit(
        db,
        organization_id=job.organization_id,
        actor_type="worker",
        actor_user_id=None,
        action="assessment_report.generation_failed",
        resource_type="assessment_report_generation_job",
        resource_id=job.id,
        summary="Automatic assessment report generation failed after max attempts.",
        metadata={
            "job_id": str(job.id),
            "operation_id": str(job.operation_id),
            "last_error_code": error_code,
            "generation_origin": GENERATION_ORIGIN_SCHEDULED_AUTOMATIC,
            "generation_reason": "scheduled_monitoring",
        },
    )


def _retry_or_fail(
    db: Session,
    *,
    job_id: UUID,
    processing_token: UUID,
    attempt_count: int,
    error_code: str,
) -> bool:
    moment = _now()
    if attempt_count >= MAX_ATTEMPTS:
        owned = complete_claimed_job(
            db,
            job_id=job_id,
            processing_token=processing_token,
            values={"status": "failed", "last_error_code": "max_attempts_exceeded"},
            commit=False,
        )
        if owned:
            job = db.get(AssessmentReportGenerationJob, job_id)
            if job is not None:
                _record_terminal_failure(
                    db, job=job, error_code=error_code
                )
            db.commit()
        else:
            db.rollback()
        return owned
    owned = complete_claimed_job(
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
    return owned


def _process_claimed_job(
    db: Session,
    *,
    job_id: UUID,
    processing_token: UUID,
    before_success_commit: Callable[[], None] | None = None,
) -> AssessmentReportGenerationJob | None:
    job = db.get(AssessmentReportGenerationJob, job_id)
    if (
        job is None
        or job.status != "processing"
        or job.processing_token != processing_token
    ):
        return None

    authz = authorize_automatic_job(db, job)
    if authz.outcome == "skip":
        owned = complete_claimed_job(
            db,
            job_id=job_id,
            processing_token=processing_token,
            values={"status": "skipped", "last_error_code": authz.code},
        )
        return db.get(AssessmentReportGenerationJob, job_id) if owned else None
    if authz.outcome == "fail" or authz.operation is None:
        owned = complete_claimed_job(
            db,
            job_id=job_id,
            processing_token=processing_token,
            values={"status": "failed", "last_error_code": authz.code},
        )
        return db.get(AssessmentReportGenerationJob, job_id) if owned else None

    operation = authz.operation
    attempt_count = int(job.attempt_count or 0)
    try:
        content, digest = build_report_digest_for_operation(db, operation)
        report, created = persist_assessment_report(
            db,
            operation=operation,
            content=content,
            digest=digest,
            origin=GENERATION_ORIGIN_SCHEDULED_AUTOMATIC,
            created_by_user_id=None,
            actor=None,
            commit=False,
        )
        owned = complete_claimed_job(
            db,
            job_id=job_id,
            processing_token=processing_token,
            values={
                "status": "succeeded",
                "report_id": report.id,
                "last_error_code": None,
            },
            commit=False,
        )
        if not owned:
            db.rollback()
            return None
        from app.services.reports.delivery import enqueue_automatic_report_delivery

        enqueue_automatic_report_delivery(
            db,
            operation=operation,
            report=report,
            generation_job_id=job_id,
        )
        if before_success_commit is not None:
            before_success_commit()
        db.commit()
        db.refresh(job)
        logger.info(
            "automatic report generated",
            extra={
                "event": "report.automatic.succeeded",
                "job_id": str(job_id),
                "operation_id": str(operation.id),
                "report_id": str(report.id),
                "report_created": created,
                "reused": not created,
            },
        )
        return job
    except HTTPException as exc:
        db.rollback()
        _retry_or_fail(
            db,
            job_id=job_id,
            processing_token=processing_token,
            attempt_count=attempt_count,
            error_code=f"http_{exc.status_code}",
        )
        return db.get(AssessmentReportGenerationJob, job_id)
    except Exception:
        logger.exception(
            "automatic report generation failed",
            extra={
                "event": "report.automatic.error",
                "job_id": str(job_id),
                "operation_id": str(operation.id),
            },
        )
        db.rollback()
        _retry_or_fail(
            db,
            job_id=job_id,
            processing_token=processing_token,
            attempt_count=attempt_count,
            error_code="generation_error",
        )
        return db.get(AssessmentReportGenerationJob, job_id)


def process_one_automatic_report(
    session_factory: sessionmaker,
    *,
    now: datetime | None = None,
    lease_seconds: int = DEFAULT_LEASE_SECONDS,
    before_success_commit: Callable[[], None] | None = None,
) -> AssessmentReportGenerationJob | None:
    db = session_factory()
    try:
        claimed = claim_report_generation_job(
            db, now=now, lease_seconds=lease_seconds
        )
        if claimed is None:
            return None
        job, token = claimed
        job_id = job.id
    finally:
        db.close()

    db = session_factory()
    try:
        return _process_claimed_job(
            db,
            job_id=job_id,
            processing_token=token,
            before_success_commit=before_success_commit,
        )
    finally:
        db.close()
