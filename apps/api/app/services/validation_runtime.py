"""Claim and execute queued ValidationAttempt jobs (worker-side)."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.models.asset import Asset
from app.models.candidate import SecurityCandidate
from app.models.operation import Operation
from app.models.validation import ValidationAttempt
from app.services.discovery.execute import AuthorizationExecutionError
from app.services.operations import append_event
from app.services.validation_engine.engine import (
    ValidationAuthzError,
    apply_validation_result,
    assert_validation_authorized,
    evaluate_candidate,
    mark_validation_failed,
)
from app.services.validation_engine.http import SafeHttpClient
from app.services.validation_engine.types import method_for_candidate_type

logger = logging.getLogger(__name__)


def claim_next_validation_attempt(db: Session) -> ValidationAttempt | None:
    attempt = db.scalar(
        select(ValidationAttempt)
        .where(ValidationAttempt.status == "pending")
        .order_by(ValidationAttempt.created_at.asc())
        .with_for_update(skip_locked=True)
        .limit(1)
    )
    if attempt is None:
        return None

    attempt.status = "running"
    operation = db.get(Operation, attempt.operation_id)
    candidate = db.get(SecurityCandidate, attempt.candidate_id)
    if operation is not None and candidate is not None:
        append_event(
            db,
            operation,
            event_type="validation.started",
            summary=f"Safe validation started for candidate: {candidate.title}",
            metadata={
                "candidate_id": str(candidate.id),
                "asset_id": str(attempt.asset_id),
                "candidate_type": candidate.candidate_type,
                "status": "running",
                "validation_method": attempt.validation_method,
            },
        )
    db.commit()
    db.refresh(attempt)
    return attempt


def execute_validation_job(
    db: Session,
    attempt_id: UUID,
    *,
    http_client: SafeHttpClient | None = None,
) -> ValidationAttempt:
    attempt = db.get(ValidationAttempt, attempt_id)
    if attempt is None:
        raise RuntimeError("validation attempt disappeared")
    if attempt.status not in {"running", "pending"}:
        return attempt

    if attempt.status == "pending":
        attempt.status = "running"
        db.flush()

    candidate = db.get(SecurityCandidate, attempt.candidate_id)
    asset = db.get(Asset, attempt.asset_id)
    operation = db.get(Operation, attempt.operation_id)
    if candidate is None or asset is None or operation is None:
        attempt.status = "failed"
        attempt.summary = "Validation failed: missing candidate, asset, or operation."
        attempt.completed_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(attempt)
        return attempt

    if candidate.status == "dismissed":
        return mark_validation_failed(
            db,
            attempt,
            candidate=candidate,
            operation=operation,
            summary="Validation failed because the candidate was dismissed.",
        )

    try:
        assert_validation_authorized(db, operation=operation, asset=asset)
        result = evaluate_candidate(
            db,
            candidate=candidate,
            asset=asset,
            operation=operation,
            client=http_client,
        )
        return apply_validation_result(
            db, attempt, candidate=candidate, operation=operation, result=result
        )
    except (ValidationAuthzError, AuthorizationExecutionError) as exc:
        logger.warning("validation authz failure for attempt %s: %s", attempt_id, exc)
        return mark_validation_failed(
            db,
            attempt,
            candidate=candidate,
            operation=operation,
            summary="Validation stopped because the target is not authorized or the asset is out of scope.",
            evidence={
                "method": attempt.validation_method,
                "candidate_id": str(candidate.id),
                "asset_id": str(asset.id),
                "reason": str(exc),
            },
        )
    except Exception:
        logger.exception("unexpected validation failure for attempt %s", attempt_id)
        return mark_validation_failed(
            db,
            attempt,
            candidate=candidate,
            operation=operation,
            summary="Safe validation failed unexpectedly.",
        )


def process_one_validation(
    session_factory: sessionmaker[Session],
    *,
    http_client: SafeHttpClient | None = None,
) -> ValidationAttempt | None:
    db = session_factory()
    try:
        claimed = claim_next_validation_attempt(db)
        if claimed is None:
            return None
        attempt_id = claimed.id
    finally:
        db.close()

    db = session_factory()
    try:
        return execute_validation_job(db, attempt_id, http_client=http_client)
    finally:
        db.close()


def default_method_for_candidate(candidate: SecurityCandidate) -> str:
    return method_for_candidate_type(candidate.candidate_type) or "none"
