"""Postgres-backed operation claiming and authorized discovery execution.

Claim behavior
--------------
Workers call ``claim_next_operation`` inside a transaction that:

1. Selects the oldest ``queued`` operation with ``stop_requested = false``
2. Locks the row with ``FOR UPDATE SKIP LOCKED``
3. Transitions it to ``running``, sets ``started_at``, and emits ``operation.started``

Cancellation is cooperative: the API sets ``stop_requested``; the worker checks
between discovery stages and then marks ``stopped``.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.models.operation import Operation
from app.services.audit import record_audit
from app.services.candidate_engine import generate_candidates_for_operation
from app.services.change_detection import detect_and_persist_changes
from app.services.discovery.execute import (
    AuthorizationExecutionError,
    StopRequested,
    run_discovery,
)
from app.services.discovery.runner import DiscoveryError, DiscoveryTools, SubprocessDiscoveryTools
from app.services.operations import append_event

logger = logging.getLogger(__name__)

SAFE_FAILURE_MESSAGE = "Asset discovery failed."
SAFE_FAILURE_CODE = "discovery_failed"
SAFE_AUTHZ_FAILURE_MESSAGE = "Target is not authorized for discovery."
SAFE_AUTHZ_FAILURE_CODE = "target_not_authorized"

def claim_next_operation(db: Session) -> Operation | None:
    operation = db.scalar(
        select(Operation)
        .where(
            Operation.status == "queued",
            Operation.stop_requested.is_(False),
        )
        .order_by(Operation.created_at.asc())
        .with_for_update(skip_locked=True)
        .limit(1)
    )
    if operation is None:
        return None

    now = datetime.now(timezone.utc)
    operation.status = "running"
    operation.started_at = now
    append_event(
        db,
        operation,
        event_type="operation.started",
        summary="Scout operation started.",
        metadata={"status": "running"},
    )
    record_audit(
        db,
        organization_id=operation.organization_id,
        actor_type="worker",
        actor_user_id=operation.created_by_user_id,
        action="operation.started",
        resource_type="operation",
        resource_id=operation.id,
        summary="Scout operation started by worker.",
        metadata={
            "operation_id": str(operation.id),
            "target_id": str(operation.target_id),
            "status": "running",
            "source": operation.source,
            "testing_profile": operation.testing_profile,
        },
    )
    db.commit()
    db.refresh(operation)
    return operation


def _reload(db: Session, operation_id: UUID) -> Operation:
    operation = db.scalar(select(Operation).where(Operation.id == operation_id))
    if operation is None:
        raise RuntimeError("operation disappeared during execution")
    return operation


def _mark_stopped(db: Session, operation: Operation, *, summary: str) -> Operation:
    operation.status = "stopped"
    operation.stopped_at = datetime.now(timezone.utc)
    operation.stop_requested = True
    append_event(
        db,
        operation,
        event_type="operation.stopped",
        summary=summary,
        metadata={"status": "stopped"},
    )
    record_audit(
        db,
        organization_id=operation.organization_id,
        actor_type="worker",
        actor_user_id=operation.created_by_user_id,
        action="operation.stopped",
        resource_type="operation",
        resource_id=operation.id,
        summary=summary,
        metadata={
            "operation_id": str(operation.id),
            "target_id": str(operation.target_id),
            "status": "stopped",
            "source": operation.source,
        },
    )
    db.commit()
    db.refresh(operation)
    return operation


def _mark_failed(
    db: Session,
    operation: Operation,
    *,
    error_code: str = SAFE_FAILURE_CODE,
    error_message: str = SAFE_FAILURE_MESSAGE,
) -> Operation:
    operation.status = "failed"
    operation.failed_at = datetime.now(timezone.utc)
    operation.error_code = error_code
    operation.error_message = error_message
    append_event(
        db,
        operation,
        event_type="operation.failed",
        summary="Scout operation failed.",
        metadata={"status": "failed"},
    )
    record_audit(
        db,
        organization_id=operation.organization_id,
        actor_type="worker",
        actor_user_id=operation.created_by_user_id,
        action="operation.failed",
        resource_type="operation",
        resource_id=operation.id,
        summary="Scout operation failed.",
        metadata={
            "operation_id": str(operation.id),
            "target_id": str(operation.target_id),
            "status": "failed",
            "source": operation.source,
        },
    )
    db.commit()
    db.refresh(operation)
    return operation


def _mark_completed(db: Session, operation: Operation) -> Operation:
    operation.status = "completed"
    operation.completed_at = datetime.now(timezone.utc)
    append_event(
        db,
        operation,
        event_type="operation.completed",
        summary="Scout operation completed.",
        metadata={"status": "completed"},
    )
    record_audit(
        db,
        organization_id=operation.organization_id,
        actor_type="worker",
        actor_user_id=operation.created_by_user_id,
        action="operation.completed",
        resource_type="operation",
        resource_id=operation.id,
        summary="Scout operation completed.",
        metadata={
            "operation_id": str(operation.id),
            "target_id": str(operation.target_id),
            "status": "completed",
            "source": operation.source,
            "testing_profile": operation.testing_profile,
        },
    )
    db.commit()
    db.refresh(operation)
    return operation


def execute_discovery_job(
    db: Session,
    operation_id: UUID,
    tools: DiscoveryTools,
) -> Operation:
    """Run authorized asset discovery for a claimed (running) operation."""
    operation = _reload(db, operation_id)
    if operation.status != "running":
        return operation

    def should_stop() -> bool:
        current = _reload(db, operation_id)
        return bool(current.stop_requested or current.status == "stopped")

    try:
        if should_stop():
            operation = _reload(db, operation_id)
            if operation.status != "stopped":
                return _mark_stopped(db, operation, summary="Scout operation stopped.")
            return operation

        run_discovery(db, operation, tools, should_stop=should_stop)

        operation = _reload(db, operation_id)
        if should_stop():
            if operation.status != "stopped":
                return _mark_stopped(db, operation, summary="Scout operation stopped.")
            return operation

        detect_and_persist_changes(db, operation)

        operation = _reload(db, operation_id)
        if should_stop():
            if operation.status != "stopped":
                return _mark_stopped(db, operation, summary="Scout operation stopped.")
            return operation

        generate_candidates_for_operation(db, operation)

        operation = _reload(db, operation_id)
        if should_stop():
            if operation.status != "stopped":
                return _mark_stopped(db, operation, summary="Scout operation stopped.")
            return operation
        return _mark_completed(db, operation)
    except StopRequested:
        operation = _reload(db, operation_id)
        if operation.status != "stopped":
            return _mark_stopped(db, operation, summary="Scout operation stopped.")
        return operation
    except AuthorizationExecutionError:
        logger.warning("authorization failure for operation %s", operation_id)
        operation = _reload(db, operation_id)
        if operation.status in {"completed", "stopped", "failed"}:
            return operation
        return _mark_failed(
            db,
            operation,
            error_code=SAFE_AUTHZ_FAILURE_CODE,
            error_message=SAFE_AUTHZ_FAILURE_MESSAGE,
        )
    except DiscoveryError as exc:
        # Sanitize: map tool timeouts/errors to stable public messages.
        message = str(exc).lower()
        if "timed out" in message:
            public = "Discovery tooling timed out."
            code = "discovery_timeout"
        else:
            public = SAFE_FAILURE_MESSAGE
            code = SAFE_FAILURE_CODE
        logger.exception("discovery failed for operation %s", operation_id)
        operation = _reload(db, operation_id)
        if operation.status in {"completed", "stopped", "failed"}:
            return operation
        return _mark_failed(db, operation, error_code=code, error_message=public)
    except Exception:
        logger.exception("unexpected discovery failure for operation %s", operation_id)
        operation = _reload(db, operation_id)
        if operation.status in {"completed", "stopped", "failed"}:
            return operation
        return _mark_failed(db, operation)


def process_one_operation(
    session_factory: sessionmaker[Session],
    *,
    tools: DiscoveryTools | None = None,
) -> Operation | None:
    """Claim at most one queued operation and execute discovery."""
    discovery_tools = tools or SubprocessDiscoveryTools()
    db = session_factory()
    try:
        claimed = claim_next_operation(db)
        if claimed is None:
            return None
        operation_id = claimed.id
    finally:
        db.close()

    db = session_factory()
    try:
        return execute_discovery_job(db, operation_id, discovery_tools)
    finally:
        db.close()
