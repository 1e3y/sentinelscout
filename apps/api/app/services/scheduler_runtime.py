"""Claim due monitoring configs and enqueue scheduled Operations (no scanning)."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload, sessionmaker

from app.models.monitoring import MonitoringConfiguration
from app.models.operation import Operation
from app.models.operation_controls import TESTING_PROFILE_SAFE_PRODUCTION
from app.models.target import AuthorizedTarget
from app.models.user import User
from app.services.audit import record_audit
from app.services.monitoring import compute_next_run_at, target_authorized_for_monitoring
from app.services.operation_controls import create_control_snapshot
from app.services.operations import append_event

logger = logging.getLogger(__name__)


def _active_scheduled_operation(db: Session, *, target_id: UUID) -> Operation | None:
    return db.scalar(
        select(Operation)
        .where(
            Operation.target_id == target_id,
            Operation.source == "scheduled",
            Operation.status.in_(("queued", "running")),
        )
        .limit(1)
    )


def claim_and_schedule_one(db: Session) -> Operation | None:
    """Claim one due monitoring config and create a queued Operation, or None."""
    now = datetime.now(timezone.utc)
    config = db.scalar(
        select(MonitoringConfiguration)
        .where(
            MonitoringConfiguration.enabled.is_(True),
            MonitoringConfiguration.next_run_at.is_not(None),
            MonitoringConfiguration.next_run_at <= now,
        )
        .order_by(MonitoringConfiguration.next_run_at.asc())
        .with_for_update(skip_locked=True)
        .limit(1)
    )
    if config is None:
        return None

    target = db.scalar(
        select(AuthorizedTarget)
        .options(joinedload(AuthorizedTarget.scope))
        .where(AuthorizedTarget.id == config.target_id)
    )
    if target is None:
        config.enabled = False
        config.disabled_reason = "Target no longer exists."
        config.next_run_at = None
        config.updated_at = now
        db.commit()
        return None

    if target.organization_id != config.organization_id:
        config.enabled = False
        config.disabled_reason = "Target organization mismatch."
        config.next_run_at = None
        config.updated_at = now
        db.commit()
        return None

    ok, reason = target_authorized_for_monitoring(target)
    if not ok:
        config.enabled = False
        config.disabled_reason = reason or "Target is not authorized for monitoring."
        config.next_run_at = None
        config.updated_at = now
        db.commit()
        logger.info(
            "disabled monitoring for target %s: %s", config.target_id, config.disabled_reason
        )
        return None

    # Prevent duplicate active scheduled ops for this target.
    if _active_scheduled_operation(db, target_id=target.id) is not None:
        config.next_run_at = compute_next_run_at(config.frequency, from_time=now)
        config.updated_at = now
        db.commit()
        logger.info(
            "skipped scheduling for target %s; active scheduled operation exists",
            target.id,
        )
        return None

    actor_id = config.updated_by_user_id
    if actor_id is None:
        # Fall back to any org member is unsafe; disable instead.
        config.enabled = False
        config.disabled_reason = "Monitoring has no associated user to attribute operations."
        config.next_run_at = None
        config.updated_at = now
        db.commit()
        return None

    user = db.get(User, actor_id)
    if user is None:
        config.enabled = False
        config.disabled_reason = "Monitoring owner user no longer exists."
        config.next_run_at = None
        config.updated_at = now
        db.commit()
        return None

    operation = Operation(
        organization_id=target.organization_id,
        target_id=target.id,
        created_by_user_id=user.id,
        status="queued",
        source="scheduled",
        testing_profile=TESTING_PROFILE_SAFE_PRODUCTION,
    )
    db.add(operation)
    db.flush()
    create_control_snapshot(db, operation=operation, target=target)

    append_event(
        db,
        operation,
        event_type="operation.created",
        summary="Scout operation queued by monitoring schedule.",
        metadata={
            "target_id": str(target.id),
            "domain": target.domain,
            "status": "queued",
            "source": "scheduled",
        },
    )
    append_event(
        db,
        operation,
        event_type="monitoring.operation_scheduled",
        summary=f"Monitoring scheduled discovery operation for {target.domain}.",
        metadata={
            "target_id": str(target.id),
            "domain": target.domain,
            "status": "queued",
            "source": "scheduled",
        },
    )
    record_audit(
        db,
        organization_id=operation.organization_id,
        actor_type="scheduler",
        actor_user_id=user.id,
        action="monitoring.operation_created",
        resource_type="operation",
        resource_id=operation.id,
        summary=f"Monitoring created scheduled operation for {target.domain}.",
        metadata={
            "target_id": str(target.id),
            "domain": target.domain,
            "source": "scheduled",
            "status": "queued",
            "testing_profile": TESTING_PROFILE_SAFE_PRODUCTION,
            "operation_id": str(operation.id),
        },
    )
    record_audit(
        db,
        organization_id=operation.organization_id,
        actor_type="scheduler",
        actor_user_id=user.id,
        action="operation.created",
        resource_type="operation",
        resource_id=operation.id,
        summary=f"Scheduled operation created for {target.domain}.",
        metadata={
            "target_id": str(target.id),
            "domain": target.domain,
            "source": "scheduled",
            "status": "queued",
            "testing_profile": TESTING_PROFILE_SAFE_PRODUCTION,
        },
    )

    config.last_run_at = now
    config.next_run_at = compute_next_run_at(config.frequency, from_time=now)
    config.updated_at = now
    config.disabled_reason = None
    db.commit()
    db.refresh(operation)
    # Ensure target is loaded for callers/logging.
    _ = operation.target
    return operation


def process_one_scheduled_monitoring(
    session_factory: sessionmaker[Session],
) -> Operation | None:
    db = session_factory()
    try:
        return claim_and_schedule_one(db)
    finally:
        db.close()
