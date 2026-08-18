"""Monitoring configuration CRUD and next_run_at helpers."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from app.models.monitoring import MONITORING_FREQUENCIES, MonitoringConfiguration
from app.services.diff import latest_diff_counts
from app.models.organization import OrganizationMembership
from app.models.target import AuthorizedTarget
from app.models.user import User
from app.services.audit import record_audit


def compute_next_run_at(frequency: str, *, from_time: datetime | None = None) -> datetime:
    base = from_time or datetime.now(timezone.utc)
    if base.tzinfo is None:
        base = base.replace(tzinfo=timezone.utc)
    if frequency == "daily":
        return base + timedelta(days=1)
    if frequency == "weekly":
        return base + timedelta(days=7)
    raise ValueError(f"Unsupported monitoring frequency: {frequency}")


def _require_target_for_user(
    db: Session, *, target_id: UUID, user_id: UUID
) -> AuthorizedTarget:
    target = db.scalar(
        select(AuthorizedTarget)
        .options(joinedload(AuthorizedTarget.scope))
        .where(AuthorizedTarget.id == target_id)
    )
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found")
    membership = db.scalar(
        select(OrganizationMembership).where(
            OrganizationMembership.user_id == user_id,
            OrganizationMembership.organization_id == target.organization_id,
        )
    )
    if membership is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found")
    return target


def get_monitoring_for_target(
    db: Session,
    *,
    target_id: UUID,
    user_id: UUID,
) -> MonitoringConfiguration | None:
    target = _require_target_for_user(db, target_id=target_id, user_id=user_id)
    return db.scalar(
        select(MonitoringConfiguration).where(
            MonitoringConfiguration.target_id == target.id
        )
    )


def upsert_monitoring(
    db: Session,
    *,
    target_id: UUID,
    user: User,
    enabled: bool,
    frequency: str,
) -> MonitoringConfiguration:
    if frequency not in MONITORING_FREQUENCIES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="frequency must be 'daily' or 'weekly'",
        )

    target = _require_target_for_user(db, target_id=target_id, user_id=user.id)

    if enabled:
        if target.status == "revoked":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot enable monitoring for a revoked target",
            )
        if target.status != "verified":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Target must be verified before enabling monitoring",
            )
        if target.scope is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Target scope is required before enabling monitoring",
            )

    config = db.scalar(
        select(MonitoringConfiguration).where(
            MonitoringConfiguration.target_id == target.id
        )
    )
    now = datetime.now(timezone.utc)
    if config is None:
        config = MonitoringConfiguration(
            organization_id=target.organization_id,
            target_id=target.id,
            enabled=enabled,
            frequency=frequency,
            updated_by_user_id=user.id,
            next_run_at=compute_next_run_at(frequency, from_time=now) if enabled else None,
            disabled_reason=None if enabled else "Monitoring disabled by user.",
        )
        db.add(config)
    else:
        config.enabled = enabled
        config.frequency = frequency
        config.updated_by_user_id = user.id
        config.updated_at = now
        if enabled:
            config.disabled_reason = None
            # If newly enabled or previously had no schedule, set next run.
            if config.next_run_at is None or config.next_run_at <= now:
                config.next_run_at = compute_next_run_at(frequency, from_time=now)
        else:
            config.disabled_reason = "Monitoring disabled by user."
            # Keep next_run_at for audit; scheduler ignores disabled.

    action = "monitoring.enabled" if enabled else "monitoring.disabled"
    record_audit(
        db,
        organization_id=target.organization_id,
        actor_type="user",
        actor_user_id=user.id,
        action=action,
        resource_type="monitoring",
        resource_id=config.id,
        summary=(
            f"Monitoring {'enabled' if enabled else 'disabled'} for {target.domain} ({frequency})."
        ),
        metadata={
            "target_id": str(target.id),
            "domain": target.domain,
            "enabled": enabled,
            "frequency": frequency,
            "status": "enabled" if enabled else "disabled",
        },
    )
    db.commit()
    db.refresh(config)
    return config


def target_authorized_for_monitoring(target: AuthorizedTarget) -> tuple[bool, str | None]:
    if target.status == "revoked":
        return False, "Target is revoked."
    if target.status != "verified":
        return False, "Target is not verified."
    if target.scope is None:
        return False, "Target scope is missing."
    return True, None


def latest_change_counts(db: Session, *, target_id: UUID) -> dict[str, Any]:
    """Counts from the latest completed operation's immutable M18 diff snapshot."""
    return latest_diff_counts(db, target_id=target_id)
