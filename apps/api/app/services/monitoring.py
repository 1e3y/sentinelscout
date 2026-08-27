"""Monitoring configuration CRUD and next_run_at helpers."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import delete, select
from sqlalchemy.orm import Session, joinedload, selectinload

from app.models.monitoring import (
    AUTO_DELIVER_EXPIRES_IN,
    MONITORING_FREQUENCIES,
    MonitoringConfiguration,
    MonitoringReportDeliveryRecipient,
)
from app.models.organization import OrganizationMembership
from app.models.target import AuthorizedTarget
from app.services.audit import record_audit
from app.services.authorization import AuthorizedOrgActor, assert_admin_actor, merge_auth_audit
from app.services.diff import latest_diff_counts


def compute_next_run_at(frequency: str, *, from_time: datetime | None = None) -> datetime:
    base = from_time or datetime.now(UTC)
    if base.tzinfo is None:
        base = base.replace(tzinfo=UTC)
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
        select(MonitoringConfiguration)
        .options(selectinload(MonitoringConfiguration.delivery_recipients))
        .where(MonitoringConfiguration.target_id == target.id)
    )


def upsert_monitoring(
    db: Session,
    *,
    actor: AuthorizedOrgActor,
    target_id: UUID,
    enabled: bool,
    frequency: str,
    auto_generate_reports: bool | None = None,
    auto_deliver_reports: bool | None = None,
    auto_deliver_expires_in: str | None = None,
    recipients: list[str] | None = None,
) -> MonitoringConfiguration:
    if frequency not in MONITORING_FREQUENCIES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="frequency must be 'daily' or 'weekly'",
        )
    if auto_deliver_expires_in is not None and auto_deliver_expires_in not in AUTO_DELIVER_EXPIRES_IN:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="auto_deliver_expires_in must be '24h', '7d', or '30d'",
        )

    target = _require_target_for_user(db, target_id=target_id, user_id=actor.user_id)
    assert_admin_actor(actor, target.organization_id, not_found="Target not found")

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
        select(MonitoringConfiguration)
        .options(selectinload(MonitoringConfiguration.delivery_recipients))
        .where(MonitoringConfiguration.target_id == target.id)
    )
    now = datetime.now(UTC)
    previous_auto = False if config is None else bool(config.auto_generate_reports)
    if auto_generate_reports is None:
        resolved_auto = previous_auto
    else:
        resolved_auto = bool(auto_generate_reports)

    previous_deliver = False if config is None else bool(config.auto_deliver_reports)
    if auto_deliver_reports is None:
        resolved_deliver = previous_deliver
    else:
        resolved_deliver = bool(auto_deliver_reports)

    previous_expires = "7d" if config is None else str(config.auto_deliver_expires_in or "7d")
    if auto_deliver_expires_in is None:
        resolved_expires = previous_expires if previous_expires in AUTO_DELIVER_EXPIRES_IN else "7d"
    else:
        resolved_expires = auto_deliver_expires_in

    previous_recipients = (
        []
        if config is None
        else sorted(row.email_normalized for row in config.delivery_recipients)
    )
    replacing_recipients = recipients is not None
    if replacing_recipients:
        from app.services.reports.delivery import normalize_recipient_list

        resolved_recipients = normalize_recipient_list(recipients)
    else:
        resolved_recipients = previous_recipients

    if config is None:
        config = MonitoringConfiguration(
            organization_id=target.organization_id,
            target_id=target.id,
            enabled=enabled,
            auto_generate_reports=resolved_auto,
            auto_deliver_reports=resolved_deliver,
            auto_deliver_expires_in=resolved_expires,
            frequency=frequency,
            updated_by_user_id=actor.user_id,
            next_run_at=compute_next_run_at(frequency, from_time=now) if enabled else None,
            disabled_reason=None if enabled else "Monitoring disabled by user.",
        )
        db.add(config)
        db.flush()
    else:
        config.enabled = enabled
        config.auto_generate_reports = resolved_auto
        config.auto_deliver_reports = resolved_deliver
        config.auto_deliver_expires_in = resolved_expires
        config.frequency = frequency
        config.updated_by_user_id = actor.user_id
        config.updated_at = now
        if enabled:
            config.disabled_reason = None
            # If newly enabled or previously had no schedule, set next run.
            if config.next_run_at is None or config.next_run_at <= now:
                config.next_run_at = compute_next_run_at(frequency, from_time=now)
        else:
            config.disabled_reason = "Monitoring disabled by user."
            # Keep next_run_at for audit; scheduler ignores disabled.

    if replacing_recipients:
        db.execute(
            delete(MonitoringReportDeliveryRecipient).where(
                MonitoringReportDeliveryRecipient.monitoring_configuration_id == config.id
            )
        )
        for email in resolved_recipients:
            db.add(
                MonitoringReportDeliveryRecipient(
                    organization_id=target.organization_id,
                    monitoring_configuration_id=config.id,
                    target_id=target.id,
                    email_normalized=email,
                    created_by_user_id=actor.user_id,
                )
            )

    action = "monitoring.enabled" if enabled else "monitoring.disabled"
    record_audit(
        db,
        organization_id=target.organization_id,
        actor_type="user",
        actor_user_id=actor.user_id,
        action=action,
        resource_type="monitoring",
        resource_id=config.id,
        summary=(
            f"Monitoring {'enabled' if enabled else 'disabled'} for {target.domain} ({frequency})."
        ),
        metadata=merge_auth_audit(
            actor,
            {
                "target_id": str(target.id),
                "domain": target.domain,
                "enabled": enabled,
                "auto_generate_reports": resolved_auto,
                "auto_deliver_reports": resolved_deliver,
                "frequency": frequency,
                "status": "enabled" if enabled else "disabled",
            },
        ),
    )
    if previous_auto != resolved_auto:
        auto_action = (
            "monitoring.auto_reports_enabled"
            if resolved_auto
            else "monitoring.auto_reports_disabled"
        )
        record_audit(
            db,
            organization_id=target.organization_id,
            actor_type="user",
            actor_user_id=actor.user_id,
            action=auto_action,
            resource_type="monitoring",
            resource_id=config.id,
            summary=(
                f"Automatic assessment reports "
                f"{'enabled' if resolved_auto else 'disabled'} for {target.domain}."
            ),
            metadata=merge_auth_audit(
                actor,
                {
                    "target_id": str(target.id),
                    "domain": target.domain,
                    "auto_generate_reports": resolved_auto,
                },
            ),
        )
    if previous_deliver != resolved_deliver:
        deliver_action = (
            "monitoring.auto_delivery_enabled"
            if resolved_deliver
            else "monitoring.auto_delivery_disabled"
        )
        record_audit(
            db,
            organization_id=target.organization_id,
            actor_type="user",
            actor_user_id=actor.user_id,
            action=deliver_action,
            resource_type="monitoring",
            resource_id=config.id,
            summary=(
                f"Automatic report delivery "
                f"{'enabled' if resolved_deliver else 'disabled'} for {target.domain}."
            ),
            metadata=merge_auth_audit(
                actor,
                {
                    "target_id": str(target.id),
                    "domain": target.domain,
                    "auto_deliver_reports": resolved_deliver,
                    "recipient_count": len(resolved_recipients),
                    "expires_in": resolved_expires,
                },
            ),
        )
    if replacing_recipients and previous_recipients != resolved_recipients:
        record_audit(
            db,
            organization_id=target.organization_id,
            actor_type="user",
            actor_user_id=actor.user_id,
            action="monitoring.auto_delivery_recipients_updated",
            resource_type="monitoring",
            resource_id=config.id,
            summary=f"Automatic report delivery recipients updated for {target.domain}.",
            metadata=merge_auth_audit(
                actor,
                {
                    "target_id": str(target.id),
                    "domain": target.domain,
                    "recipient_count": len(resolved_recipients),
                    "expires_in": resolved_expires,
                },
            ),
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
