"""Postgres fixed-window rate limits keyed by organization + user + action."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.models.rate_limit import RateLimitCounter

ACTION_TARGET_CREATE = "target.create"
ACTION_VERIFICATION = "target.verify"
ACTION_OPERATION_CREATE = "operation.create"
ACTION_VALIDATION = "validation.request"
ACTION_RETEST = "retest.request"
ACTION_NOTIFICATION_SETTINGS = "notification.settings"


def _limit_for_action(settings: Settings, action: str) -> int:
    return {
        ACTION_TARGET_CREATE: settings.rate_limit_target_create,
        ACTION_VERIFICATION: settings.rate_limit_verification,
        ACTION_OPERATION_CREATE: settings.rate_limit_operation_create,
        ACTION_VALIDATION: settings.rate_limit_validation,
        ACTION_RETEST: settings.rate_limit_retest,
        ACTION_NOTIFICATION_SETTINGS: settings.rate_limit_notification_settings,
    }.get(action, settings.rate_limit_operation_create)


def _window_start(now: datetime, window_seconds: int) -> datetime:
    epoch = int(now.timestamp())
    aligned = epoch - (epoch % window_seconds)
    return datetime.fromtimestamp(aligned, tz=timezone.utc)


def enforce_rate_limit(
    db: Session,
    *,
    organization_id: UUID,
    user_id: UUID,
    action: str,
    settings: Settings | None = None,
) -> None:
    cfg = settings or get_settings()
    if not cfg.rate_limit_enabled:
        return

    limit = _limit_for_action(cfg, action)
    now = datetime.now(timezone.utc)
    window_start = _window_start(now, cfg.rate_limit_window_seconds)

    # Serialize increments for the same counter key.
    db.execute(
        text("SELECT pg_advisory_xact_lock(hashtext(:lock_key))"),
        {
            "lock_key": f"{organization_id}:{user_id}:{action}:{window_start.isoformat()}",
        },
    )

    counter = db.scalar(
        select(RateLimitCounter).where(
            RateLimitCounter.organization_id == organization_id,
            RateLimitCounter.user_id == user_id,
            RateLimitCounter.action == action,
            RateLimitCounter.window_start == window_start,
        )
    )
    if counter is None:
        counter = RateLimitCounter(
            organization_id=organization_id,
            user_id=user_id,
            action=action,
            window_start=window_start,
            count=0,
        )
        db.add(counter)
        db.flush()

    if counter.count >= limit:
        retry_after = int(
            (
                window_start + timedelta(seconds=cfg.rate_limit_window_seconds) - now
            ).total_seconds()
        )
        # Release the advisory lock / transaction work before failing the request.
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded for this action. Try again later.",
            headers={"Retry-After": str(max(retry_after, 1))},
        )

    counter.count += 1
    db.flush()
