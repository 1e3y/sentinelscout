"""Postgres fixed-window rate limits keyed by organization + user + action."""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.models.rate_limit import RateLimitCounter
from app.models.report_share import AnonymousRateLimitCounter

ACTION_TARGET_CREATE = "target.create"
ACTION_VERIFICATION = "target.verify"
ACTION_OPERATION_CREATE = "operation.create"
ACTION_VALIDATION = "validation.request"
ACTION_RETEST = "retest.request"
ACTION_REMEDIATION_RECORD = "finding.remediation_record"
ACTION_FINDING_FOLLOW_UP = "finding.follow_up"
ACTION_NOTIFICATION_SETTINGS = "notification.settings"
ACTION_REPORT_GENERATE = "report.generate"
ACTION_REPORT_PDF_EXPORT = "report.pdf_export"
ACTION_REPORT_SHARE_CREATE = "report.share_create"
ACTION_SHARED_REPORT_COARSE = "shared_report.coarse"
ACTION_SHARED_REPORT_USE = "shared_report.use"
SHARED_REPORT_COARSE_PARTITIONS = 64


def _limit_for_action(settings: Settings, action: str) -> int:
    return {
        ACTION_TARGET_CREATE: settings.rate_limit_target_create,
        ACTION_VERIFICATION: settings.rate_limit_verification,
        ACTION_OPERATION_CREATE: settings.rate_limit_operation_create,
        ACTION_VALIDATION: settings.rate_limit_validation,
        ACTION_RETEST: settings.rate_limit_retest,
        ACTION_REMEDIATION_RECORD: settings.rate_limit_finding_remediation,
        ACTION_FINDING_FOLLOW_UP: settings.rate_limit_finding_follow_up,
        ACTION_NOTIFICATION_SETTINGS: settings.rate_limit_notification_settings,
        ACTION_REPORT_GENERATE: settings.rate_limit_report_generate,
        ACTION_REPORT_PDF_EXPORT: settings.rate_limit_report_pdf_export,
        ACTION_REPORT_SHARE_CREATE: settings.rate_limit_report_share_create,
        ACTION_SHARED_REPORT_COARSE: settings.rate_limit_shared_report_coarse,
        ACTION_SHARED_REPORT_USE: settings.rate_limit_shared_report_use,
    }.get(action, settings.rate_limit_operation_create)


def coarse_share_partition(share_id: UUID) -> str:
    """Fixed pre-lookup partition from the public share UUID only.

    ``sha256(UUID.bytes)`` modulo ``SHARED_REPORT_COARSE_PARTITIONS``.
    The stored bucket is ``p00``…``p63``, never the raw id or full hash.
    Existence is not an input; valid and nonexistent ids use this same
    function before any share row is loaded.
    """
    digest = hashlib.sha256(share_id.bytes).digest()
    index = int.from_bytes(digest, "big") % SHARED_REPORT_COARSE_PARTITIONS
    return f"p{index:02d}"


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


def enforce_anonymous_rate_limit(
    db: Session,
    *,
    action: str,
    bucket: str,
    settings: Settings | None = None,
) -> None:
    """Fixed-window limiter for unauthenticated share traffic.

    M25 choice: there is no trustworthy proxy-aware client-IP helper in
    this repository, and a bare SHA-256(IP) is not privacy-safe. Do not
    key anonymous buckets by raw IP, X-Forwarded-For, or an HMAC of IP.

    Before share lookup, use a coarse partition ``p00``…``p63`` derived
    only from the public share UUID. After the high-entropy secret
    verifies, use a share-specific ``shared_report.use`` bucket.

    ``bucket`` must be an application-chosen short label (a partition or
    an already-authorized share id). Caller-supplied IDs and forwarding
    headers are never stored as identity.
    """
    cfg = settings or get_settings()
    if not cfg.rate_limit_enabled:
        return

    limit = _limit_for_action(cfg, action)
    now = datetime.now(timezone.utc)
    window_start = _window_start(now, cfg.rate_limit_window_seconds)

    db.execute(
        text("SELECT pg_advisory_xact_lock(hashtext(:lock_key))"),
        {"lock_key": f"anon:{action}:{bucket}:{window_start.isoformat()}"},
    )

    counter = db.scalar(
        select(AnonymousRateLimitCounter).where(
            AnonymousRateLimitCounter.action == action,
            AnonymousRateLimitCounter.bucket == bucket,
            AnonymousRateLimitCounter.window_start == window_start,
        )
    )
    if counter is None:
        counter = AnonymousRateLimitCounter(
            action=action,
            bucket=bucket,
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
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded for this action. Try again later.",
            headers={
                "Retry-After": str(max(retry_after, 1)),
                "Cache-Control": "private, no-store",
            },
        )

    counter.count += 1
    db.flush()
