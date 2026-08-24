"""Immutable AuditEvent writer with allowlisted, redacted metadata."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.audit import AUDIT_ACTOR_TYPES, AuditEvent
from app.models.organization import OrganizationMembership

# Explicit allowlist — never store secrets, tokens, bodies, or prompts.
_AUDIT_METADATA_ALLOWLIST = frozenset(
    {
        "target_id",
        "domain",
        "status",
        "source",
        "operation_id",
        "candidate_id",
        "finding_id",
        "asset_id",
        "retest_id",
        "validation_attempt_id",
        "authorization_id",
        "authorization_status",
        "scope_root",
        "include_subdomains",
        "exclusions_count",
        "frequency",
        "enabled",
        "testing_profile",
        "severity",
        "candidate_type",
        "validation_method",
        "retest_status",
        "validation_status",
        "actor_email",
        "previous_status",
        "new_status",
        "reason",
        "capability_manifest_version",
        "alert_id",
        "alert_type",
        "alert_count",
        "email_enabled",
        "email_min_priority",
        "recipient_count",
        "outbox_id",
        "channel",
        "last_error_code",
        "authorization_role",
        "authorization_basis",
        "report_id",
        "report_version",
        "schema_version",
        "snapshot_digest",
        "operation_status",
        "headline_status",
        "assessment_completeness",
        "findings_total",
        "findings_open",
        "share_id",
        "expires_at",
    }
)

_BLOCKED_METADATA_KEYS = frozenset(
    {
        "token",
        "txt_value",
        "secret",
        "password",
        "credential",
        "authorization",
        "cookie",
        "api_key",
        "apikey",
        "bearer",
        "clerk",
        "jwks",
        "prompt",
        "body",
        "response_body",
        "chain_of_thought",
        "raw",
        "share_url",
        "secret_hash",
        "fragment",
    }
)


def sanitize_audit_metadata(metadata: dict | None) -> dict:
    """Keep only explicitly allowlisted keys; drop blocked/secret-like names."""
    if not metadata:
        return {}
    clean: dict = {}
    for key, value in metadata.items():
        key_l = str(key).lower()
        # Exact blocked names never persist (even if later allowlisted by mistake).
        if key_l in _BLOCKED_METADATA_KEYS:
            continue
        # Allowlist-first so keys like authorization_status are kept safely.
        if key not in _AUDIT_METADATA_ALLOWLIST:
            # Substring block for non-allowlisted keys (token, cookie, body, …).
            if any(b in key_l for b in _BLOCKED_METADATA_KEYS):
                continue
            continue
        if isinstance(value, (str, int, float, bool)) or value is None:
            clean[key] = value
        elif isinstance(value, list) and all(isinstance(i, (str, int, float, bool)) for i in value):
            clean[key] = value[:50]
        else:
            clean[key] = str(value)[:500]
    return clean


def record_audit(
    db: Session,
    *,
    organization_id: UUID,
    actor_type: str,
    action: str,
    resource_type: str,
    summary: str,
    resource_id: UUID | None = None,
    actor_user_id: UUID | None = None,
    metadata: dict | None = None,
    commit: bool = False,
) -> AuditEvent:
    if actor_type not in AUDIT_ACTOR_TYPES:
        raise ValueError(f"Invalid audit actor_type: {actor_type}")
    event = AuditEvent(
        organization_id=organization_id,
        actor_type=actor_type,
        actor_user_id=actor_user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        summary=summary,
        event_metadata=sanitize_audit_metadata(metadata),
    )
    db.add(event)
    db.flush()
    if commit:
        db.commit()
        db.refresh(event)
    return event


def list_audit_events(
    db: Session,
    *,
    user_id: UUID,
    resource_type: str | None = None,
    resource_id: UUID | None = None,
    action: str | None = None,
    created_after: datetime | None = None,
    created_before: datetime | None = None,
    limit: int = 100,
) -> list[AuditEvent]:
    org_ids = set(
        db.scalars(
            select(OrganizationMembership.organization_id).where(
                OrganizationMembership.user_id == user_id
            )
        ).all()
    )
    if not org_ids:
        return []

    stmt = (
        select(AuditEvent)
        .where(AuditEvent.organization_id.in_(org_ids))
        .order_by(AuditEvent.created_at.desc())
        .limit(min(max(limit, 1), 500))
    )
    if resource_type:
        stmt = stmt.where(AuditEvent.resource_type == resource_type)
    if resource_id is not None:
        stmt = stmt.where(AuditEvent.resource_id == resource_id)
    if action:
        stmt = stmt.where(AuditEvent.action == action)
    if created_after is not None:
        stmt = stmt.where(AuditEvent.created_at >= created_after)
    if created_before is not None:
        stmt = stmt.where(AuditEvent.created_at <= created_before)
    return list(db.scalars(stmt).all())


def get_audit_event_or_404(db: Session, *, event_id: UUID, user_id: UUID) -> AuditEvent:
    event = db.get(AuditEvent, event_id)
    if event is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit event not found")
    membership = db.scalar(
        select(OrganizationMembership).where(
            OrganizationMembership.user_id == user_id,
            OrganizationMembership.organization_id == event.organization_id,
        )
    )
    if membership is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit event not found")
    return event
