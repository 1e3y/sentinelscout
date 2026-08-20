from __future__ import annotations

import secrets
from datetime import datetime, timezone
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from app.models.target import AuthorizedTarget, TargetAuthorization, TargetScope
from app.services.audit import record_audit
from app.services.authorization import (
    AuthorizedOrgActor,
    assert_admin_actor,
    merge_auth_audit,
)
from app.services.dns import DnsTxtResolver
from app.services.domains import (
    build_txt_name,
    build_txt_value,
    is_subdomain_or_self,
    normalize_domain,
)

VALID_STATUSES = frozenset(
    {"unverified", "verification_pending", "verified", "revoked"}
)


def require_active_organization(auth) -> None:
    if auth.active_organization is None or auth.active_membership is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Active organization required",
        )


def get_org_target_or_404(
    db: Session,
    *,
    target_id: UUID,
    organization_id: UUID,
) -> AuthorizedTarget:
    target = db.scalar(
        select(AuthorizedTarget)
        .options(
            joinedload(AuthorizedTarget.authorization),
            joinedload(AuthorizedTarget.scope),
        )
        .where(
            AuthorizedTarget.id == target_id,
            AuthorizedTarget.organization_id == organization_id,
        )
    )
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found")
    return target


def create_target(
    db: Session,
    *,
    actor: AuthorizedOrgActor,
    organization_id: UUID,
    raw_domain: str,
) -> AuthorizedTarget:
    assert_admin_actor(actor, organization_id, not_found="Target not found")
    domain = normalize_domain(raw_domain)

    existing = db.scalar(
        select(AuthorizedTarget).where(
            AuthorizedTarget.organization_id == organization_id,
            AuthorizedTarget.domain == domain,
        )
    )
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Target domain already registered for this organization",
        )

    target = AuthorizedTarget(
        organization_id=organization_id,
        created_by_user_id=actor.user_id,
        domain=domain,
        status="unverified",
    )
    db.add(target)
    db.flush()

    scope = TargetScope(
        target_id=target.id,
        root_domain=domain,
        include_subdomains=False,
        exclusions=[],
    )
    db.add(scope)
    record_audit(
        db,
        organization_id=organization_id,
        actor_type="user",
        actor_user_id=actor.user_id,
        action="target.created",
        resource_type="target",
        resource_id=target.id,
        summary=f"Target created: {domain}.",
        metadata=merge_auth_audit(
            actor,
            {"target_id": str(target.id), "domain": domain, "status": "unverified"},
        ),
    )
    db.commit()
    db.refresh(target)
    return get_org_target_or_404(db, target_id=target.id, organization_id=organization_id)


def list_targets(db: Session, *, organization_id: UUID) -> list[AuthorizedTarget]:
    return list(
        db.scalars(
            select(AuthorizedTarget)
            .options(
                joinedload(AuthorizedTarget.authorization),
                joinedload(AuthorizedTarget.scope),
            )
            .where(AuthorizedTarget.organization_id == organization_id)
            .order_by(AuthorizedTarget.created_at.desc())
        ).unique().all()
    )


def start_verification(
    db: Session,
    target: AuthorizedTarget,
    *,
    actor: AuthorizedOrgActor,
) -> AuthorizedTarget:
    assert_admin_actor(actor, target.organization_id, not_found="Target not found")
    if target.status == "revoked":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Revoked targets cannot be verified",
        )

    token = secrets.token_urlsafe(32)
    txt_name = build_txt_name(target.domain)
    txt_value = build_txt_value(token)

    authz = target.authorization
    if authz is None:
        authz = TargetAuthorization(
            target_id=target.id,
            method="dns_txt",
            token=token,
            txt_name=txt_name,
            txt_value=txt_value,
        )
        db.add(authz)
    else:
        authz.method = "dns_txt"
        authz.token = token
        authz.txt_name = txt_name
        authz.txt_value = txt_value
        authz.verified_at = None
        authz.last_checked_at = None

    if target.status != "verified":
        target.status = "verification_pending"

    record_audit(
        db,
        organization_id=target.organization_id,
        actor_type="user",
        actor_user_id=actor.user_id,
        action="target.verification_started",
        resource_type="target",
        resource_id=target.id,
        summary=f"Verification started for {target.domain}.",
        metadata=merge_auth_audit(
            actor,
            {
                "target_id": str(target.id),
                "domain": target.domain,
                "status": target.status,
                "authorization_id": str(authz.id) if authz.id else None,
            },
        ),
    )
    db.commit()
    return get_org_target_or_404(
        db, target_id=target.id, organization_id=target.organization_id
    )


def verify_target_dns(
    db: Session,
    target: AuthorizedTarget,
    resolver: DnsTxtResolver,
    *,
    actor: AuthorizedOrgActor,
) -> tuple[AuthorizedTarget, bool, str]:
    assert_admin_actor(actor, target.organization_id, not_found="Target not found")
    if target.status == "revoked":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Revoked targets cannot be verified",
        )

    authz = target.authorization
    if authz is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Verification has not been started",
        )

    now = datetime.now(timezone.utc)
    authz.last_checked_at = now

    records = resolver.lookup_txt(authz.txt_name)
    expected = authz.txt_value
    matched = any(_txt_matches(record, expected) for record in records)

    if not matched:
        db.commit()
        return (
            get_org_target_or_404(
                db, target_id=target.id, organization_id=target.organization_id
            ),
            False,
            "TXT record not found or token mismatch",
        )

    target.status = "verified"
    target.verified_at = now
    target.revoked_at = None
    authz.verified_at = now
    record_audit(
        db,
        organization_id=target.organization_id,
        actor_type="user",
        actor_user_id=actor.user_id,
        action="target.verified",
        resource_type="target",
        resource_id=target.id,
        summary=f"Target verified: {target.domain}.",
        metadata=merge_auth_audit(
            actor,
            {
                "target_id": str(target.id),
                "domain": target.domain,
                "status": "verified",
                "authorization_status": "verified",
                "authorization_id": str(authz.id),
            },
        ),
    )
    db.commit()
    return (
        get_org_target_or_404(
            db, target_id=target.id, organization_id=target.organization_id
        ),
        True,
        "Domain ownership verified",
    )


def _txt_matches(record: str, expected: str) -> bool:
    return record.strip().strip('"') == expected


def update_scope(
    db: Session,
    target: AuthorizedTarget,
    *,
    actor: AuthorizedOrgActor,
    include_subdomains: bool,
    exclusions: list[str],
) -> TargetScope:
    assert_admin_actor(actor, target.organization_id, not_found="Target not found")
    if target.scope is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Target scope missing",
        )

    normalized_exclusions: list[str] = []
    seen: set[str] = set()
    for item in exclusions:
        domain = normalize_domain(item)
        if not is_subdomain_or_self(domain, target.domain):
            raise HTTPException(
                status_code=422,
                detail=f"Exclusion '{domain}' is outside target root domain",
            )
        if domain == target.domain:
            raise HTTPException(
                status_code=422,
                detail="Root domain cannot be listed as an exclusion",
            )
        if domain not in seen:
            seen.add(domain)
            normalized_exclusions.append(domain)

    target.scope.include_subdomains = include_subdomains
    target.scope.exclusions = normalized_exclusions
    target.scope.root_domain = target.domain
    record_audit(
        db,
        organization_id=target.organization_id,
        actor_type="user",
        actor_user_id=actor.user_id,
        action="target.scope_updated",
        resource_type="target",
        resource_id=target.id,
        summary=f"Scope updated for {target.domain}.",
        metadata=merge_auth_audit(
            actor,
            {
                "target_id": str(target.id),
                "domain": target.domain,
                "scope_root": target.domain,
                "include_subdomains": include_subdomains,
                "exclusions_count": len(normalized_exclusions),
            },
        ),
    )
    db.commit()
    db.refresh(target.scope)
    return target.scope


def is_effectively_verified(target: AuthorizedTarget) -> bool:
    return target.status == "verified"


def revoke_target(
    db: Session,
    target: AuthorizedTarget,
    *,
    actor: AuthorizedOrgActor,
) -> AuthorizedTarget:
    assert_admin_actor(actor, target.organization_id, not_found="Target not found")
    if target.status == "revoked":
        return get_org_target_or_404(
            db, target_id=target.id, organization_id=target.organization_id
        )

    target.status = "revoked"
    target.revoked_at = datetime.now(timezone.utc)
    record_audit(
        db,
        organization_id=target.organization_id,
        actor_type="user",
        actor_user_id=actor.user_id,
        action="target.revoked",
        resource_type="target",
        resource_id=target.id,
        summary=f"Target revoked: {target.domain}.",
        metadata=merge_auth_audit(
            actor,
            {
                "target_id": str(target.id),
                "domain": target.domain,
                "status": "revoked",
                "authorization_status": "revoked",
            },
        ),
    )
    db.commit()
    return get_org_target_or_404(
        db, target_id=target.id, organization_id=target.organization_id
    )
