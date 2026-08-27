from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.api.deps import AuthContext, get_auth_context, get_db, require_org_admin
from app.core.config import get_settings
from app.schemas.monitoring import MonitoringConfigurationResponse, UpsertMonitoringRequest
from app.schemas.target import (
    CreateTargetRequest,
    TargetResponse,
    TargetScopeResponse,
    UpdateTargetScopeRequest,
    VerifyTargetResponse,
)
from app.services.dns import DnsTxtResolver
from app.services.monitoring import (
    get_monitoring_for_target,
    latest_change_counts,
    upsert_monitoring,
)
from app.services.rate_limit import (
    ACTION_TARGET_CREATE,
    ACTION_VERIFICATION,
    enforce_rate_limit,
)
from app.services.targets import (
    create_target,
    get_org_target_or_404,
    list_targets,
    require_active_organization,
    revoke_target,
    start_verification,
    update_scope,
    verify_target_dns,
)

router = APIRouter(prefix="/v1/targets", tags=["targets"])


def get_dns_resolver(request: Request) -> DnsTxtResolver:
    return request.app.state.dns_resolver


def _to_target_response(target) -> TargetResponse:
    authz = None
    if target.authorization is not None:
        authz = {
            "method": target.authorization.method,
            "txt_name": target.authorization.txt_name,
            "txt_value": target.authorization.txt_value,
            "created_at": target.authorization.created_at,
            "last_checked_at": target.authorization.last_checked_at,
            "verified_at": target.authorization.verified_at,
        }
    return TargetResponse(
        id=target.id,
        organization_id=target.organization_id,
        domain=target.domain,
        status=target.status,
        created_at=target.created_at,
        updated_at=target.updated_at,
        verified_at=target.verified_at,
        revoked_at=target.revoked_at,
        authorization=authz,
    )


def _to_scope_response(scope) -> TargetScopeResponse:
    return TargetScopeResponse(
        target_id=scope.target_id,
        root_domain=scope.root_domain,
        include_subdomains=scope.include_subdomains,
        exclusions=list(scope.exclusions or []),
        created_at=scope.created_at,
        updated_at=scope.updated_at,
    )


@router.post("", response_model=TargetResponse, status_code=201)
def create_target_endpoint(
    body: CreateTargetRequest,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
) -> TargetResponse:
    require_active_organization(auth)
    assert auth.active_organization is not None
    _, _, actor = require_org_admin(auth.active_organization.id, auth, db)
    enforce_rate_limit(
        db,
        organization_id=auth.active_organization.id,
        user_id=auth.user.id,
        action=ACTION_TARGET_CREATE,
    )
    target = create_target(
        db,
        actor=actor,
        organization_id=auth.active_organization.id,
        raw_domain=body.domain,
    )
    return _to_target_response(target)


@router.get("", response_model=list[TargetResponse])
def list_targets_endpoint(
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
) -> list[TargetResponse]:
    require_active_organization(auth)
    assert auth.active_organization is not None
    targets = list_targets(db, organization_id=auth.active_organization.id)
    return [_to_target_response(t) for t in targets]


@router.get("/{target_id}", response_model=TargetResponse)
def get_target_endpoint(
    target_id: UUID,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
) -> TargetResponse:
    require_active_organization(auth)
    assert auth.active_organization is not None
    target = get_org_target_or_404(
        db, target_id=target_id, organization_id=auth.active_organization.id
    )
    return _to_target_response(target)


@router.post("/{target_id}/verification", response_model=TargetResponse)
def start_verification_endpoint(
    target_id: UUID,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
) -> TargetResponse:
    require_active_organization(auth)
    assert auth.active_organization is not None
    target = get_org_target_or_404(
        db, target_id=target_id, organization_id=auth.active_organization.id
    )
    _, _, actor = require_org_admin(auth.active_organization.id, auth, db)
    enforce_rate_limit(
        db,
        organization_id=auth.active_organization.id,
        user_id=auth.user.id,
        action=ACTION_VERIFICATION,
    )
    target = start_verification(db, target, actor=actor)
    return _to_target_response(target)


@router.post("/{target_id}/verify", response_model=VerifyTargetResponse)
def verify_target_endpoint(
    target_id: UUID,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
    resolver: Annotated[DnsTxtResolver, Depends(get_dns_resolver)],
) -> VerifyTargetResponse:
    require_active_organization(auth)
    assert auth.active_organization is not None
    target = get_org_target_or_404(
        db, target_id=target_id, organization_id=auth.active_organization.id
    )
    _, _, actor = require_org_admin(auth.active_organization.id, auth, db)
    enforce_rate_limit(
        db,
        organization_id=auth.active_organization.id,
        user_id=auth.user.id,
        action=ACTION_VERIFICATION,
    )
    target, verified, detail = verify_target_dns(
        db, target, resolver, actor=actor
    )
    return VerifyTargetResponse(
        id=target.id,
        domain=target.domain,
        status=target.status,
        verified=verified,
        detail=detail,
    )


@router.get("/{target_id}/scope", response_model=TargetScopeResponse)
def get_scope_endpoint(
    target_id: UUID,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
) -> TargetScopeResponse:
    require_active_organization(auth)
    assert auth.active_organization is not None
    target = get_org_target_or_404(
        db, target_id=target_id, organization_id=auth.active_organization.id
    )
    if target.scope is None:
        from fastapi import HTTPException, status

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Target scope not found"
        )
    return _to_scope_response(target.scope)


@router.put("/{target_id}/scope", response_model=TargetScopeResponse)
def update_scope_endpoint(
    target_id: UUID,
    body: UpdateTargetScopeRequest,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
) -> TargetScopeResponse:
    require_active_organization(auth)
    assert auth.active_organization is not None
    target = get_org_target_or_404(
        db, target_id=target_id, organization_id=auth.active_organization.id
    )
    _, _, actor = require_org_admin(auth.active_organization.id, auth, db)
    scope = update_scope(
        db,
        target,
        actor=actor,
        include_subdomains=body.include_subdomains,
        exclusions=body.exclusions,
    )
    return _to_scope_response(scope)


@router.post("/{target_id}/revoke", response_model=TargetResponse)
def revoke_target_endpoint(
    target_id: UUID,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
) -> TargetResponse:
    require_active_organization(auth)
    assert auth.active_organization is not None
    target = get_org_target_or_404(
        db, target_id=target_id, organization_id=auth.active_organization.id
    )
    _, _, actor = require_org_admin(auth.active_organization.id, auth, db)
    target = revoke_target(db, target, actor=actor)
    return _to_target_response(target)


def _to_monitoring_response(
    config,
    *,
    target_id: UUID,
    organization_id: UUID,
    changes: dict,
    include_recipients: bool,
):
    email_delivery_enabled = bool(get_settings().email_delivery_enabled)
    if config is None:
        return MonitoringConfigurationResponse(
            id=None,
            organization_id=organization_id,
            target_id=target_id,
            enabled=False,
            auto_generate_reports=False,
            auto_deliver_reports=False,
            auto_deliver_expires_in="7d",
            recipient_count=0,
            recipients=[] if include_recipients else None,
            email_delivery_enabled=email_delivery_enabled,
            frequency="weekly",
            next_run_at=None,
            last_run_at=None,
            disabled_reason=None,
            created_at=None,
            updated_at=None,
            latest_changes=changes,
        )
    emails = sorted(row.email_normalized for row in (config.delivery_recipients or []))
    return MonitoringConfigurationResponse(
        id=config.id,
        organization_id=config.organization_id,
        target_id=config.target_id,
        enabled=bool(config.enabled),
        auto_generate_reports=bool(config.auto_generate_reports),
        auto_deliver_reports=bool(config.auto_deliver_reports),
        auto_deliver_expires_in=config.auto_deliver_expires_in or "7d",
        recipient_count=len(emails),
        recipients=emails if include_recipients else None,
        email_delivery_enabled=email_delivery_enabled,
        frequency=config.frequency,
        next_run_at=config.next_run_at,
        last_run_at=config.last_run_at,
        disabled_reason=config.disabled_reason,
        created_at=config.created_at,
        updated_at=config.updated_at,
        latest_changes=changes,
    )


@router.get("/{target_id}/monitoring", response_model=MonitoringConfigurationResponse)
def get_monitoring_endpoint(
    target_id: UUID,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
) -> MonitoringConfigurationResponse:
    require_active_organization(auth)
    assert auth.active_organization is not None
    target = get_org_target_or_404(
        db, target_id=target_id, organization_id=auth.active_organization.id
    )
    config = get_monitoring_for_target(db, target_id=target.id, user_id=auth.user.id)
    changes = latest_change_counts(db, target_id=target.id)
    actor = auth.org_actor()
    include_recipients = actor is not None and actor.is_admin
    return _to_monitoring_response(
        config,
        target_id=target.id,
        organization_id=target.organization_id,
        changes=changes,
        include_recipients=include_recipients,
    )


@router.put("/{target_id}/monitoring", response_model=MonitoringConfigurationResponse)
def upsert_monitoring_endpoint(
    target_id: UUID,
    body: UpsertMonitoringRequest,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
) -> MonitoringConfigurationResponse:
    require_active_organization(auth)
    assert auth.active_organization is not None
    get_org_target_or_404(
        db, target_id=target_id, organization_id=auth.active_organization.id
    )
    _, _, actor = require_org_admin(auth.active_organization.id, auth, db)
    config = upsert_monitoring(
        db,
        actor=actor,
        target_id=target_id,
        enabled=body.enabled,
        frequency=body.frequency,
        auto_generate_reports=body.auto_generate_reports,
        auto_deliver_reports=body.auto_deliver_reports,
        auto_deliver_expires_in=body.auto_deliver_expires_in,
        recipients=body.recipients,
    )
    config = get_monitoring_for_target(db, target_id=config.target_id, user_id=auth.user.id)
    changes = latest_change_counts(db, target_id=config.target_id)
    return _to_monitoring_response(
        config,
        target_id=config.target_id,
        organization_id=config.organization_id,
        changes=changes,
        include_recipients=True,
    )
