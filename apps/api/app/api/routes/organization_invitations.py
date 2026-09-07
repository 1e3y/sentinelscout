"""Organization invitation endpoints (Milestones 40–41, 43).

Provider-authoritative member invitations, pending revocation, and terminal
invitation history. No local invitation table. invitation_ref stays out of
URL/query paths. M42 resend remains deferred.
"""

from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.api.deps import AuthContext, get_auth_context, get_clerk_directory, get_db, require_org_admin
from app.schemas.organization_invitations import (
    OrganizationInvitationCreateRequest,
    OrganizationInvitationCreated,
    OrganizationInvitationHistoryResponse,
    OrganizationInvitationRevokeRequest,
    OrganizationInvitationRevoked,
    OrganizationInvitationsResponse,
)
from app.services.clerk import ClerkDirectory
from app.services.organization_invitation_refs import InvitationRefCodecError, open_invitation_ref
from app.services.organization_invitations import (
    DEFAULT_PAGE_SIZE,
    MAX_PAGE_SIZE,
    create_organization_invitation,
    decode_history_cursor,
    list_organization_invitation_history,
    list_pending_organization_invitations,
    normalize_history_filter_key,
    raise_pending_not_found,
    revoke_organization_invitation,
)
from app.services.rate_limit import (
    ACTION_ORGANIZATION_INVITATION_CREATE,
    ACTION_ORGANIZATION_INVITATION_HISTORY_READ,
    ACTION_ORGANIZATION_INVITATION_READ,
    ACTION_ORGANIZATION_INVITATION_REVOKE,
    enforce_rate_limit,
)
from app.services.targets import require_active_organization

router = APIRouter(
    prefix="/v1/organization-invitations",
    tags=["organization-invitations"],
)


@router.post(
    "",
    response_model=OrganizationInvitationCreated,
    status_code=status.HTTP_201_CREATED,
)
def create_organization_invitation_endpoint(
    body: OrganizationInvitationCreateRequest,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
    directory: Annotated[ClerkDirectory, Depends(get_clerk_directory)],
) -> OrganizationInvitationCreated:
    """Invite one person as a member of the active organization."""
    require_active_organization(auth)
    assert auth.active_organization is not None
    organization, _membership, actor = require_org_admin(
        auth.active_organization.id, auth, db
    )

    enforce_rate_limit(
        db,
        organization_id=organization.id,
        user_id=actor.user_id,
        action=ACTION_ORGANIZATION_INVITATION_CREATE,
    )

    return create_organization_invitation(
        db,
        organization=organization,
        directory=directory,
        actor_user_id=actor.user_id,
        actor_clerk_user_id=auth.user.clerk_user_id,
        email_raw=body.email,
    )


@router.get("", response_model=OrganizationInvitationsResponse)
def list_organization_invitations_endpoint(
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
    directory: Annotated[ClerkDirectory, Depends(get_clerk_directory)],
    page_size: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = DEFAULT_PAGE_SIZE,
    cursor: str | None = None,
) -> OrganizationInvitationsResponse:
    """List currently pending provider invitations for the active organization."""
    require_active_organization(auth)
    assert auth.active_organization is not None
    organization, _membership, actor = require_org_admin(
        auth.active_organization.id, auth, db
    )

    enforce_rate_limit(
        db,
        organization_id=organization.id,
        user_id=actor.user_id,
        action=ACTION_ORGANIZATION_INVITATION_READ,
    )

    return list_pending_organization_invitations(
        organization=organization,
        directory=directory,
        page_size=page_size,
        cursor=cursor,
    )


@router.get("/history", response_model=OrganizationInvitationHistoryResponse)
def list_organization_invitation_history_endpoint(
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
    directory: Annotated[ClerkDirectory, Depends(get_clerk_directory)],
    page_size: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = DEFAULT_PAGE_SIZE,
    cursor: str | None = None,
    status_filter: Annotated[
        Literal["accepted", "revoked", "expired"] | None,
        Query(alias="status"),
    ] = None,
) -> OrganizationInvitationHistoryResponse:
    """List terminal organization invitation history (read-only).

    Omit ``status`` for all terminal (accepted+revoked+expired). ``status=all``
    is not supported (422 via schema).
    """
    require_active_organization(auth)
    assert auth.active_organization is not None
    organization, _membership, actor = require_org_admin(
        auth.active_organization.id, auth, db
    )

    # Validate normalized filter + cursor binding before rate limit / provider I/O.
    filter_key = normalize_history_filter_key(status_filter)
    if cursor is not None:
        decode_history_cursor(cursor, expected_filter_key=filter_key)

    enforce_rate_limit(
        db,
        organization_id=organization.id,
        user_id=actor.user_id,
        action=ACTION_ORGANIZATION_INVITATION_HISTORY_READ,
    )

    return list_organization_invitation_history(
        organization=organization,
        directory=directory,
        status=status_filter,
        page_size=page_size,
        cursor=cursor,
    )


@router.post(
    "/revoke",
    response_model=OrganizationInvitationRevoked,
    status_code=status.HTTP_200_OK,
)
def revoke_organization_invitation_endpoint(
    body: OrganizationInvitationRevokeRequest,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
    directory: Annotated[ClerkDirectory, Depends(get_clerk_directory)],
) -> OrganizationInvitationRevoked:
    """Revoke one pending invitation via opaque invitation_ref (body only)."""
    require_active_organization(auth)
    assert auth.active_organization is not None
    organization, _membership, actor = require_org_admin(
        auth.active_organization.id, auth, db
    )

    # Local decrypt/validate before rate limit and before any provider I/O.
    # Do not log request bodies / invitation_ref.
    try:
        open_invitation_ref(
            body.invitation_ref,
            expected_organization_id=organization.id,
        )
    except InvitationRefCodecError:
        raise_pending_not_found()

    enforce_rate_limit(
        db,
        organization_id=organization.id,
        user_id=actor.user_id,
        action=ACTION_ORGANIZATION_INVITATION_REVOKE,
    )

    return revoke_organization_invitation(
        db,
        organization=organization,
        directory=directory,
        actor_user_id=actor.user_id,
        actor_clerk_user_id=auth.user.clerk_user_id,
        invitation_ref=body.invitation_ref,
    )
