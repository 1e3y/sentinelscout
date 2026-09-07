"""Organization access review + management endpoints (Milestones 38 / 39).

M38 GET remains observational and provider-authoritative.
M39 mutations target linked app User.id only; provider is authoritative.
"""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import AuthContext, get_auth_context, get_clerk_directory, get_db, require_org_admin
from app.schemas.organization_access import OrganizationAccessResponse
from app.schemas.organization_access_mutations import (
    OrganizationMemberRemovalResponse,
    OrganizationMemberRoleUpdateRequest,
    OrganizationMemberRoleUpdateResponse,
)
from app.services.clerk import ClerkDirectory
from app.services.organization_access import (
    DEFAULT_PAGE_SIZE,
    MAX_PAGE_SIZE,
    list_organization_access,
)
from app.services.organization_access_mutations import (
    remove_organization_member,
    update_organization_member_role,
)
from app.services.rate_limit import (
    ACTION_ORGANIZATION_ACCESS_MUTATE,
    ACTION_ORGANIZATION_ACCESS_READ,
    enforce_rate_limit,
)
from app.services.targets import require_active_organization

router = APIRouter(prefix="/v1/organization-access", tags=["organization-access"])


@router.get("", response_model=OrganizationAccessResponse)
def list_organization_access_endpoint(
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
    directory: Annotated[ClerkDirectory, Depends(get_clerk_directory)],
    page_size: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = DEFAULT_PAGE_SIZE,
    cursor: str | None = None,
) -> OrganizationAccessResponse:
    """Paginated authoritative current membership for the verified active organization."""
    require_active_organization(auth)
    assert auth.active_organization is not None
    organization, _membership, actor = require_org_admin(
        auth.active_organization.id, auth, db
    )

    # Rate-limit BEFORE any provider membership-list call.
    enforce_rate_limit(
        db,
        organization_id=organization.id,
        user_id=actor.user_id,
        action=ACTION_ORGANIZATION_ACCESS_READ,
    )

    return list_organization_access(
        db,
        organization=organization,
        directory=directory,
        page_size=page_size,
        cursor=cursor,
    )


@router.put(
    "/members/{user_id}/role",
    response_model=OrganizationMemberRoleUpdateResponse,
)
def update_organization_member_role_endpoint(
    user_id: UUID,
    body: OrganizationMemberRoleUpdateRequest,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
    directory: Annotated[ClerkDirectory, Depends(get_clerk_directory)],
) -> OrganizationMemberRoleUpdateResponse:
    """Change a linked member's recognized organization role (admin|member)."""
    require_active_organization(auth)
    assert auth.active_organization is not None
    organization, _membership, actor = require_org_admin(
        auth.active_organization.id, auth, db
    )

    # Rate-limit BEFORE provider verification/write.
    enforce_rate_limit(
        db,
        organization_id=organization.id,
        user_id=actor.user_id,
        action=ACTION_ORGANIZATION_ACCESS_MUTATE,
    )

    return update_organization_member_role(
        db,
        organization=organization,
        directory=directory,
        actor_user_id=actor.user_id,
        target_user_id=user_id,
        requested_role=body.role,
    )


@router.delete(
    "/members/{user_id}",
    response_model=OrganizationMemberRemovalResponse,
)
def remove_organization_member_endpoint(
    user_id: UUID,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
    directory: Annotated[ClerkDirectory, Depends(get_clerk_directory)],
) -> OrganizationMemberRemovalResponse:
    """Remove a linked recognized ordinary member from the organization."""
    require_active_organization(auth)
    assert auth.active_organization is not None
    organization, _membership, actor = require_org_admin(
        auth.active_organization.id, auth, db
    )

    enforce_rate_limit(
        db,
        organization_id=organization.id,
        user_id=actor.user_id,
        action=ACTION_ORGANIZATION_ACCESS_MUTATE,
    )

    return remove_organization_member(
        db,
        organization=organization,
        directory=directory,
        actor_user_id=actor.user_id,
        target_user_id=user_id,
    )
