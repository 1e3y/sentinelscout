from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated
from uuid import UUID

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.security import AuthenticatedIdentity, TokenVerifier
from app.models import Organization, OrganizationMembership, User
from app.services.authorization import (
    AuthorizedOrgActor,
    effective_authorized_role,
    persistable_org_role,
)
from app.services.clerk import ClerkDirectory
from app.services.sync import sync_user_from_clerk

bearer_scheme = HTTPBearer(auto_error=False)


@dataclass
class AuthContext:
    identity: AuthenticatedIdentity
    user: User
    active_organization: Organization | None
    active_membership: OrganizationMembership | None
    directory_role: str | None

    def org_actor(self) -> AuthorizedOrgActor | None:
        if self.active_organization is None:
            return None
        return AuthorizedOrgActor(
            user_id=self.user.id,
            organization_id=self.active_organization.id,
            normalized_role=effective_authorized_role(
                self.identity.active_org_role, self.directory_role
            ),
        )


def get_token_verifier(request: Request) -> TokenVerifier:
    return request.app.state.token_verifier


def get_clerk_directory(request: Request) -> ClerkDirectory:
    return request.app.state.clerk_directory


def get_identity(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    verifier: Annotated[TokenVerifier, Depends(get_token_verifier)],
) -> AuthenticatedIdentity:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token",
        )
    return verifier.verify(credentials.credentials)


def get_auth_context(
    identity: Annotated[AuthenticatedIdentity, Depends(get_identity)],
    db: Annotated[Session, Depends(get_db)],
    directory: Annotated[ClerkDirectory, Depends(get_clerk_directory)],
) -> AuthContext:
    user = sync_user_from_clerk(db, directory, identity.clerk_user_id)

    active_organization: Organization | None = None
    active_membership: OrganizationMembership | None = None
    directory_role: str | None = None
    if identity.active_org_id:
        active_organization = db.scalar(
            select(Organization).where(Organization.clerk_org_id == identity.active_org_id)
        )
        if active_organization is not None:
            active_membership = db.scalar(
                select(OrganizationMembership).where(
                    OrganizationMembership.organization_id == active_organization.id,
                    OrganizationMembership.user_id == user.id,
                )
            )
            # Active org from JWT without persisted membership is ignored.
            if active_membership is None:
                active_organization = None
            else:
                directory_role = active_membership.role
                effective = effective_authorized_role(
                    identity.active_org_role, directory_role
                )
                if effective is not None and active_membership.role != persistable_org_role(
                    effective
                ):
                    active_membership.role = persistable_org_role(effective)
                    db.commit()
                    db.refresh(active_membership)

    return AuthContext(
        identity=identity,
        user=user,
        active_organization=active_organization,
        active_membership=active_membership,
        directory_role=directory_role,
    )


def verified_org_admin_role(auth: AuthContext, organization: Organization) -> bool:
    """True only when the verified request identity authorizes admin for this org."""
    actor = auth.org_actor()
    return (
        actor is not None
        and actor.organization_id == organization.id
        and actor.is_admin
        and auth.identity.active_org_id == organization.clerk_org_id
    )


def require_org_membership(
    org_id: UUID,
    auth: AuthContext,
    db: Session,
) -> tuple[Organization, OrganizationMembership]:
    organization = db.get(Organization, org_id)
    if organization is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")

    membership = db.scalar(
        select(OrganizationMembership).where(
            OrganizationMembership.organization_id == organization.id,
            OrganizationMembership.user_id == auth.user.id,
        )
    )
    if membership is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")

    return organization, membership


def require_org_member(
    org_id: UUID,
    auth: AuthContext,
    db: Session,
) -> tuple[Organization, OrganizationMembership, AuthorizedOrgActor]:
    if auth.active_organization is None or auth.active_membership is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Active organization required",
        )
    organization, membership = require_org_membership(org_id, auth, db)
    if auth.active_organization.id != organization.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")
    actor = auth.org_actor()
    if actor is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Active organization required",
        )
    return organization, membership, actor


def require_org_admin(
    org_id: UUID,
    auth: AuthContext,
    db: Session,
) -> tuple[Organization, OrganizationMembership, AuthorizedOrgActor]:
    organization, membership, actor = require_org_member(org_id, auth, db)
    token_org = auth.identity.active_org_id
    token_role = auth.identity.active_org_role
    if not token_org or token_org != organization.clerk_org_id or not token_role:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Verified organization role is required",
        )
    if actor.normalized_role is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Verified organization role is required",
        )
    if not actor.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Organization admin required",
        )
    membership.role = persistable_org_role("admin")
    return organization, membership, actor


def require_active_org_actor(auth: AuthContext) -> AuthorizedOrgActor:
    if auth.active_organization is None or auth.active_membership is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Active organization required",
        )
    actor = auth.org_actor()
    if actor is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Active organization required",
        )
    return actor
