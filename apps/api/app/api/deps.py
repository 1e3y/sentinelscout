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
from app.services.clerk import ClerkDirectory
from app.services.sync import sync_user_from_clerk

bearer_scheme = HTTPBearer(auto_error=False)


@dataclass
class AuthContext:
    identity: AuthenticatedIdentity
    user: User
    active_organization: Organization | None
    active_membership: OrganizationMembership | None


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

    return AuthContext(
        identity=identity,
        user=user,
        active_organization=active_organization,
        active_membership=active_membership,
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
