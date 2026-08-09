from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import AuthContext, get_auth_context, get_db, require_org_membership
from app.models import Organization, OrganizationMembership
from app.schemas.organization import OrganizationDetailResponse, OrganizationResponse

router = APIRouter(prefix="/v1/organizations", tags=["organizations"])


@router.get("", response_model=list[OrganizationResponse])
def list_organizations(
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
) -> list[OrganizationResponse]:
    rows = db.execute(
        select(Organization, OrganizationMembership)
        .join(
            OrganizationMembership,
            OrganizationMembership.organization_id == Organization.id,
        )
        .where(OrganizationMembership.user_id == auth.user.id)
        .order_by(Organization.name.asc())
    ).all()

    return [
        OrganizationResponse(
            id=org.id,
            clerk_org_id=org.clerk_org_id,
            name=org.name,
            role=membership.role,
            created_at=org.created_at,
        )
        for org, membership in rows
    ]


@router.get("/{org_id}", response_model=OrganizationDetailResponse)
def get_organization(
    org_id: UUID,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
) -> OrganizationDetailResponse:
    organization, membership = require_org_membership(org_id, auth, db)
    return OrganizationDetailResponse(
        id=organization.id,
        clerk_org_id=organization.clerk_org_id,
        name=organization.name,
        role=membership.role,
        created_at=organization.created_at,
    )
