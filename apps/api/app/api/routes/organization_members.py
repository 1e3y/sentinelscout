from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query

from app.api.deps import AuthContext, get_auth_context, get_clerk_directory, get_db
from app.schemas.organization_members import OrganizationMembersResponse
from app.services.clerk import ClerkDirectory
from app.services.organization_members import (
    DEFAULT_MEMBER_PAGE_SIZE,
    MAX_MEMBER_PAGE_SIZE,
    list_active_organization_members,
)
from app.services.targets import require_active_organization
from sqlalchemy.orm import Session

router = APIRouter(prefix="/v1/organization-members", tags=["organization-members"])


@router.get("", response_model=OrganizationMembersResponse)
def list_organization_members_endpoint(
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
    directory: Annotated[ClerkDirectory, Depends(get_clerk_directory)],
    page_size: Annotated[
        int, Query(ge=1, le=MAX_MEMBER_PAGE_SIZE)
    ] = DEFAULT_MEMBER_PAGE_SIZE,
    cursor: str | None = None,
) -> OrganizationMembersResponse:
    """Paginated current members of the verified active organization."""
    require_active_organization(auth)
    assert auth.active_organization is not None
    return list_active_organization_members(
        db,
        organization=auth.active_organization,
        directory=directory,
        page_size=page_size,
        cursor=cursor,
    )
