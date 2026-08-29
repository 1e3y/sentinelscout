from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import AuthContext, get_auth_context, get_db
from app.core.config import get_settings
from app.schemas.security_overview import SecurityOverviewResponse
from app.services.security_overview import (
    DEFAULT_PAGE_SIZE,
    MAX_PAGE_SIZE,
    list_security_overview,
)
from app.services.targets import require_active_organization

router = APIRouter(prefix="/v1/security-overview", tags=["security-overview"])


@router.get("", response_model=SecurityOverviewResponse)
def get_security_overview_endpoint(
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
    page_size: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = DEFAULT_PAGE_SIZE,
    cursor: str | None = None,
) -> SecurityOverviewResponse:
    """Read-only overview of the caller's active organization. Members and admins alike."""
    require_active_organization(auth)
    assert auth.active_organization is not None
    return list_security_overview(
        db,
        organization=auth.active_organization,
        email_delivery_enabled=bool(get_settings().email_delivery_enabled),
        page_size=page_size,
        cursor=cursor,
    )
