"""Organization audit trail endpoint (Milestone 37).

Replaces the former member-readable raw metadata list contract.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.deps import AuthContext, get_auth_context, get_db, require_org_admin
from app.schemas.organization_audit import (
    CustomerAuditAction,
    CustomerAuditResourceKind,
    OrganizationAuditEventsResponse,
)
from app.services.organization_audit import (
    DEFAULT_PAGE_SIZE,
    MAX_PAGE_SIZE,
    list_organization_audit_events,
)
from app.services.targets import require_active_organization

router = APIRouter(prefix="/v1/audit-events", tags=["audit"])


def _require_aware(value: datetime | None, *, field_name: str) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"{field_name} must be a timezone-aware ISO-8601 datetime",
        )
    return value.astimezone(timezone.utc)


@router.get("", response_model=OrganizationAuditEventsResponse)
def list_audit_events_endpoint(
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
    page_size: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = DEFAULT_PAGE_SIZE,
    cursor: Annotated[str | None, Query()] = None,
    action: Annotated[CustomerAuditAction | None, Query()] = None,
    resource_type: Annotated[CustomerAuditResourceKind | None, Query()] = None,
    actor_user_id: Annotated[UUID | None, Query()] = None,
    from_: Annotated[datetime | None, Query(alias="from")] = None,
    to: Annotated[datetime | None, Query()] = None,
) -> OrganizationAuditEventsResponse:
    require_active_organization(auth)
    assert auth.active_organization is not None
    organization, _membership, _actor = require_org_admin(
        auth.active_organization.id, auth, db
    )

    created_from = _require_aware(from_, field_name="from")
    created_to = _require_aware(to, field_name="to")
    if created_from is not None and created_to is not None and created_from > created_to:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="from must be less than or equal to to",
        )

    return list_organization_audit_events(
        db,
        organization_id=organization.id,
        page_size=page_size,
        cursor=cursor,
        action=action,
        resource_type=resource_type,
        actor_user_id=actor_user_id,
        created_from=created_from,
        created_to=created_to,
    )
