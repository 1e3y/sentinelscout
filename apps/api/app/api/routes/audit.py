from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import AuthContext, get_auth_context, get_db
from app.schemas.audit import AuditEventResponse
from app.services.audit import list_audit_events

router = APIRouter(prefix="/v1/audit-events", tags=["audit"])


def _to_audit_response(event) -> AuditEventResponse:
    return AuditEventResponse(
        id=event.id,
        organization_id=event.organization_id,
        actor_type=event.actor_type,
        actor_user_id=event.actor_user_id,
        action=event.action,
        resource_type=event.resource_type,
        resource_id=event.resource_id,
        summary=event.summary,
        metadata=dict(event.event_metadata or {}),
        created_at=event.created_at,
    )


@router.get("", response_model=list[AuditEventResponse])
def list_audit_events_endpoint(
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
    resource_type: Annotated[str | None, Query()] = None,
    resource_id: Annotated[UUID | None, Query()] = None,
    action: Annotated[str | None, Query()] = None,
    created_after: Annotated[datetime | None, Query()] = None,
    created_before: Annotated[datetime | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[AuditEventResponse]:
    events = list_audit_events(
        db,
        user_id=auth.user.id,
        resource_type=resource_type,
        resource_id=resource_id,
        action=action,
        created_after=created_after,
        created_before=created_before,
        limit=limit,
    )
    return [_to_audit_response(event) for event in events]
