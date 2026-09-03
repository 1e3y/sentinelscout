"""Organization notification delivery ledger endpoint (Milestone 36)."""

from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import AuthContext, get_auth_context, get_db, require_org_admin
from app.schemas.notification_deliveries import NotificationDeliveriesResponse
from app.services.notification_deliveries import (
    DEFAULT_PAGE_SIZE,
    MAX_PAGE_SIZE,
    list_notification_deliveries,
)
from app.services.targets import require_active_organization

router = APIRouter(prefix="/v1", tags=["notification-deliveries"])

DeliveryClassParam = Literal["alert_email", "report_delivery", "follow_up_reminder"]
StateParam = Literal[
    "pending",
    "processing",
    "retrying",
    "delivered",
    "skipped",
    "dead",
]


@router.get(
    "/notification-deliveries",
    response_model=NotificationDeliveriesResponse,
)
def list_notification_deliveries_endpoint(
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
    page_size: Annotated[
        int, Query(ge=1, le=MAX_PAGE_SIZE)
    ] = DEFAULT_PAGE_SIZE,
    cursor: Annotated[str | None, Query()] = None,
    delivery_class: Annotated[DeliveryClassParam | None, Query()] = None,
    state: Annotated[StateParam | None, Query()] = None,
) -> NotificationDeliveriesResponse:
    require_active_organization(auth)
    assert auth.active_organization is not None
    organization, _membership, _actor = require_org_admin(
        auth.active_organization.id, auth, db
    )
    return list_notification_deliveries(
        db,
        organization_id=organization.id,
        page_size=page_size,
        cursor=cursor,
        delivery_class=delivery_class,
        state=state,  # type: ignore[arg-type]
    )
