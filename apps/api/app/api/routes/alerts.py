from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import AuthContext, get_auth_context, get_db
from app.schemas.alert import AlertResponse, AlertSummaryResponse
from app.services.alerts import (
    acknowledge_alert,
    alert_summary_for_user,
    dismiss_alert,
    get_alert_or_404,
    list_alerts_for_user,
    load_public_deliveries,
    mark_alert_read,
    serialize_alert,
    serialize_alert_for_user,
)

router = APIRouter(prefix="/v1/alerts", tags=["alerts"])


def _to_response(row, deliveries) -> AlertResponse:
    alert, episode, state, domain = row
    return AlertResponse.model_validate(
        serialize_alert(
            alert=alert,
            episode=episode,
            state=state,
            target_domain=domain,
            deliveries=deliveries,
        )
    )


@router.get("", response_model=list[AlertResponse])
def list_alerts_endpoint(
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
    category: str | None = None,
    priority: str | None = None,
    unread: bool = False,
    include_dismissed: bool = Query(default=False),
) -> list[AlertResponse]:
    rows = list_alerts_for_user(
        db,
        user_id=auth.user.id,
        category=category,
        priority=priority,
        unread=unread,
        include_dismissed=include_dismissed,
    )
    deliveries = load_public_deliveries(db, alert_ids=[item[0].id for item in rows])
    return [_to_response(row, deliveries.get(row[0].id, [])) for row in rows]


@router.get("/summary", response_model=AlertSummaryResponse)
def alert_summary_endpoint(
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
) -> AlertSummaryResponse:
    return AlertSummaryResponse.model_validate(
        alert_summary_for_user(db, user_id=auth.user.id)
    )


@router.get("/{alert_id}", response_model=AlertResponse)
def get_alert_endpoint(
    alert_id: UUID,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
) -> AlertResponse:
    alert = get_alert_or_404(db, alert_id=alert_id, user_id=auth.user.id)
    return AlertResponse.model_validate(
        serialize_alert_for_user(db, alert=alert, user_id=auth.user.id)
    )


@router.post("/{alert_id}/read", response_model=AlertResponse)
def read_alert_endpoint(
    alert_id: UUID,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
) -> AlertResponse:
    alert = get_alert_or_404(db, alert_id=alert_id, user_id=auth.user.id)
    mark_alert_read(db, alert=alert, user_id=auth.user.id)
    db.refresh(alert)
    return AlertResponse.model_validate(
        serialize_alert_for_user(db, alert=alert, user_id=auth.user.id)
    )


@router.post("/{alert_id}/acknowledge", response_model=AlertResponse)
def acknowledge_alert_endpoint(
    alert_id: UUID,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
) -> AlertResponse:
    alert = get_alert_or_404(db, alert_id=alert_id, user_id=auth.user.id)
    acknowledge_alert(db, alert=alert, user_id=auth.user.id)
    db.refresh(alert)
    return AlertResponse.model_validate(
        serialize_alert_for_user(db, alert=alert, user_id=auth.user.id)
    )


@router.post("/{alert_id}/dismiss", response_model=AlertResponse)
def dismiss_alert_endpoint(
    alert_id: UUID,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
) -> AlertResponse:
    alert = get_alert_or_404(db, alert_id=alert_id, user_id=auth.user.id)
    dismiss_alert(db, alert=alert, user_id=auth.user.id)
    db.refresh(alert)
    return AlertResponse.model_validate(
        serialize_alert_for_user(db, alert=alert, user_id=auth.user.id)
    )
