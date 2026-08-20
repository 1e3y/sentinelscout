from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import (
    AuthContext,
    get_auth_context,
    get_db,
    require_org_admin,
    require_org_membership,
    verified_org_admin_role,
)
from app.core.config import get_settings
from app.schemas.notification import (
    NotificationSettingsResponse,
    NotificationSettingsUpdateRequest,
)
from app.services.notification_settings import (
    serialize_notification_settings,
    update_notification_settings,
)
from app.services.rate_limit import ACTION_NOTIFICATION_SETTINGS, enforce_rate_limit

router = APIRouter(prefix="/v1/organizations", tags=["notifications"])


@router.get(
    "/{org_id}/notification-settings",
    response_model=NotificationSettingsResponse,
)
def get_notification_settings_endpoint(
    org_id: UUID,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
) -> NotificationSettingsResponse:
    organization, _membership = require_org_membership(org_id, auth, db)
    return NotificationSettingsResponse.model_validate(
        serialize_notification_settings(
            db,
            organization_id=organization.id,
            can_manage=verified_org_admin_role(auth, organization),
        )
    )


@router.put(
    "/{org_id}/notification-settings",
    response_model=NotificationSettingsResponse,
)
def put_notification_settings_endpoint(
    org_id: UUID,
    body: NotificationSettingsUpdateRequest,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
) -> NotificationSettingsResponse:
    organization, _membership = require_org_admin(org_id, auth, db)
    enforce_rate_limit(
        db,
        organization_id=organization.id,
        user_id=auth.user.id,
        action=ACTION_NOTIFICATION_SETTINGS,
        settings=get_settings(),
    )
    recipient_ids: list[UUID] = []
    for raw in body.recipient_user_ids:
        try:
            recipient_ids.append(UUID(str(raw)))
        except (TypeError, ValueError) as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="recipient_user_ids must be user UUIDs",
            ) from exc
    update_notification_settings(
        db,
        organization_id=organization.id,
        actor_user_id=auth.user.id,
        email_enabled=body.email_enabled,
        email_min_priority=body.email_min_priority,
        recipient_user_ids=recipient_ids,
    )
    return NotificationSettingsResponse.model_validate(
        serialize_notification_settings(
            db,
            organization_id=organization.id,
            can_manage=True,
        )
    )
