"""Organization email delivery intent. Independent of environment provider readiness."""

from __future__ import annotations

from typing import Any
from uuid import UUID, uuid4

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.notification import (
    EMAIL_MIN_PRIORITIES,
    OrganizationEmailRecipient,
    OrganizationNotificationSettings,
)
from app.models.organization import OrganizationMembership
from app.models.user import User
from app.services.audit import record_audit

PRIORITY_RANK = {"info": 0, "low": 1, "medium": 2}


def get_or_default_settings(
    db: Session, *, organization_id: UUID
) -> OrganizationNotificationSettings | None:
    return db.scalar(
        select(OrganizationNotificationSettings).where(
            OrganizationNotificationSettings.organization_id == organization_id
        )
    )


def list_email_recipient_user_ids(db: Session, *, organization_id: UUID) -> list[UUID]:
    return list(
        db.scalars(
            select(OrganizationEmailRecipient.user_id).where(
                OrganizationEmailRecipient.organization_id == organization_id
            )
        ).all()
    )


def email_should_enqueue(alert_priority: str, min_priority: str) -> bool:
    alert_rank = PRIORITY_RANK.get(alert_priority)
    min_rank = PRIORITY_RANK.get(min_priority)
    if alert_rank is None or min_rank is None:
        return False
    return alert_rank >= min_rank


def serialize_notification_settings(
    db: Session,
    *,
    organization_id: UUID,
    can_manage: bool,
) -> dict[str, Any]:
    settings = get_or_default_settings(db, organization_id=organization_id)
    recipient_ids = set(list_email_recipient_user_ids(db, organization_id=organization_id))
    memberships = list(
        db.execute(
            select(OrganizationMembership, User)
            .join(User, User.id == OrganizationMembership.user_id)
            .where(OrganizationMembership.organization_id == organization_id)
            .order_by(User.email.asc())
        ).all()
    )
    members = []
    recipients = []
    for _membership, user in memberships:
        members.append(
            {
                "user_id": str(user.id),
                "name": user.name,
                "email": user.email,
                "email_verified": bool(user.email_verified),
            }
        )
        if user.id in recipient_ids:
            recipients.append(
                {
                    "user_id": str(user.id),
                    "name": user.name,
                    "email": user.email,
                    "email_verified": bool(user.email_verified),
                }
            )
    return {
        "organization_id": str(organization_id),
        "email_enabled": bool(settings.email_enabled) if settings is not None else False,
        "email_min_priority": (
            settings.email_min_priority if settings is not None else "medium"
        ),
        "recipients": recipients,
        "members": members,
        "can_manage": can_manage,
    }


def update_notification_settings(
    db: Session,
    *,
    organization_id: UUID,
    actor_user_id: UUID,
    email_enabled: bool,
    email_min_priority: str,
    recipient_user_ids: list[UUID],
) -> OrganizationNotificationSettings:
    if email_min_priority not in EMAIL_MIN_PRIORITIES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="email_min_priority must be info, low, or medium",
        )
    unique_ids = list(dict.fromkeys(recipient_user_ids))
    memberships = {
        row.user_id: row
        for row in db.scalars(
            select(OrganizationMembership).where(
                OrganizationMembership.organization_id == organization_id
            )
        ).all()
    }
    users = {
        row.id: row
        for row in db.scalars(select(User).where(User.id.in_(unique_ids))).all()
    } if unique_ids else {}
    for user_id in unique_ids:
        if user_id not in memberships:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Recipients must be current organization members",
            )
        user = users.get(user_id)
        if user is None or not user.email_verified or not user.email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Recipients must have a verified primary email",
            )

    settings = get_or_default_settings(db, organization_id=organization_id)
    if settings is None:
        settings = OrganizationNotificationSettings(
            id=uuid4(),
            organization_id=organization_id,
            email_enabled=email_enabled,
            email_min_priority=email_min_priority,
            updated_by_user_id=actor_user_id,
        )
        db.add(settings)
    else:
        settings.email_enabled = email_enabled
        settings.email_min_priority = email_min_priority
        settings.updated_by_user_id = actor_user_id

    existing = list(
        db.scalars(
            select(OrganizationEmailRecipient).where(
                OrganizationEmailRecipient.organization_id == organization_id
            )
        ).all()
    )
    desired = set(unique_ids)
    for row in existing:
        if row.user_id not in desired:
            db.delete(row)
    existing_ids = {row.user_id for row in existing}
    for user_id in unique_ids:
        if user_id not in existing_ids:
            db.add(
                OrganizationEmailRecipient(
                    organization_id=organization_id,
                    user_id=user_id,
                    created_by_user_id=actor_user_id,
                )
            )
    record_audit(
        db,
        organization_id=organization_id,
        actor_type="user",
        actor_user_id=actor_user_id,
        action="notification.settings.updated",
        resource_type="organization",
        resource_id=organization_id,
        summary="Notification email settings updated.",
        metadata={
            "email_enabled": email_enabled,
            "email_min_priority": email_min_priority,
            "recipient_count": len(unique_ids),
        },
    )
    db.commit()
    db.refresh(settings)
    return settings
