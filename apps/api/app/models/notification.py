from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.db import Base

if TYPE_CHECKING:
    from app.models.organization import Organization
    from app.models.user import User

EMAIL_MIN_PRIORITIES = frozenset({"info", "low", "medium"})


class OrganizationNotificationSettings(Base):
    """Per-organization delivery intent. Disabled by default. No digest."""

    __tablename__ = "organization_notification_settings"
    __table_args__ = (
        UniqueConstraint("organization_id", name="uq_org_notification_settings"),
        CheckConstraint(
            "email_min_priority IN ('info', 'low', 'medium')",
            name="ck_org_notification_email_min_priority",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    email_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    email_min_priority: Mapped[str] = mapped_column(String(16), nullable=False, default="medium")
    finding_follow_up_reminders_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    updated_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    organization: Mapped[Organization] = relationship("Organization")
    updated_by: Mapped[User | None] = relationship("User")


class OrganizationEmailRecipient(Base):
    """Explicit current org-member recipients. destination_key = user:<uuid>."""

    __tablename__ = "organization_email_recipients"
    __table_args__ = (
        UniqueConstraint("organization_id", "user_id", name="uq_org_email_recipient"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    organization: Mapped[Organization] = relationship(
        "Organization", foreign_keys=[organization_id]
    )
    user: Mapped[User] = relationship("User", foreign_keys=[user_id])
