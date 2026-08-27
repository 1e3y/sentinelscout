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
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.db import Base

if TYPE_CHECKING:
    from app.models.organization import Organization
    from app.models.target import AuthorizedTarget
    from app.models.user import User

MONITORING_FREQUENCIES = frozenset({"daily", "weekly"})
AUTO_DELIVER_EXPIRES_IN = frozenset({"24h", "7d", "30d"})
MAX_REPORT_DELIVERY_RECIPIENTS = 10


class MonitoringConfiguration(Base):
    __tablename__ = "monitoring_configurations"
    __table_args__ = (
        UniqueConstraint("target_id", name="uq_monitoring_target_id"),
        CheckConstraint(
            "frequency IN ('daily', 'weekly')",
            name="ck_monitoring_frequency",
        ),
        CheckConstraint(
            "auto_deliver_expires_in IN ('24h', '7d', '30d')",
            name="ck_monitoring_auto_deliver_expires_in",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    target_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("authorized_targets.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    auto_generate_reports: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    auto_deliver_reports: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    auto_deliver_expires_in: Mapped[str] = mapped_column(String(8), nullable=False, default="7d")
    frequency: Mapped[str] = mapped_column(String(32), nullable=False, default="weekly")
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    disabled_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
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
    target: Mapped[AuthorizedTarget] = relationship("AuthorizedTarget")
    updated_by: Mapped[User | None] = relationship("User")
    delivery_recipients: Mapped[list[MonitoringReportDeliveryRecipient]] = relationship(
        "MonitoringReportDeliveryRecipient",
        back_populates="configuration",
        cascade="all, delete-orphan",
    )


class MonitoringReportDeliveryRecipient(Base):
    """External mailbox for automatic report delivery. Not an org member list."""

    __tablename__ = "monitoring_report_delivery_recipients"
    __table_args__ = (
        UniqueConstraint(
            "monitoring_configuration_id",
            "email_normalized",
            name="uq_monitoring_report_delivery_recipient",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    monitoring_configuration_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("monitoring_configurations.id", ondelete="CASCADE"),
        nullable=False,
    )
    target_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("authorized_targets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    email_normalized: Mapped[str] = mapped_column(String(320), nullable=False)
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    configuration: Mapped[MonitoringConfiguration] = relationship(
        "MonitoringConfiguration", back_populates="delivery_recipients"
    )
