from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.db import Base

if TYPE_CHECKING:
    from app.models.report import AssessmentReport
    from app.models.user import User

SHARE_CREATION_ORIGIN_MANUAL = "manual"
SHARE_CREATION_ORIGIN_SCHEDULED_AUTOMATIC = "scheduled_automatic"
SHARE_CREATION_ORIGINS = frozenset(
    {SHARE_CREATION_ORIGIN_MANUAL, SHARE_CREATION_ORIGIN_SCHEDULED_AUTOMATIC}
)


class AssessmentReportShare(Base):
    """Revocable, expiring external credential for one immutable report.

    The plaintext secret is never stored. ``secret_hash`` is SHA-256 hex.
    """

    __tablename__ = "assessment_report_shares"
    __table_args__ = (
        CheckConstraint("length(secret_hash) = 64", name="ck_report_share_secret_hash_len"),
        CheckConstraint("expires_at > created_at", name="ck_report_share_expires_after_create"),
        CheckConstraint(
            "creation_origin IN ('manual', 'scheduled_automatic')",
            name="ck_assessment_report_share_creation_origin",
        ),
        CheckConstraint(
            "(creation_origin = 'manual' AND created_by_user_id IS NOT NULL) OR "
            "(creation_origin = 'scheduled_automatic' AND created_by_user_id IS NULL)",
            name="ck_assessment_report_share_origin_actor",
        ),
        UniqueConstraint(
            "delivery_outbox_id", name="uq_assessment_report_share_delivery_outbox"
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    report_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assessment_reports.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=True,
    )
    creation_origin: Mapped[str] = mapped_column(
        String(32), nullable=False, default=SHARE_CREATION_ORIGIN_MANUAL
    )
    delivery_outbox_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
    )
    secret_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    report: Mapped[AssessmentReport] = relationship("AssessmentReport")
    created_by: Mapped[User | None] = relationship("User")


class AnonymousRateLimitCounter(Base):
    """Fixed-window counters for unauthenticated share endpoints.

    Buckets are application-chosen short labels (``p00``…``p63`` or an
    authorized share id), never attacker-supplied UUIDs or raw IP addresses.
    """

    __tablename__ = "anonymous_rate_limit_counters"
    __table_args__ = (
        UniqueConstraint(
            "action",
            "bucket",
            "window_start",
            name="uq_anonymous_rate_limit_window",
        ),
        CheckConstraint("count >= 0", name="ck_anonymous_rate_limit_count_nonneg"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    bucket: Mapped[str] = mapped_column(String(64), nullable=False)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )
