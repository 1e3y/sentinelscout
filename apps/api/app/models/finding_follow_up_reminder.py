"""Durable finding follow-up reminder jobs (Milestone 34)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base

REMINDER_KIND_DUE = "due"
REMINDER_KINDS = frozenset({REMINDER_KIND_DUE})

REMINDER_JOB_STATUSES = frozenset(
    {"pending", "processing", "delivered", "failed", "dead", "skipped"}
)


class FindingFollowUpReminderJob(Base):
    """One semantic due-reminder intent per Finding follow-up generation."""

    __tablename__ = "finding_follow_up_reminder_jobs"
    __table_args__ = (
        UniqueConstraint(
            "finding_id",
            "follow_up_change_id",
            "reminder_kind",
            name="uq_finding_follow_up_reminder_generation",
        ),
        CheckConstraint(
            "reminder_kind IN ('due')",
            name="ck_finding_follow_up_reminder_kind",
        ),
        CheckConstraint(
            "status IN ('pending', 'processing', 'delivered', 'failed', 'dead', 'skipped')",
            name="ck_finding_follow_up_reminder_status",
        ),
        Index(
            "ix_finding_follow_up_reminder_jobs_due",
            "available_at",
            postgresql_where=text("status IN ('pending', 'failed')"),
        ),
        Index(
            "ix_finding_follow_up_reminder_jobs_lease",
            "lease_expires_at",
            postgresql_where=text("status = 'processing'"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("findings.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    follow_up_change_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("finding_follow_up_changes.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    assigned_to_user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    due_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    reminder_kind: Mapped[str] = mapped_column(
        String(32), nullable=False, default=REMINDER_KIND_DUE
    )
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    available_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    processing_token: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    delivery_snapshot: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
    delivered_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
