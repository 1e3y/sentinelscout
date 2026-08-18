from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.db import Base

if TYPE_CHECKING:
    from app.models.coverage import OperationCoverageSummary
    from app.models.diff import OperationDiffSummary
    from app.models.operation_controls import OperationControlSnapshot
    from app.models.organization import Organization
    from app.models.target import AuthorizedTarget
    from app.models.user import User


class Operation(Base):
    __tablename__ = "operations"
    __table_args__ = (
        CheckConstraint(
            "source IN ('manual', 'scheduled')",
            name="ck_operation_source",
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
        ForeignKey("authorized_targets.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    created_by_user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    status: Mapped[str] = mapped_column(String, nullable=False, default="queued")
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="manual")
    testing_profile: Mapped[str] = mapped_column(
        String(64), nullable=False, default="safe_production"
    )
    stop_requested: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    failed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    stopped_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_code: Mapped[str | None] = mapped_column(String, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    organization: Mapped[Organization] = relationship("Organization")
    target: Mapped[AuthorizedTarget] = relationship("AuthorizedTarget")
    created_by: Mapped[User] = relationship("User")
    events: Mapped[list[OperationEvent]] = relationship(
        "OperationEvent",
        back_populates="operation",
        cascade="all, delete-orphan",
        order_by="OperationEvent.sequence",
    )
    control_snapshot: Mapped[OperationControlSnapshot | None] = relationship(
        "OperationControlSnapshot",
        back_populates="operation",
        uselist=False,
        cascade="all, delete-orphan",
    )
    coverage_summary: Mapped[OperationCoverageSummary | None] = relationship(
        "OperationCoverageSummary",
        back_populates="operation",
        uselist=False,
        cascade="all, delete-orphan",
    )
    diff_summary: Mapped[OperationDiffSummary | None] = relationship(
        "OperationDiffSummary",
        back_populates="operation",
        uselist=False,
        cascade="all, delete-orphan",
        foreign_keys="OperationDiffSummary.operation_id",
    )


class OperationEvent(Base):
    __tablename__ = "operation_events"
    __table_args__ = (
        UniqueConstraint("operation_id", "sequence", name="uq_operation_event_sequence"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    operation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("operations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    event_type: Mapped[str] = mapped_column(String, nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    event_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata",
        JSONB,
        nullable=False,
        default=dict,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    operation: Mapped[Operation] = relationship("Operation", back_populates="events")
