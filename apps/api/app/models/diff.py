from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.db import Base

if TYPE_CHECKING:
    from app.models.operation import Operation


class OperationDiffSummary(Base):
    """Immutable comparison snapshot + diff result frozen at terminal operation status."""

    __tablename__ = "operation_diff_summaries"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    operation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("operations.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
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
    baseline_operation_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("operations.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    schema_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    comparability: Mapped[str] = mapped_column(String(64), nullable=False)
    comparison_snapshot: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    changes: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, default=list)
    counts: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    headline: Mapped[str] = mapped_column(Text, nullable=False)
    security_signal_baseline_unavailable: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    security_signal_comparison_suppressed: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    security_signal_suppression_reason: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )
    operation_status_at_freeze: Mapped[str] = mapped_column(String(32), nullable=False)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="frozen")
    frozen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    operation: Mapped[Operation] = relationship(
        "Operation",
        back_populates="diff_summary",
        foreign_keys=[operation_id],
    )
