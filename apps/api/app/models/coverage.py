from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.db import Base

if TYPE_CHECKING:
    from app.models.operation import Operation


class OperationCoverageSummary(Base):
    """Immutable discovery-layer coverage snapshot frozen at terminal operation status."""

    __tablename__ = "operation_coverage_summaries"

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
    schema_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    capability_manifest_version: Mapped[int] = mapped_column(Integer, nullable=False)
    capability_snapshot: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    surface: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    http_evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    scope_boundaries: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    freshness: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    headline: Mapped[str] = mapped_column(Text, nullable=False)
    operation_status_at_freeze: Mapped[str] = mapped_column(String(32), nullable=False)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="frozen")
    frozen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    operation: Mapped[Operation] = relationship("Operation", back_populates="coverage_summary")
