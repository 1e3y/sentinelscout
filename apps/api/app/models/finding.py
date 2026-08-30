from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.db import Base

if TYPE_CHECKING:
    from app.models.asset import Asset
    from app.models.candidate import SecurityCandidate
    from app.models.operation import Operation
    from app.models.organization import Organization

FINDING_STATUSES = frozenset({"open", "in_progress", "ready_for_retest", "resolved"})
FINDING_SEVERITIES = frozenset({"informational", "low", "medium", "high", "critical"})

# Milestone 8 user-allowed transitions only.
ALLOWED_REMEDIATION_TRANSITIONS: dict[str, frozenset[str]] = {
    "open": frozenset({"in_progress"}),
    "in_progress": frozenset({"ready_for_retest"}),
    # ready_for_retest → resolved is Milestone 9 (retest-gated).
}


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("candidate_id", name="uq_finding_candidate_id"),
        CheckConstraint(
            "status IN ('open', 'in_progress', 'ready_for_retest', 'resolved')",
            name="ck_finding_status",
        ),
        CheckConstraint(
            "severity IN ('informational', 'low', 'medium', 'high', 'critical')",
            name="ck_finding_severity",
        ),
        # Keyset order for the organization findings inbox (M30).
        Index(
            "ix_findings_org_created_at_id",
            "organization_id",
            "created_at",
            "id",
            postgresql_ops={"created_at": "DESC", "id": "DESC"},
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    operation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("operations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    candidate_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("security_candidates.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="open")
    business_impact: Mapped[str] = mapped_column(Text, nullable=False)
    remediation_guidance: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    assigned_to_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    follow_up_due_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
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
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    organization: Mapped[Organization] = relationship("Organization")
    operation: Mapped[Operation] = relationship("Operation")
    candidate: Mapped[SecurityCandidate] = relationship("SecurityCandidate")
    asset: Mapped[Asset] = relationship("Asset")
