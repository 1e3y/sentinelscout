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
    text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.db import Base

if TYPE_CHECKING:
    from app.models.asset import Asset
    from app.models.candidate import SecurityCandidate
    from app.models.finding import Finding
    from app.models.organization import Organization
    from app.models.validation import ValidationAttempt

RETEST_ATTEMPT_STATUSES = frozenset(
    {
        "pending",
        "running",
        "passed",
        "failed",
        "inconclusive",
        "error",
    }
)

ACTIVE_RETEST_STATUSES = frozenset({"pending", "running"})


class RetestAttempt(Base):
    __tablename__ = "retest_attempts"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending', 'running', 'passed', 'failed', "
            "'inconclusive', 'error')",
            name="ck_retest_attempt_status",
        ),
        Index(
            "uq_retest_active_per_finding",
            "finding_id",
            unique=True,
            postgresql_where=text("status IN ('pending', 'running')"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
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
    candidate_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("security_candidates.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    original_validation_attempt_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("validation_attempts.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    method: Mapped[str] = mapped_column(String(64), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    organization: Mapped[Organization] = relationship("Organization")
    finding: Mapped[Finding] = relationship("Finding")
    candidate: Mapped[SecurityCandidate] = relationship("SecurityCandidate")
    asset: Mapped[Asset] = relationship("Asset")
    original_validation_attempt: Mapped[ValidationAttempt] = relationship("ValidationAttempt")
