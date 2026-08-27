from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.db import Base

if TYPE_CHECKING:
    from app.models.operation import Operation
    from app.models.organization import Organization
    from app.models.report import AssessmentReport

REPORT_GENERATION_JOB_STATUSES = frozenset(
    {"pending", "processing", "succeeded", "skipped", "failed"}
)


class AssessmentReportGenerationJob(Base):
    """Durable automatic-report work item. Unique per operation; no generic workflow table."""

    __tablename__ = "assessment_report_generation_jobs"
    __table_args__ = (
        UniqueConstraint(
            "operation_id", name="uq_assessment_report_generation_job_operation"
        ),
        CheckConstraint(
            "status IN ('pending', 'processing', 'succeeded', 'skipped', 'failed')",
            name="ck_assessment_report_generation_job_status",
        ),
        CheckConstraint(
            "attempt_count >= 0",
            name="ck_assessment_report_generation_job_attempts",
        ),
        Index(
            "ix_assessment_report_generation_jobs_due",
            "available_at",
            postgresql_where=text("status = 'pending'"),
        ),
        Index(
            "ix_assessment_report_generation_jobs_lease",
            "lease_expires_at",
            postgresql_where=text("status = 'processing'"),
        ),
        Index(
            "ix_assessment_report_generation_jobs_status_available",
            "status",
            "available_at",
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
        unique=True,
    )
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    available_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    processing_token: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    report_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assessment_reports.id", ondelete="RESTRICT"),
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
    operation: Mapped[Operation] = relationship("Operation")
    report: Mapped[AssessmentReport | None] = relationship("AssessmentReport")
