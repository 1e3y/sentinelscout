from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.db import Base

if TYPE_CHECKING:
    from app.models.operation import Operation
    from app.models.organization import Organization
    from app.models.report import AssessmentReport
    from app.models.report_generation_job import AssessmentReportGenerationJob
    from app.models.report_share import AssessmentReportShare
    from app.models.target import AuthorizedTarget

REPORT_DELIVERY_JOB_STATUSES = frozenset(
    {"pending", "processing", "succeeded", "skipped", "failed"}
)
REPORT_DELIVERY_OUTBOX_STATUSES = frozenset(
    {"pending", "processing", "delivered", "failed", "dead", "skipped"}
)


class AssessmentReportDeliveryJob(Base):
    """Durable automatic-report delivery intent. Unique per scheduled operation."""

    __tablename__ = "assessment_report_delivery_jobs"
    __table_args__ = (
        UniqueConstraint(
            "operation_id", name="uq_assessment_report_delivery_job_operation"
        ),
        CheckConstraint(
            "status IN ('pending', 'processing', 'succeeded', 'skipped', 'failed')",
            name="ck_assessment_report_delivery_job_status",
        ),
        CheckConstraint(
            "frozen_expires_in IN ('24h', '7d', '30d')",
            name="ck_assessment_report_delivery_job_expires",
        ),
        CheckConstraint(
            "attempt_count >= 0",
            name="ck_assessment_report_delivery_job_attempts",
        ),
        Index(
            "ix_assessment_report_delivery_jobs_status_available",
            "status",
            "available_at",
        ),
        Index(
            "ix_assessment_report_delivery_jobs_due",
            "available_at",
            postgresql_where=text("status = 'pending'"),
        ),
        Index(
            "ix_assessment_report_delivery_jobs_lease",
            "lease_expires_at",
            postgresql_where=text("status = 'processing'"),
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
    generation_job_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assessment_report_generation_jobs.id", ondelete="CASCADE"),
        nullable=False,
    )
    report_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assessment_reports.id", ondelete="RESTRICT"),
        nullable=False,
    )
    target_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("authorized_targets.id", ondelete="CASCADE"),
        nullable=False,
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
    frozen_recipients: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, default=list)
    frozen_expires_in: Mapped[str] = mapped_column(String(8), nullable=False)
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
    generation_job: Mapped[AssessmentReportGenerationJob] = relationship(
        "AssessmentReportGenerationJob"
    )
    report: Mapped[AssessmentReport] = relationship("AssessmentReport")
    target: Mapped[AuthorizedTarget] = relationship("AuthorizedTarget")


class AssessmentReportDeliveryOutbox(Base):
    """Per-recipient email outbox. Encrypted share secret is transient until terminal."""

    __tablename__ = "assessment_report_delivery_outbox"
    __table_args__ = (
        UniqueConstraint(
            "delivery_job_id",
            "destination_key",
            name="uq_assessment_report_delivery_outbox_destination",
        ),
        CheckConstraint(
            "status IN ('pending', 'processing', 'delivered', 'failed', 'dead', 'skipped')",
            name="ck_assessment_report_delivery_outbox_status",
        ),
        CheckConstraint(
            "attempt_count >= 0",
            name="ck_assessment_report_delivery_outbox_attempts",
        ),
        Index(
            "ix_assessment_report_delivery_outbox_status_available",
            "status",
            "available_at",
        ),
        Index(
            "ix_assessment_report_delivery_outbox_due",
            "available_at",
            postgresql_where=text("status IN ('pending', 'failed')"),
        ),
        Index(
            "ix_assessment_report_delivery_outbox_lease",
            "lease_expires_at",
            postgresql_where=text("status = 'processing'"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    delivery_job_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assessment_report_delivery_jobs.id", ondelete="CASCADE"),
        nullable=False,
    )
    report_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assessment_reports.id", ondelete="RESTRICT"),
        nullable=False,
    )
    share_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assessment_report_shares.id", ondelete="RESTRICT"),
        nullable=True,
        unique=True,
    )
    destination_key: Mapped[str] = mapped_column(String(356), nullable=False)
    recipient_email_normalized: Mapped[str] = mapped_column(String(320), nullable=False)
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
    encrypted_secret: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    encrypted_secret_nonce: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    encryption_key_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    frozen_frontend_origin: Mapped[str] = mapped_column(String(512), nullable=False)
    frozen_from_email: Mapped[str] = mapped_column(String(320), nullable=False)
    frozen_subject: Mapped[str] = mapped_column(String(256), nullable=False)
    frozen_target_domain: Mapped[str] = mapped_column(String(253), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    organization: Mapped[Organization] = relationship("Organization")
    delivery_job: Mapped[AssessmentReportDeliveryJob] = relationship(
        "AssessmentReportDeliveryJob"
    )
    report: Mapped[AssessmentReport] = relationship("AssessmentReport")
    share: Mapped[AssessmentReportShare | None] = relationship(
        "AssessmentReportShare", foreign_keys=[share_id]
    )
