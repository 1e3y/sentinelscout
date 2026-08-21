from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.db import Base

if TYPE_CHECKING:
    from app.models.operation import Operation
    from app.models.target import AuthorizedTarget
    from app.models.user import User

REPORT_SCHEMA_VERSION = 1

ASSESSMENT_COMPLETENESS_VALUES = frozenset({"complete", "incomplete"})
HEADLINE_STATUSES = frozenset(
    {
        "assessment_incomplete",
        "action_required",
        "attention_recommended",
        "no_open_supported_findings",
    }
)


class AssessmentReport(Base):
    """Immutable customer-facing assessment artifact. No update or delete APIs.

    operation_id and target_id use RESTRICT so deleting a source operation or
    target cannot silently destroy a delivered report.
    """

    __tablename__ = "assessment_reports"
    __table_args__ = (
        UniqueConstraint(
            "operation_id", "report_version", name="uq_assessment_report_operation_version"
        ),
        CheckConstraint(
            "assessment_completeness IN ('complete', 'incomplete')",
            name="ck_assessment_report_completeness",
        ),
        CheckConstraint(
            "headline_status IN ('assessment_incomplete', 'action_required', "
            "'attention_recommended', 'no_open_supported_findings')",
            name="ck_assessment_report_headline_status",
        ),
        CheckConstraint("report_version >= 1", name="ck_assessment_report_version_positive"),
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
    operation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("operations.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    created_by_user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    # Frozen copy of the control-snapshot domain so list views need no live join.
    target_domain: Mapped[str] = mapped_column(String(253), nullable=False)
    report_version: Mapped[int] = mapped_column(Integer, nullable=False)
    schema_version: Mapped[int] = mapped_column(
        Integer, nullable=False, default=REPORT_SCHEMA_VERSION
    )
    snapshot_digest: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    snapshot_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    operation_status_at_generation: Mapped[str] = mapped_column(String(32), nullable=False)
    assessment_completeness: Mapped[str] = mapped_column(String(16), nullable=False)
    headline_status: Mapped[str] = mapped_column(String(32), nullable=False)
    findings_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    findings_open: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    findings_resolved: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    regression_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    coverage_limitation_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    severity_counts: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    generated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    operation: Mapped[Operation] = relationship("Operation")
    target: Mapped[AuthorizedTarget] = relationship("AuthorizedTarget")
    created_by: Mapped[User] = relationship("User")
