from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Integer, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.db import Base

if TYPE_CHECKING:
    from app.models.finding import Finding
    from app.models.organization import Organization
    from app.models.user import User


class FindingRemediationRevision(Base):
    """Append-only human-authored remediation documentation for one Finding."""

    __tablename__ = "finding_remediation_revisions"
    __table_args__ = (
        UniqueConstraint(
            "finding_id",
            "revision_number",
            name="uq_finding_remediation_revision_number",
        ),
        CheckConstraint(
            "revision_number >= 1",
            name="ck_finding_remediation_revision_number",
        ),
        CheckConstraint(
            "char_length(summary) BETWEEN 1 AND 4000",
            name="ck_finding_remediation_summary_length",
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
    revision_number: Mapped[int] = mapped_column(Integer, nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    created_by_user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    organization: Mapped[Organization] = relationship("Organization")
    finding: Mapped[Finding] = relationship("Finding")
    created_by_user: Mapped[User] = relationship("User")
