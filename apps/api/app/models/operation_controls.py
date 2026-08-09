from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.db import Base

if TYPE_CHECKING:
    from app.models.operation import Operation
    from app.models.user import User

TESTING_PROFILE_SAFE_PRODUCTION = "safe_production"


class OperationControlSnapshot(Base):
    """Immutable authorized-boundary snapshot captured at operation creation."""

    __tablename__ = "operation_control_snapshots"

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
    target_domain: Mapped[str] = mapped_column(String(253), nullable=False)
    authorization_status: Mapped[str] = mapped_column(String(32), nullable=False)
    target_authorization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    scope_root: Mapped[str] = mapped_column(String(253), nullable=False)
    include_subdomains: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    exclusions: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, default=list)
    operation_source: Mapped[str] = mapped_column(String(32), nullable=False)
    testing_profile: Mapped[str] = mapped_column(
        String(64), nullable=False, default=TESTING_PROFILE_SAFE_PRODUCTION
    )
    created_by_user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    operation: Mapped[Operation] = relationship("Operation", back_populates="control_snapshot")
    created_by: Mapped[User] = relationship("User")
