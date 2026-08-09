from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.db import Base

if TYPE_CHECKING:
    from app.models.organization import Organization
    from app.models.user import User


class AuthorizedTarget(Base):
    __tablename__ = "authorized_targets"
    __table_args__ = (
        UniqueConstraint("organization_id", "domain", name="uq_org_target_domain"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    domain: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False, default="unverified")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    organization: Mapped[Organization] = relationship("Organization")
    created_by: Mapped[User | None] = relationship("User")
    authorization: Mapped[TargetAuthorization | None] = relationship(
        "TargetAuthorization",
        back_populates="target",
        uselist=False,
        cascade="all, delete-orphan",
    )
    scope: Mapped[TargetScope | None] = relationship(
        "TargetScope",
        back_populates="target",
        uselist=False,
        cascade="all, delete-orphan",
    )


class TargetAuthorization(Base):
    __tablename__ = "target_authorizations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    target_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("authorized_targets.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    method: Mapped[str] = mapped_column(String, nullable=False, default="dns_txt")
    token: Mapped[str] = mapped_column(Text, nullable=False)
    txt_name: Mapped[str] = mapped_column(String, nullable=False)
    txt_value: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    target: Mapped[AuthorizedTarget] = relationship("AuthorizedTarget", back_populates="authorization")


class TargetScope(Base):
    __tablename__ = "target_scopes"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    target_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("authorized_targets.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    root_domain: Mapped[str] = mapped_column(String, nullable=False)
    include_subdomains: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    exclusions: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    target: Mapped[AuthorizedTarget] = relationship("AuthorizedTarget", back_populates="scope")
