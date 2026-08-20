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
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.db import Base

if TYPE_CHECKING:
    from app.models.diff import OperationDiffSummary
    from app.models.operation import Operation
    from app.models.organization import Organization
    from app.models.target import AuthorizedTarget
    from app.models.user import User

ALERT_CATEGORIES = frozenset(
    {"security_regression", "coverage_degradation", "informational"}
)
ALERT_PRIORITIES = frozenset({"medium", "low", "info"})
ALERT_TYPES = frozenset(
    {
        "hsts_lost",
        "resolved_condition_reappeared",
        "header_evidence_lost",
        "http_observation_coverage_degraded",
        "header_evidence_coverage_degraded",
        "http_observation_lost_explicit",
        "scope_not_comparable",
        "capability_comparison_suppressed",
    }
)
EPISODE_STATUSES = frozenset({"open", "closed"})
OUTBOX_CHANNELS = frozenset({"in_app"})
OUTBOX_STATUSES = frozenset({"pending", "delivered", "failed", "skipped"})


class AlertEpisode(Base):
    """Condition identity. last_seen_* is operational; not user notification state."""

    __tablename__ = "alert_episodes"
    __table_args__ = (
        CheckConstraint(
            "category IN ('security_regression', 'coverage_degradation', 'informational')",
            name="ck_alert_episode_category",
        ),
        CheckConstraint(
            "priority IN ('medium', 'low', 'info')",
            name="ck_alert_episode_priority",
        ),
        CheckConstraint(
            "status IN ('open', 'closed')",
            name="ck_alert_episode_status",
        ),
        Index(
            "uq_alert_episodes_open_semantic",
            "organization_id",
            "target_id",
            "semantic_key",
            unique=True,
            postgresql_where=text("status = 'open'"),
        ),
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
    semantic_key: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    alert_type: Mapped[str] = mapped_column(String(64), nullable=False)
    category: Mapped[str] = mapped_column(String(32), nullable=False)
    priority: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="open")
    opened_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    opening_operation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("operations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    opening_diff_summary_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("operation_diff_summaries.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    last_seen_operation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("operations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    last_seen_diff_summary_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("operation_diff_summaries.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    reopened_from_episode_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("alert_episodes.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    opening_evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    organization: Mapped[Organization] = relationship("Organization")
    target: Mapped[AuthorizedTarget] = relationship("AuthorizedTarget")
    alerts: Mapped[list[Alert]] = relationship("Alert", back_populates="episode")


class Alert(Base):
    """Immutable triggering notification. Ack is org-level; read/dismiss are per-user."""

    __tablename__ = "alerts"
    __table_args__ = (
        UniqueConstraint("episode_id", "operation_id", name="uq_alert_episode_operation"),
        CheckConstraint(
            "category IN ('security_regression', 'coverage_degradation', 'informational')",
            name="ck_alert_category",
        ),
        CheckConstraint(
            "priority IN ('medium', 'low', 'info')",
            name="ck_alert_priority",
        ),
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
    episode_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("alert_episodes.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    operation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("operations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    diff_summary_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("operation_diff_summaries.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    alert_type: Mapped[str] = mapped_column(String(64), nullable=False)
    category: Mapped[str] = mapped_column(String(32), nullable=False)
    priority: Mapped[str] = mapped_column(String(16), nullable=False)
    semantic_key: Mapped[str] = mapped_column(String(512), nullable=False)
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )
    acknowledged_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    acknowledged_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    organization: Mapped[Organization] = relationship("Organization")
    episode: Mapped[AlertEpisode] = relationship("AlertEpisode", back_populates="alerts")
    operation: Mapped[Operation] = relationship("Operation")
    diff_summary: Mapped[OperationDiffSummary] = relationship("OperationDiffSummary")
    acknowledged_by: Mapped[User | None] = relationship("User")


class AlertUserState(Base):
    """Per-member read/dismiss. One member's dismiss does not hide the alert for others."""

    __tablename__ = "alert_user_states"
    __table_args__ = (
        UniqueConstraint("alert_id", "user_id", name="uq_alert_user_state"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    alert_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("alerts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    read_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    dismissed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    alert: Mapped[Alert] = relationship("Alert")
    user: Mapped[User] = relationship("User")


class NotificationOutbox(Base):
    """Transactional outbox. M19 writes in_app/org as delivered; no external providers."""

    __tablename__ = "notification_outbox"
    __table_args__ = (
        UniqueConstraint(
            "alert_id",
            "channel",
            "destination_key",
            name="uq_notification_outbox_destination",
        ),
        CheckConstraint(
            "channel IN ('in_app')",
            name="ck_notification_outbox_channel",
        ),
        CheckConstraint(
            "status IN ('pending', 'delivered', 'failed', 'skipped')",
            name="ck_notification_outbox_status",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    alert_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("alerts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    channel: Mapped[str] = mapped_column(String(32), nullable=False)
    destination_key: Mapped[str] = mapped_column(String(256), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    available_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    alert: Mapped[Alert] = relationship("Alert")


class AlertGenerationReceipt(Base):
    """Idempotency receipt for freeze, including zero-alert generations."""

    __tablename__ = "alert_generation_receipts"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    diff_summary_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("operation_diff_summaries.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    operation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("operations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="frozen")
    alert_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
