"""alerts, episodes, per-user state, and notification outbox

Revision ID: 20260819_0015
Revises: 20260817_0014
Create Date: 2026-08-19 22:30:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260819_0015"
down_revision: Union[str, Sequence[str], None] = "20260817_0014"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "alert_episodes",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("semantic_key", sa.String(length=512), nullable=False),
        sa.Column("alert_type", sa.String(length=64), nullable=False),
        sa.Column("category", sa.String(length=32), nullable=False),
        sa.Column("priority", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column(
            "opened_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "last_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("opening_operation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("opening_diff_summary_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("last_seen_operation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("last_seen_diff_summary_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("reopened_from_episode_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("opening_evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["target_id"], ["authorized_targets.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(["opening_operation_id"], ["operations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["opening_diff_summary_id"],
            ["operation_diff_summaries.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["last_seen_operation_id"], ["operations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["last_seen_diff_summary_id"],
            ["operation_diff_summaries.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["reopened_from_episode_id"], ["alert_episodes.id"], ondelete="SET NULL"
        ),
        sa.CheckConstraint(
            "category IN ('security_regression', 'coverage_degradation', 'informational')",
            name="ck_alert_episode_category",
        ),
        sa.CheckConstraint(
            "priority IN ('medium', 'low', 'info')",
            name="ck_alert_episode_priority",
        ),
        sa.CheckConstraint(
            "status IN ('open', 'closed')",
            name="ck_alert_episode_status",
        ),
    )
    op.create_index(
        "ix_alert_episodes_organization_id", "alert_episodes", ["organization_id"]
    )
    op.create_index("ix_alert_episodes_target_id", "alert_episodes", ["target_id"])
    op.create_index("ix_alert_episodes_semantic_key", "alert_episodes", ["semantic_key"])
    op.create_index(
        "uq_alert_episodes_open_semantic",
        "alert_episodes",
        ["organization_id", "target_id", "semantic_key"],
        unique=True,
        postgresql_where=sa.text("status = 'open'"),
    )

    op.create_table(
        "alerts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("episode_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("operation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("diff_summary_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("alert_type", sa.String(length=64), nullable=False),
        sa.Column("category", sa.String(length=32), nullable=False),
        sa.Column("priority", sa.String(length=16), nullable=False),
        sa.Column("semantic_key", sa.String(length=512), nullable=False),
        sa.Column("title", sa.String(length=256), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("acknowledged_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["target_id"], ["authorized_targets.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(["episode_id"], ["alert_episodes.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["operation_id"], ["operations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["diff_summary_id"], ["operation_diff_summaries.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["acknowledged_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.UniqueConstraint("episode_id", "operation_id", name="uq_alert_episode_operation"),
        sa.CheckConstraint(
            "category IN ('security_regression', 'coverage_degradation', 'informational')",
            name="ck_alert_category",
        ),
        sa.CheckConstraint(
            "priority IN ('medium', 'low', 'info')",
            name="ck_alert_priority",
        ),
    )
    op.create_index("ix_alerts_organization_id", "alerts", ["organization_id"])
    op.create_index("ix_alerts_target_id", "alerts", ["target_id"])
    op.create_index("ix_alerts_episode_id", "alerts", ["episode_id"])
    op.create_index("ix_alerts_operation_id", "alerts", ["operation_id"])
    op.create_index("ix_alerts_diff_summary_id", "alerts", ["diff_summary_id"])
    op.create_index("ix_alerts_created_at", "alerts", ["created_at"])

    op.create_table(
        "alert_user_states",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("alert_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("read_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("dismissed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["alert_id"], ["alerts.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("alert_id", "user_id", name="uq_alert_user_state"),
    )
    op.create_index("ix_alert_user_states_alert_id", "alert_user_states", ["alert_id"])
    op.create_index(
        "ix_alert_user_states_organization_id", "alert_user_states", ["organization_id"]
    )
    op.create_index("ix_alert_user_states_user_id", "alert_user_states", ["user_id"])

    op.create_table(
        "notification_outbox",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("alert_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("channel", sa.String(length=32), nullable=False),
        sa.Column("destination_key", sa.String(length=256), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column(
            "available_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["alert_id"], ["alerts.id"], ondelete="CASCADE"),
        sa.UniqueConstraint(
            "alert_id",
            "channel",
            "destination_key",
            name="uq_notification_outbox_destination",
        ),
        sa.CheckConstraint("channel IN ('in_app')", name="ck_notification_outbox_channel"),
        sa.CheckConstraint(
            "status IN ('pending', 'delivered', 'failed', 'skipped')",
            name="ck_notification_outbox_status",
        ),
    )
    op.create_index(
        "ix_notification_outbox_organization_id", "notification_outbox", ["organization_id"]
    )
    op.create_index("ix_notification_outbox_alert_id", "notification_outbox", ["alert_id"])

    op.create_table(
        "alert_generation_receipts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("diff_summary_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("operation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("alert_count", sa.Integer(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["diff_summary_id"], ["operation_diff_summaries.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["operation_id"], ["operations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("diff_summary_id", name="uq_alert_generation_receipt_diff"),
    )
    op.create_index(
        "ix_alert_generation_receipts_diff_summary_id",
        "alert_generation_receipts",
        ["diff_summary_id"],
        unique=True,
    )
    op.create_index(
        "ix_alert_generation_receipts_operation_id",
        "alert_generation_receipts",
        ["operation_id"],
    )
    op.create_index(
        "ix_alert_generation_receipts_organization_id",
        "alert_generation_receipts",
        ["organization_id"],
    )


def downgrade() -> None:
    op.drop_table("alert_generation_receipts")
    op.drop_table("notification_outbox")
    op.drop_table("alert_user_states")
    op.drop_table("alerts")
    op.drop_table("alert_episodes")
