"""Finding follow-up reminder jobs (Milestone 34).

Revision ID: 20260831_0024
Revises: 20260830_0023
Create Date: 2026-08-31 12:00:00.000000
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260831_0024"
down_revision: Union[str, None] = "20260830_0023"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "organization_notification_settings",
        sa.Column(
            "finding_follow_up_reminders_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )

    op.create_table(
        "finding_follow_up_reminder_jobs",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("finding_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("follow_up_change_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("assigned_to_user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("due_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reminder_kind", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("processing_token", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("last_error_code", sa.String(length=64), nullable=True),
        sa.Column(
            "delivery_snapshot",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
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
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "reminder_kind IN ('due')",
            name="ck_finding_follow_up_reminder_kind",
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'processing', 'delivered', 'failed', 'dead', 'skipped')",
            name="ck_finding_follow_up_reminder_status",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["findings.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["follow_up_change_id"],
            ["finding_follow_up_changes.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["assigned_to_user_id"],
            ["users.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "finding_id",
            "follow_up_change_id",
            "reminder_kind",
            name="uq_finding_follow_up_reminder_generation",
        ),
    )
    op.create_index(
        "ix_finding_follow_up_reminder_jobs_organization_id",
        "finding_follow_up_reminder_jobs",
        ["organization_id"],
    )
    op.create_index(
        "ix_finding_follow_up_reminder_jobs_finding_id",
        "finding_follow_up_reminder_jobs",
        ["finding_id"],
    )
    op.create_index(
        "ix_finding_follow_up_reminder_jobs_follow_up_change_id",
        "finding_follow_up_reminder_jobs",
        ["follow_up_change_id"],
    )
    op.create_index(
        "ix_finding_follow_up_reminder_jobs_assigned_to_user_id",
        "finding_follow_up_reminder_jobs",
        ["assigned_to_user_id"],
    )
    # Claim due rows (pending/failed) and expired leases.
    op.create_index(
        "ix_finding_follow_up_reminder_jobs_due",
        "finding_follow_up_reminder_jobs",
        ["available_at"],
        postgresql_where=sa.text("status IN ('pending', 'failed')"),
    )
    op.create_index(
        "ix_finding_follow_up_reminder_jobs_lease",
        "finding_follow_up_reminder_jobs",
        ["lease_expires_at"],
        postgresql_where=sa.text("status = 'processing'"),
    )


def downgrade() -> None:
    op.drop_index(
        "ix_finding_follow_up_reminder_jobs_lease",
        table_name="finding_follow_up_reminder_jobs",
    )
    op.drop_index(
        "ix_finding_follow_up_reminder_jobs_due",
        table_name="finding_follow_up_reminder_jobs",
    )
    op.drop_index(
        "ix_finding_follow_up_reminder_jobs_assigned_to_user_id",
        table_name="finding_follow_up_reminder_jobs",
    )
    op.drop_index(
        "ix_finding_follow_up_reminder_jobs_follow_up_change_id",
        table_name="finding_follow_up_reminder_jobs",
    )
    op.drop_index(
        "ix_finding_follow_up_reminder_jobs_finding_id",
        table_name="finding_follow_up_reminder_jobs",
    )
    op.drop_index(
        "ix_finding_follow_up_reminder_jobs_organization_id",
        table_name="finding_follow_up_reminder_jobs",
    )
    op.drop_table("finding_follow_up_reminder_jobs")
    op.drop_column(
        "organization_notification_settings",
        "finding_follow_up_reminders_enabled",
    )
