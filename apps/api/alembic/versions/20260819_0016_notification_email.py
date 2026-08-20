"""notification email settings, verified email, outbox fencing and freeze

Revision ID: 20260819_0016
Revises: 20260819_0015
Create Date: 2026-08-19 23:30:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260819_0016"
down_revision: Union[str, Sequence[str], None] = "20260819_0015"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column(
            "email_verified",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )

    op.create_table(
        "organization_notification_settings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("email_enabled", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column(
            "email_min_priority",
            sa.String(length=16),
            nullable=False,
            server_default="medium",
        ),
        sa.Column("updated_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
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
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["updated_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.UniqueConstraint("organization_id", name="uq_org_notification_settings"),
        sa.CheckConstraint(
            "email_min_priority IN ('info', 'low', 'medium')",
            name="ck_org_notification_email_min_priority",
        ),
    )
    op.create_index(
        "ix_organization_notification_settings_organization_id",
        "organization_notification_settings",
        ["organization_id"],
        unique=True,
    )

    op.create_table(
        "organization_email_recipients",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("created_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.UniqueConstraint("organization_id", "user_id", name="uq_org_email_recipient"),
    )
    op.create_index(
        "ix_organization_email_recipients_organization_id",
        "organization_email_recipients",
        ["organization_id"],
    )
    op.create_index(
        "ix_organization_email_recipients_user_id",
        "organization_email_recipients",
        ["user_id"],
    )

    op.drop_constraint("ck_notification_outbox_channel", "notification_outbox", type_="check")
    op.drop_constraint("ck_notification_outbox_status", "notification_outbox", type_="check")
    op.create_check_constraint(
        "ck_notification_outbox_channel",
        "notification_outbox",
        "channel IN ('in_app', 'email')",
    )
    op.create_check_constraint(
        "ck_notification_outbox_status",
        "notification_outbox",
        "status IN ('pending', 'processing', 'delivered', 'failed', 'dead', 'skipped')",
    )
    op.add_column(
        "notification_outbox",
        sa.Column("delivery_snapshot", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )
    op.add_column(
        "notification_outbox",
        sa.Column("recipient_user_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.add_column(
        "notification_outbox",
        sa.Column("processing_token", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.add_column(
        "notification_outbox",
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "notification_outbox",
        sa.Column("last_error_code", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "notification_outbox",
        sa.Column("last_attempt_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_foreign_key(
        "fk_notification_outbox_recipient_user_id",
        "notification_outbox",
        "users",
        ["recipient_user_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index(
        "ix_notification_outbox_recipient_user_id",
        "notification_outbox",
        ["recipient_user_id"],
    )
    op.create_index(
        "ix_notification_outbox_email_due",
        "notification_outbox",
        ["available_at"],
        postgresql_where=sa.text("channel = 'email' AND status IN ('pending', 'failed')"),
    )
    op.create_index(
        "ix_notification_outbox_email_lease",
        "notification_outbox",
        ["lease_expires_at"],
        postgresql_where=sa.text("channel = 'email' AND status = 'processing'"),
    )


def downgrade() -> None:
    op.drop_index("ix_notification_outbox_email_lease", table_name="notification_outbox")
    op.drop_index("ix_notification_outbox_email_due", table_name="notification_outbox")
    op.drop_index("ix_notification_outbox_recipient_user_id", table_name="notification_outbox")
    op.drop_constraint(
        "fk_notification_outbox_recipient_user_id", "notification_outbox", type_="foreignkey"
    )
    op.drop_column("notification_outbox", "last_attempt_at")
    op.drop_column("notification_outbox", "last_error_code")
    op.drop_column("notification_outbox", "lease_expires_at")
    op.drop_column("notification_outbox", "processing_token")
    op.drop_column("notification_outbox", "recipient_user_id")
    op.drop_column("notification_outbox", "delivery_snapshot")
    op.drop_constraint("ck_notification_outbox_status", "notification_outbox", type_="check")
    op.drop_constraint("ck_notification_outbox_channel", "notification_outbox", type_="check")
    op.create_check_constraint(
        "ck_notification_outbox_channel",
        "notification_outbox",
        "channel IN ('in_app')",
    )
    op.create_check_constraint(
        "ck_notification_outbox_status",
        "notification_outbox",
        "status IN ('pending', 'delivered', 'failed', 'skipped')",
    )
    op.drop_table("organization_email_recipients")
    op.drop_table("organization_notification_settings")
    op.drop_column("users", "email_verified")
