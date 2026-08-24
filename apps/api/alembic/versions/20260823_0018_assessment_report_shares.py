"""external assessment report shares

Revision ID: 20260823_0018
Revises: 20260821_0017
Create Date: 2026-08-23 17:32:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260823_0018"
down_revision: Union[str, Sequence[str], None] = "20260821_0017"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "assessment_report_shares",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("report_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("created_by_user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("secret_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["report_id"], ["assessment_reports.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"], ondelete="RESTRICT"),
        sa.CheckConstraint("length(secret_hash) = 64", name="ck_report_share_secret_hash_len"),
        sa.CheckConstraint(
            "expires_at > created_at", name="ck_report_share_expires_after_create"
        ),
    )
    op.create_index(
        "ix_assessment_report_shares_organization_id",
        "assessment_report_shares",
        ["organization_id"],
    )
    op.create_index(
        "ix_assessment_report_shares_report_id",
        "assessment_report_shares",
        ["report_id"],
    )
    op.create_index(
        "ix_assessment_report_shares_created_at",
        "assessment_report_shares",
        ["report_id", "created_at"],
    )

    op.create_table(
        "anonymous_rate_limit_counters",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("bucket", sa.String(length=64), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint("count >= 0", name="ck_anonymous_rate_limit_count_nonneg"),
        sa.UniqueConstraint(
            "action",
            "bucket",
            "window_start",
            name="uq_anonymous_rate_limit_window",
        ),
    )
    op.create_index(
        "ix_anonymous_rate_limit_counters_action",
        "anonymous_rate_limit_counters",
        ["action"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_anonymous_rate_limit_counters_action",
        table_name="anonymous_rate_limit_counters",
    )
    op.drop_table("anonymous_rate_limit_counters")
    op.drop_index(
        "ix_assessment_report_shares_created_at", table_name="assessment_report_shares"
    )
    op.drop_index(
        "ix_assessment_report_shares_report_id", table_name="assessment_report_shares"
    )
    op.drop_index(
        "ix_assessment_report_shares_organization_id",
        table_name="assessment_report_shares",
    )
    op.drop_table("assessment_report_shares")
