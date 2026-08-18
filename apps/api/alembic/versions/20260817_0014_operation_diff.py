"""operation diff summaries

Revision ID: 20260817_0014
Revises: 20260816_0013
Create Date: 2026-08-17 21:50:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260817_0014"
down_revision: Union[str, Sequence[str], None] = "20260816_0013"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "operation_diff_summaries",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("operation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("baseline_operation_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("schema_version", sa.Integer(), nullable=False),
        sa.Column("comparability", sa.String(length=64), nullable=False),
        sa.Column("comparison_snapshot", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("changes", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("counts", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("headline", sa.Text(), nullable=False),
        sa.Column(
            "security_signal_baseline_unavailable",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column(
            "security_signal_comparison_suppressed",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("security_signal_suppression_reason", sa.Text(), nullable=True),
        sa.Column("operation_status_at_freeze", sa.String(length=32), nullable=False),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column(
            "frozen_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["operation_id"], ["operations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["target_id"], ["authorized_targets.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["baseline_operation_id"], ["operations.id"], ondelete="SET NULL"
        ),
        sa.UniqueConstraint("operation_id", name="uq_operation_diff_summary_operation_id"),
    )
    op.create_index(
        "ix_operation_diff_summaries_operation_id",
        "operation_diff_summaries",
        ["operation_id"],
        unique=True,
    )
    op.create_index(
        "ix_operation_diff_summaries_organization_id",
        "operation_diff_summaries",
        ["organization_id"],
    )
    op.create_index(
        "ix_operation_diff_summaries_target_id",
        "operation_diff_summaries",
        ["target_id"],
    )
    op.create_index(
        "ix_operation_diff_summaries_baseline_operation_id",
        "operation_diff_summaries",
        ["baseline_operation_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_operation_diff_summaries_baseline_operation_id",
        table_name="operation_diff_summaries",
    )
    op.drop_index(
        "ix_operation_diff_summaries_target_id",
        table_name="operation_diff_summaries",
    )
    op.drop_index(
        "ix_operation_diff_summaries_organization_id",
        table_name="operation_diff_summaries",
    )
    op.drop_index(
        "ix_operation_diff_summaries_operation_id",
        table_name="operation_diff_summaries",
    )
    op.drop_table("operation_diff_summaries")
