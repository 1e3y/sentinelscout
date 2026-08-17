"""operation coverage summaries

Revision ID: 20260816_0013
Revises: 20260809_0012
Create Date: 2026-08-16 18:45:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260816_0013"
down_revision: Union[str, Sequence[str], None] = "20260809_0012"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "operation_coverage_summaries",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("operation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False),
        sa.Column("capability_manifest_version", sa.Integer(), nullable=False),
        sa.Column("capability_snapshot", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("surface", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("http_evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("scope_boundaries", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("freshness", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("headline", sa.Text(), nullable=False),
        sa.Column("operation_status_at_freeze", sa.String(length=32), nullable=False),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column(
            "frozen_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["operation_id"], ["operations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("operation_id", name="uq_operation_coverage_summary_operation_id"),
    )
    op.create_index(
        "ix_operation_coverage_summaries_operation_id",
        "operation_coverage_summaries",
        ["operation_id"],
        unique=True,
    )
    op.create_index(
        "ix_operation_coverage_summaries_organization_id",
        "operation_coverage_summaries",
        ["organization_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_operation_coverage_summaries_organization_id",
        table_name="operation_coverage_summaries",
    )
    op.drop_index(
        "ix_operation_coverage_summaries_operation_id",
        table_name="operation_coverage_summaries",
    )
    op.drop_table("operation_coverage_summaries")
