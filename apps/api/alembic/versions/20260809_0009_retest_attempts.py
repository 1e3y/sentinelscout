"""retest attempts and finding resolution via retest

Revision ID: 20260809_0009
Revises: 20260809_0008
Create Date: 2026-08-09 02:40:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260809_0009"
down_revision: Union[str, Sequence[str], None] = "20260809_0008"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "retest_attempts",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("finding_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("candidate_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "original_validation_attempt_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("method", sa.String(length=64), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["candidate_id"], ["security_candidates.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["original_validation_attempt_id"],
            ["validation_attempts.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(
            "status IN ('pending', 'running', 'passed', 'failed', "
            "'inconclusive', 'error')",
            name="ck_retest_attempt_status",
        ),
    )
    op.create_index(
        "ix_retest_attempts_organization_id",
        "retest_attempts",
        ["organization_id"],
        unique=False,
    )
    op.create_index(
        "ix_retest_attempts_finding_id", "retest_attempts", ["finding_id"], unique=False
    )
    op.create_index(
        "ix_retest_attempts_candidate_id",
        "retest_attempts",
        ["candidate_id"],
        unique=False,
    )
    op.create_index(
        "ix_retest_attempts_asset_id", "retest_attempts", ["asset_id"], unique=False
    )
    op.create_index(
        "ix_retest_attempts_original_validation_attempt_id",
        "retest_attempts",
        ["original_validation_attempt_id"],
        unique=False,
    )
    op.create_index(
        "uq_retest_active_per_finding",
        "retest_attempts",
        ["finding_id"],
        unique=True,
        postgresql_where=sa.text("status IN ('pending', 'running')"),
    )


def downgrade() -> None:
    op.drop_index(
        "uq_retest_active_per_finding",
        table_name="retest_attempts",
        postgresql_where=sa.text("status IN ('pending', 'running')"),
    )
    op.drop_index(
        "ix_retest_attempts_original_validation_attempt_id",
        table_name="retest_attempts",
    )
    op.drop_index("ix_retest_attempts_asset_id", table_name="retest_attempts")
    op.drop_index("ix_retest_attempts_candidate_id", table_name="retest_attempts")
    op.drop_index("ix_retest_attempts_finding_id", table_name="retest_attempts")
    op.drop_index("ix_retest_attempts_organization_id", table_name="retest_attempts")
    op.drop_table("retest_attempts")
