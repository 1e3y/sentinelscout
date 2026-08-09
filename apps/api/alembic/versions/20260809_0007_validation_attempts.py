"""validation attempts and supported candidate status

Revision ID: 20260809_0007
Revises: 20260809_0006
Create Date: 2026-08-09 01:20:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260809_0007"
down_revision: Union[str, Sequence[str], None] = "20260809_0006"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_constraint("ck_security_candidate_status", "security_candidates", type_="check")
    op.create_check_constraint(
        "ck_security_candidate_status",
        "security_candidates",
        "status IN ('candidate', 'dismissed', 'needs_review', 'supported')",
    )

    op.create_table(
        "validation_attempts",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("operation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("candidate_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("validation_method", sa.String(length=64), nullable=False),
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
        sa.ForeignKeyConstraint(["operation_id"], ["operations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(
            "status IN ('pending', 'running', 'supported', 'unsupported', "
            "'inconclusive', 'failed')",
            name="ck_validation_attempt_status",
        ),
    )
    op.create_index(
        "ix_validation_attempts_organization_id",
        "validation_attempts",
        ["organization_id"],
        unique=False,
    )
    op.create_index(
        "ix_validation_attempts_operation_id",
        "validation_attempts",
        ["operation_id"],
        unique=False,
    )
    op.create_index(
        "ix_validation_attempts_candidate_id",
        "validation_attempts",
        ["candidate_id"],
        unique=False,
    )
    op.create_index(
        "ix_validation_attempts_asset_id",
        "validation_attempts",
        ["asset_id"],
        unique=False,
    )
    op.create_index(
        "uq_validation_active_per_candidate",
        "validation_attempts",
        ["candidate_id"],
        unique=True,
        postgresql_where=sa.text("status IN ('pending', 'running')"),
    )


def downgrade() -> None:
    op.drop_index(
        "uq_validation_active_per_candidate",
        table_name="validation_attempts",
        postgresql_where=sa.text("status IN ('pending', 'running')"),
    )
    op.drop_index("ix_validation_attempts_asset_id", table_name="validation_attempts")
    op.drop_index("ix_validation_attempts_candidate_id", table_name="validation_attempts")
    op.drop_index("ix_validation_attempts_operation_id", table_name="validation_attempts")
    op.drop_index("ix_validation_attempts_organization_id", table_name="validation_attempts")
    op.drop_table("validation_attempts")

    op.drop_constraint("ck_security_candidate_status", "security_candidates", type_="check")
    op.create_check_constraint(
        "ck_security_candidate_status",
        "security_candidates",
        "status IN ('candidate', 'dismissed', 'needs_review')",
    )
