"""security candidates

Revision ID: 20260809_0006
Revises: 20260809_0005
Create Date: 2026-08-09 00:50:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260809_0006"
down_revision: Union[str, Sequence[str], None] = "20260809_0005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "security_candidates",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("operation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("candidate_type", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=256), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
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
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["operation_id"], ["operations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "organization_id",
            "asset_id",
            "candidate_type",
            name="uq_candidate_org_asset_type",
        ),
        sa.CheckConstraint(
            "status IN ('candidate', 'dismissed', 'needs_review')",
            name="ck_security_candidate_status",
        ),
    )
    op.create_index(
        "ix_security_candidates_organization_id",
        "security_candidates",
        ["organization_id"],
        unique=False,
    )
    op.create_index(
        "ix_security_candidates_operation_id",
        "security_candidates",
        ["operation_id"],
        unique=False,
    )
    op.create_index(
        "ix_security_candidates_asset_id",
        "security_candidates",
        ["asset_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_security_candidates_asset_id", table_name="security_candidates")
    op.drop_index("ix_security_candidates_operation_id", table_name="security_candidates")
    op.drop_index("ix_security_candidates_organization_id", table_name="security_candidates")
    op.drop_table("security_candidates")
