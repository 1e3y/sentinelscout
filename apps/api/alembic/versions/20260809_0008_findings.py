"""findings and remediation workflow

Revision ID: 20260809_0008
Revises: 20260809_0007
Create Date: 2026-08-09 02:00:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260809_0008"
down_revision: Union[str, Sequence[str], None] = "20260809_0007"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("operation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("candidate_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("title", sa.String(length=256), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("business_impact", sa.Text(), nullable=False),
        sa.Column("remediation_guidance", sa.Text(), nullable=False),
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
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["candidate_id"], ["security_candidates.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["operation_id"], ["operations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("candidate_id", name="uq_finding_candidate_id"),
        sa.CheckConstraint(
            "status IN ('open', 'in_progress', 'ready_for_retest', 'resolved')",
            name="ck_finding_status",
        ),
        sa.CheckConstraint(
            "severity IN ('informational', 'low', 'medium', 'high', 'critical')",
            name="ck_finding_severity",
        ),
    )
    op.create_index("ix_findings_organization_id", "findings", ["organization_id"], unique=False)
    op.create_index("ix_findings_operation_id", "findings", ["operation_id"], unique=False)
    op.create_index("ix_findings_candidate_id", "findings", ["candidate_id"], unique=False)
    op.create_index("ix_findings_asset_id", "findings", ["asset_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_findings_asset_id", table_name="findings")
    op.drop_index("ix_findings_candidate_id", table_name="findings")
    op.drop_index("ix_findings_operation_id", table_name="findings")
    op.drop_index("ix_findings_organization_id", table_name="findings")
    op.drop_table("findings")
