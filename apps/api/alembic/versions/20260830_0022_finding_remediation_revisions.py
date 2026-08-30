"""immutable finding remediation revisions

Revision ID: 20260830_0022
Revises: 20260829_0021
Create Date: 2026-08-30 00:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260830_0022"
down_revision: str | Sequence[str] | None = "20260829_0021"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "finding_remediation_revisions",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("finding_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("revision_number", sa.Integer(), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("created_by_user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "revision_number >= 1",
            name="ck_finding_remediation_revision_number",
        ),
        sa.CheckConstraint(
            "char_length(summary) BETWEEN 1 AND 4000",
            name="ck_finding_remediation_summary_length",
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
            ["created_by_user_id"],
            ["users.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "finding_id",
            "revision_number",
            name="uq_finding_remediation_revision_number",
        ),
    )
    op.create_index(
        "ix_finding_remediation_revisions_organization_id",
        "finding_remediation_revisions",
        ["organization_id"],
    )
    op.create_index(
        "ix_finding_remediation_revisions_finding_id",
        "finding_remediation_revisions",
        ["finding_id"],
    )
    op.create_index(
        "ix_finding_remediation_revisions_created_by_user_id",
        "finding_remediation_revisions",
        ["created_by_user_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_finding_remediation_revisions_created_by_user_id",
        table_name="finding_remediation_revisions",
    )
    op.drop_index(
        "ix_finding_remediation_revisions_finding_id",
        table_name="finding_remediation_revisions",
    )
    op.drop_index(
        "ix_finding_remediation_revisions_organization_id",
        table_name="finding_remediation_revisions",
    )
    op.drop_table("finding_remediation_revisions")
