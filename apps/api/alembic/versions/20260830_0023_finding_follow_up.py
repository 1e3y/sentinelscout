"""finding ownership and follow-up due dates

Revision ID: 20260830_0023
Revises: 20260830_0022
Create Date: 2026-08-30 12:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260830_0023"
down_revision: str | Sequence[str] | None = "20260830_0022"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column("assigned_to_user_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.add_column(
        "findings",
        sa.Column("follow_up_due_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_foreign_key(
        "fk_findings_assigned_to_user_id_users",
        "findings",
        "users",
        ["assigned_to_user_id"],
        ["id"],
        ondelete="SET NULL",
    )
    # No finding assignee index in this migration: EXPLAIN first (M33 index discipline).

    op.create_table(
        "finding_follow_up_changes",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("finding_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("changed_by_user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "previous_assigned_to_user_id",
            postgresql.UUID(as_uuid=True),
            nullable=True,
        ),
        sa.Column(
            "new_assigned_to_user_id",
            postgresql.UUID(as_uuid=True),
            nullable=True,
        ),
        sa.Column("previous_due_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("new_due_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
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
            ["changed_by_user_id"],
            ["users.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["previous_assigned_to_user_id"],
            ["users.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["new_assigned_to_user_id"],
            ["users.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_finding_follow_up_changes_finding_created_at_id",
        "finding_follow_up_changes",
        ["finding_id", "created_at", "id"],
        unique=False,
        postgresql_ops={"created_at": "DESC", "id": "DESC"},
    )


def downgrade() -> None:
    op.drop_index(
        "ix_finding_follow_up_changes_finding_created_at_id",
        table_name="finding_follow_up_changes",
    )
    op.drop_table("finding_follow_up_changes")
    op.drop_constraint(
        "fk_findings_assigned_to_user_id_users", "findings", type_="foreignkey"
    )
    op.drop_column("findings", "follow_up_due_at")
    op.drop_column("findings", "assigned_to_user_id")
