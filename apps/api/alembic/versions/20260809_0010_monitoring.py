"""monitoring configurations and operation source

Revision ID: 20260809_0010
Revises: 20260809_0009
Create Date: 2026-08-09 03:10:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260809_0010"
down_revision: Union[str, Sequence[str], None] = "20260809_0009"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "operations",
        sa.Column("source", sa.String(length=32), nullable=False, server_default="manual"),
    )
    op.create_check_constraint(
        "ck_operation_source",
        "operations",
        "source IN ('manual', 'scheduled')",
    )

    op.create_table(
        "monitoring_configurations",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("frequency", sa.String(length=32), nullable=False),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("disabled_reason", sa.Text(), nullable=True),
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
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["target_id"], ["authorized_targets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["updated_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("target_id", name="uq_monitoring_target_id"),
        sa.CheckConstraint(
            "frequency IN ('daily', 'weekly')",
            name="ck_monitoring_frequency",
        ),
    )
    op.create_index(
        "ix_monitoring_configurations_organization_id",
        "monitoring_configurations",
        ["organization_id"],
        unique=False,
    )
    op.create_index(
        "ix_monitoring_configurations_target_id",
        "monitoring_configurations",
        ["target_id"],
        unique=False,
    )
    op.create_index(
        "ix_monitoring_due",
        "monitoring_configurations",
        ["enabled", "next_run_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_monitoring_due", table_name="monitoring_configurations")
    op.drop_index(
        "ix_monitoring_configurations_target_id", table_name="monitoring_configurations"
    )
    op.drop_index(
        "ix_monitoring_configurations_organization_id",
        table_name="monitoring_configurations",
    )
    op.drop_table("monitoring_configurations")
    op.drop_constraint("ck_operation_source", "operations", type_="check")
    op.drop_column("operations", "source")
