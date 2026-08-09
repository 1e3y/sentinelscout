"""rate limit counters for sensitive actions

Revision ID: 20260809_0012
Revises: 20260809_0011
Create Date: 2026-08-09 05:00:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260809_0012"
down_revision: Union[str, Sequence[str], None] = "20260809_0011"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "rate_limit_counters",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.UniqueConstraint(
            "organization_id",
            "user_id",
            "action",
            "window_start",
            name="uq_rate_limit_counter_window",
        ),
    )
    op.create_index(
        "ix_rate_limit_counters_organization_id", "rate_limit_counters", ["organization_id"]
    )
    op.create_index("ix_rate_limit_counters_user_id", "rate_limit_counters", ["user_id"])
    op.create_index("ix_rate_limit_counters_action", "rate_limit_counters", ["action"])


def downgrade() -> None:
    op.drop_index("ix_rate_limit_counters_action", table_name="rate_limit_counters")
    op.drop_index("ix_rate_limit_counters_user_id", table_name="rate_limit_counters")
    op.drop_index("ix_rate_limit_counters_organization_id", table_name="rate_limit_counters")
    op.drop_table("rate_limit_counters")
