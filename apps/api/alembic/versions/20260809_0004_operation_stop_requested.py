"""add stop_requested to operations

Revision ID: 20260809_0004
Revises: 20260809_0003
Create Date: 2026-08-09 00:30:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "20260809_0004"
down_revision: Union[str, Sequence[str], None] = "20260809_0003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "operations",
        sa.Column(
            "stop_requested",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )
    op.create_index(
        "ix_operations_status_created_at",
        "operations",
        ["status", "created_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_operations_status_created_at", table_name="operations")
    op.drop_column("operations", "stop_requested")
