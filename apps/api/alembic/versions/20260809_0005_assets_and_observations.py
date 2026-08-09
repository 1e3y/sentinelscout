"""assets and discovery observations

Revision ID: 20260809_0005
Revises: 20260809_0004
Create Date: 2026-08-09 00:40:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260809_0005"
down_revision: Union[str, Sequence[str], None] = "20260809_0004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "assets",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("hostname", sa.String(length=253), nullable=False),
        sa.Column("url", sa.String(length=2048), nullable=False),
        sa.Column("asset_type", sa.String(length=64), nullable=False),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("title", sa.String(length=512), nullable=True),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column(
            "first_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "last_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["target_id"], ["authorized_targets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "organization_id",
            "target_id",
            "hostname",
            "url",
            name="uq_asset_org_target_host_url",
        ),
    )
    op.create_index("ix_assets_organization_id", "assets", ["organization_id"], unique=False)
    op.create_index("ix_assets_target_id", "assets", ["target_id"], unique=False)

    op.create_table(
        "discovery_observations",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("operation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("observation_type", sa.String(length=64), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["operation_id"], ["operations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_discovery_observations_organization_id",
        "discovery_observations",
        ["organization_id"],
        unique=False,
    )
    op.create_index(
        "ix_discovery_observations_operation_id",
        "discovery_observations",
        ["operation_id"],
        unique=False,
    )
    op.create_index(
        "ix_discovery_observations_asset_id",
        "discovery_observations",
        ["asset_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_discovery_observations_asset_id", table_name="discovery_observations")
    op.drop_index("ix_discovery_observations_operation_id", table_name="discovery_observations")
    op.drop_index(
        "ix_discovery_observations_organization_id", table_name="discovery_observations"
    )
    op.drop_table("discovery_observations")
    op.drop_index("ix_assets_target_id", table_name="assets")
    op.drop_index("ix_assets_organization_id", table_name="assets")
    op.drop_table("assets")
