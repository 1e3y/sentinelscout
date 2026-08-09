"""authorized targets, authorizations, and scopes

Revision ID: 20260809_0002
Revises: 20260809_0001
Create Date: 2026-08-09 00:10:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260809_0002"
down_revision: Union[str, Sequence[str], None] = "20260809_0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "authorized_targets",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("created_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("domain", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
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
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "domain", name="uq_org_target_domain"),
    )
    op.create_index(
        "ix_authorized_targets_organization_id",
        "authorized_targets",
        ["organization_id"],
        unique=False,
    )

    op.create_table(
        "target_authorizations",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("method", sa.String(), nullable=False),
        sa.Column("token", sa.Text(), nullable=False),
        sa.Column("txt_name", sa.String(), nullable=False),
        sa.Column("txt_value", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["target_id"], ["authorized_targets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("target_id"),
    )
    op.create_index(
        "ix_target_authorizations_target_id",
        "target_authorizations",
        ["target_id"],
        unique=False,
    )

    op.create_table(
        "target_scopes",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("root_domain", sa.String(), nullable=False),
        sa.Column("include_subdomains", sa.Boolean(), nullable=False),
        sa.Column("exclusions", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
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
        sa.ForeignKeyConstraint(["target_id"], ["authorized_targets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("target_id"),
    )
    op.create_index("ix_target_scopes_target_id", "target_scopes", ["target_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_target_scopes_target_id", table_name="target_scopes")
    op.drop_table("target_scopes")
    op.drop_index("ix_target_authorizations_target_id", table_name="target_authorizations")
    op.drop_table("target_authorizations")
    op.drop_index("ix_authorized_targets_organization_id", table_name="authorized_targets")
    op.drop_table("authorized_targets")
