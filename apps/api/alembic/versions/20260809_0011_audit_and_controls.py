"""audit events, operation control snapshots, testing profile

Revision ID: 20260809_0011
Revises: 20260809_0010
Create Date: 2026-08-09 04:30:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260809_0011"
down_revision: Union[str, Sequence[str], None] = "20260809_0010"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "operations",
        sa.Column(
            "testing_profile",
            sa.String(length=64),
            nullable=False,
            server_default="safe_production",
        ),
    )

    op.create_table(
        "audit_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("actor_type", sa.String(length=32), nullable=False),
        sa.Column("actor_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("action", sa.String(length=128), nullable=False),
        sa.Column("resource_type", sa.String(length=64), nullable=False),
        sa.Column("resource_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["actor_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(
            "actor_type IN ('user', 'system', 'worker', 'scheduler')",
            name="ck_audit_actor_type",
        ),
    )
    op.create_index("ix_audit_events_organization_id", "audit_events", ["organization_id"])
    op.create_index("ix_audit_events_actor_user_id", "audit_events", ["actor_user_id"])
    op.create_index("ix_audit_events_action", "audit_events", ["action"])
    op.create_index("ix_audit_events_resource_type", "audit_events", ["resource_type"])
    op.create_index("ix_audit_events_resource_id", "audit_events", ["resource_id"])
    op.create_index("ix_audit_events_created_at", "audit_events", ["created_at"])

    op.create_table(
        "operation_control_snapshots",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("operation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("target_domain", sa.String(length=253), nullable=False),
        sa.Column("authorization_status", sa.String(length=32), nullable=False),
        sa.Column("target_authorization_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("scope_root", sa.String(length=253), nullable=False),
        sa.Column("include_subdomains", sa.Boolean(), nullable=False),
        sa.Column("exclusions", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("operation_source", sa.String(length=32), nullable=False),
        sa.Column("testing_profile", sa.String(length=64), nullable=False),
        sa.Column("created_by_user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["operation_id"], ["operations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["target_id"], ["authorized_targets.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("operation_id"),
    )
    op.create_index(
        "ix_operation_control_snapshots_operation_id",
        "operation_control_snapshots",
        ["operation_id"],
    )
    op.create_index(
        "ix_operation_control_snapshots_organization_id",
        "operation_control_snapshots",
        ["organization_id"],
    )
    op.create_index(
        "ix_operation_control_snapshots_target_id",
        "operation_control_snapshots",
        ["target_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_operation_control_snapshots_target_id", table_name="operation_control_snapshots"
    )
    op.drop_index(
        "ix_operation_control_snapshots_organization_id",
        table_name="operation_control_snapshots",
    )
    op.drop_index(
        "ix_operation_control_snapshots_operation_id",
        table_name="operation_control_snapshots",
    )
    op.drop_table("operation_control_snapshots")
    op.drop_index("ix_audit_events_created_at", table_name="audit_events")
    op.drop_index("ix_audit_events_resource_id", table_name="audit_events")
    op.drop_index("ix_audit_events_resource_type", table_name="audit_events")
    op.drop_index("ix_audit_events_action", table_name="audit_events")
    op.drop_index("ix_audit_events_actor_user_id", table_name="audit_events")
    op.drop_index("ix_audit_events_organization_id", table_name="audit_events")
    op.drop_table("audit_events")
    op.drop_column("operations", "testing_profile")
