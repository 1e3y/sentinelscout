"""automatic scheduled report delivery

Revision ID: 20260826_0020
Revises: 20260826_0019
Create Date: 2026-08-26 19:50:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "20260826_0020"
down_revision: str | Sequence[str] | None = "20260826_0019"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "monitoring_configurations",
        sa.Column(
            "auto_deliver_reports",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )
    op.add_column(
        "monitoring_configurations",
        sa.Column(
            "auto_deliver_expires_in",
            sa.String(length=8),
            nullable=False,
            server_default="7d",
        ),
    )
    op.create_check_constraint(
        "ck_monitoring_auto_deliver_expires_in",
        "monitoring_configurations",
        "auto_deliver_expires_in IN ('24h', '7d', '30d')",
    )

    op.create_table(
        "monitoring_report_delivery_recipients",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("monitoring_configuration_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("email_normalized", sa.String(length=320), nullable=False),
        sa.Column("created_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["monitoring_configuration_id"],
            ["monitoring_configurations.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["target_id"], ["authorized_targets.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.UniqueConstraint(
            "monitoring_configuration_id",
            "email_normalized",
            name="uq_monitoring_report_delivery_recipient",
        ),
    )
    op.create_index(
        "ix_monitoring_report_delivery_recipients_organization_id",
        "monitoring_report_delivery_recipients",
        ["organization_id"],
    )
    op.create_index(
        "ix_monitoring_report_delivery_recipients_target_id",
        "monitoring_report_delivery_recipients",
        ["target_id"],
    )

    op.create_table(
        "assessment_report_delivery_jobs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("operation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("generation_job_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("report_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "available_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("processing_token", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error_code", sa.String(length=64), nullable=True),
        sa.Column(
            "frozen_recipients",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("frozen_expires_in", sa.String(length=8), nullable=False),
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
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["operation_id"], ["operations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["generation_job_id"],
            ["assessment_report_generation_jobs.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["report_id"], ["assessment_reports.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["target_id"], ["authorized_targets.id"], ondelete="CASCADE"
        ),
        sa.UniqueConstraint(
            "operation_id", name="uq_assessment_report_delivery_job_operation"
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'processing', 'succeeded', 'skipped', 'failed')",
            name="ck_assessment_report_delivery_job_status",
        ),
        sa.CheckConstraint(
            "frozen_expires_in IN ('24h', '7d', '30d')",
            name="ck_assessment_report_delivery_job_expires",
        ),
        sa.CheckConstraint(
            "attempt_count >= 0",
            name="ck_assessment_report_delivery_job_attempts",
        ),
    )
    op.create_index(
        "ix_assessment_report_delivery_jobs_organization_id",
        "assessment_report_delivery_jobs",
        ["organization_id"],
    )
    op.create_index(
        "ix_assessment_report_delivery_jobs_status_available",
        "assessment_report_delivery_jobs",
        ["status", "available_at"],
    )

    op.create_table(
        "assessment_report_delivery_outbox",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("delivery_job_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("report_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("share_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("destination_key", sa.String(length=356), nullable=False),
        sa.Column("recipient_email_normalized", sa.String(length=320), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "available_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("processing_token", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error_code", sa.String(length=64), nullable=True),
        sa.Column("encrypted_secret", sa.LargeBinary(), nullable=True),
        sa.Column("encrypted_secret_nonce", sa.LargeBinary(), nullable=True),
        sa.Column("encryption_key_version", sa.String(length=32), nullable=True),
        sa.Column("frozen_frontend_origin", sa.String(length=512), nullable=False),
        sa.Column("frozen_from_email", sa.String(length=320), nullable=False),
        sa.Column("frozen_subject", sa.String(length=256), nullable=False),
        sa.Column("frozen_target_domain", sa.String(length=253), nullable=False),
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
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["delivery_job_id"],
            ["assessment_report_delivery_jobs.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["report_id"], ["assessment_reports.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["share_id"], ["assessment_report_shares.id"], ondelete="RESTRICT"
        ),
        sa.UniqueConstraint(
            "share_id", name="uq_assessment_report_delivery_outbox_share"
        ),
        sa.UniqueConstraint(
            "delivery_job_id",
            "destination_key",
            name="uq_assessment_report_delivery_outbox_destination",
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'processing', 'delivered', 'failed', 'dead', 'skipped')",
            name="ck_assessment_report_delivery_outbox_status",
        ),
        sa.CheckConstraint(
            "attempt_count >= 0",
            name="ck_assessment_report_delivery_outbox_attempts",
        ),
    )
    op.create_index(
        "ix_assessment_report_delivery_outbox_organization_id",
        "assessment_report_delivery_outbox",
        ["organization_id"],
    )
    op.create_index(
        "ix_assessment_report_delivery_outbox_status_available",
        "assessment_report_delivery_outbox",
        ["status", "available_at"],
    )

    op.add_column(
        "assessment_report_shares",
        sa.Column(
            "creation_origin",
            sa.String(length=32),
            nullable=False,
            server_default="manual",
        ),
    )
    op.alter_column(
        "assessment_report_shares",
        "created_by_user_id",
        existing_type=postgresql.UUID(as_uuid=True),
        nullable=True,
    )
    op.add_column(
        "assessment_report_shares",
        sa.Column("delivery_outbox_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_unique_constraint(
        "uq_assessment_report_share_delivery_outbox",
        "assessment_report_shares",
        ["delivery_outbox_id"],
    )
    op.create_check_constraint(
        "ck_assessment_report_share_creation_origin",
        "assessment_report_shares",
        "creation_origin IN ('manual', 'scheduled_automatic')",
    )
    op.create_check_constraint(
        "ck_assessment_report_share_origin_actor",
        "assessment_report_shares",
        "(creation_origin = 'manual' AND created_by_user_id IS NOT NULL) OR "
        "(creation_origin = 'scheduled_automatic' AND created_by_user_id IS NULL)",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_assessment_report_share_origin_actor",
        "assessment_report_shares",
        type_="check",
    )
    op.drop_constraint(
        "ck_assessment_report_share_creation_origin",
        "assessment_report_shares",
        type_="check",
    )
    op.drop_constraint(
        "uq_assessment_report_share_delivery_outbox",
        "assessment_report_shares",
        type_="unique",
    )
    op.drop_column("assessment_report_shares", "delivery_outbox_id")
    op.alter_column(
        "assessment_report_shares",
        "created_by_user_id",
        existing_type=postgresql.UUID(as_uuid=True),
        nullable=False,
    )
    op.drop_column("assessment_report_shares", "creation_origin")
    op.drop_index(
        "ix_assessment_report_delivery_outbox_status_available",
        table_name="assessment_report_delivery_outbox",
    )
    op.drop_index(
        "ix_assessment_report_delivery_outbox_organization_id",
        table_name="assessment_report_delivery_outbox",
    )
    op.drop_table("assessment_report_delivery_outbox")
    op.drop_index(
        "ix_assessment_report_delivery_jobs_status_available",
        table_name="assessment_report_delivery_jobs",
    )
    op.drop_index(
        "ix_assessment_report_delivery_jobs_organization_id",
        table_name="assessment_report_delivery_jobs",
    )
    op.drop_table("assessment_report_delivery_jobs")
    op.drop_index(
        "ix_monitoring_report_delivery_recipients_target_id",
        table_name="monitoring_report_delivery_recipients",
    )
    op.drop_index(
        "ix_monitoring_report_delivery_recipients_organization_id",
        table_name="monitoring_report_delivery_recipients",
    )
    op.drop_table("monitoring_report_delivery_recipients")
    op.drop_constraint(
        "ck_monitoring_auto_deliver_expires_in",
        "monitoring_configurations",
        type_="check",
    )
    op.drop_column("monitoring_configurations", "auto_deliver_expires_in")
    op.drop_column("monitoring_configurations", "auto_deliver_reports")
