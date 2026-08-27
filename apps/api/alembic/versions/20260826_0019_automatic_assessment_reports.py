"""automatic assessment reports after scheduled completions

Revision ID: 20260826_0019
Revises: 20260823_0018
Create Date: 2026-08-26 11:00:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260826_0019"
down_revision: Union[str, Sequence[str], None] = "20260823_0018"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "monitoring_configurations",
        sa.Column(
            "auto_generate_reports",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )

    op.add_column(
        "assessment_reports",
        sa.Column(
            "generation_origin",
            sa.String(length=32),
            nullable=False,
            server_default="manual",
        ),
    )
    op.alter_column(
        "assessment_reports",
        "created_by_user_id",
        existing_type=postgresql.UUID(as_uuid=True),
        nullable=True,
    )
    op.create_check_constraint(
        "ck_assessment_report_generation_origin",
        "assessment_reports",
        "generation_origin IN ('manual', 'scheduled_automatic')",
    )
    op.create_check_constraint(
        "ck_assessment_report_origin_actor",
        "assessment_reports",
        "(generation_origin = 'manual' AND created_by_user_id IS NOT NULL) OR "
        "(generation_origin = 'scheduled_automatic' AND created_by_user_id IS NULL)",
    )

    op.create_table(
        "assessment_report_generation_jobs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("operation_id", postgresql.UUID(as_uuid=True), nullable=False),
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
        sa.Column("report_id", postgresql.UUID(as_uuid=True), nullable=True),
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
            ["report_id"], ["assessment_reports.id"], ondelete="RESTRICT"
        ),
        sa.UniqueConstraint("operation_id", name="uq_assessment_report_generation_job_operation"),
        sa.CheckConstraint(
            "status IN ('pending', 'processing', 'succeeded', 'skipped', 'failed')",
            name="ck_assessment_report_generation_job_status",
        ),
        sa.CheckConstraint(
            "attempt_count >= 0",
            name="ck_assessment_report_generation_job_attempts",
        ),
    )
    op.create_index(
        "ix_assessment_report_generation_jobs_organization_id",
        "assessment_report_generation_jobs",
        ["organization_id"],
    )
    op.create_index(
        "ix_assessment_report_generation_jobs_status_available",
        "assessment_report_generation_jobs",
        ["status", "available_at"],
    )
    op.create_index(
        "ix_assessment_report_generation_jobs_due",
        "assessment_report_generation_jobs",
        ["available_at"],
        postgresql_where=sa.text("status = 'pending'"),
    )
    op.create_index(
        "ix_assessment_report_generation_jobs_lease",
        "assessment_report_generation_jobs",
        ["lease_expires_at"],
        postgresql_where=sa.text("status = 'processing'"),
    )


def downgrade() -> None:
    op.drop_index(
        "ix_assessment_report_generation_jobs_lease",
        table_name="assessment_report_generation_jobs",
    )
    op.drop_index(
        "ix_assessment_report_generation_jobs_due",
        table_name="assessment_report_generation_jobs",
    )
    op.drop_index(
        "ix_assessment_report_generation_jobs_status_available",
        table_name="assessment_report_generation_jobs",
    )
    op.drop_index(
        "ix_assessment_report_generation_jobs_organization_id",
        table_name="assessment_report_generation_jobs",
    )
    op.drop_table("assessment_report_generation_jobs")
    op.drop_constraint(
        "ck_assessment_report_origin_actor", "assessment_reports", type_="check"
    )
    op.drop_constraint(
        "ck_assessment_report_generation_origin", "assessment_reports", type_="check"
    )
    op.alter_column(
        "assessment_reports",
        "created_by_user_id",
        existing_type=postgresql.UUID(as_uuid=True),
        nullable=False,
    )
    op.drop_column("assessment_reports", "generation_origin")
    op.drop_column("monitoring_configurations", "auto_generate_reports")
