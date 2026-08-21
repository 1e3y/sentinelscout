"""immutable assessment reports

Revision ID: 20260821_0017
Revises: 20260819_0016
Create Date: 2026-08-21 16:30:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260821_0017"
down_revision: Union[str, Sequence[str], None] = "20260819_0016"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "assessment_reports",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("operation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("created_by_user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("target_domain", sa.String(length=253), nullable=False),
        sa.Column("report_version", sa.Integer(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("snapshot_digest", sa.String(length=64), nullable=False),
        sa.Column("snapshot_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("operation_status_at_generation", sa.String(length=32), nullable=False),
        sa.Column("assessment_completeness", sa.String(length=16), nullable=False),
        sa.Column("headline_status", sa.String(length=32), nullable=False),
        sa.Column("findings_total", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("findings_open", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("findings_resolved", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("regression_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "coverage_limitation_count", sa.Integer(), nullable=False, server_default="0"
        ),
        sa.Column(
            "severity_counts",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "generated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        # RESTRICT: a delivered report must not be destroyed by deleting its source rows.
        sa.ForeignKeyConstraint(
            ["target_id"], ["authorized_targets.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(["operation_id"], ["operations.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"], ondelete="RESTRICT"),
        sa.UniqueConstraint(
            "operation_id", "report_version", name="uq_assessment_report_operation_version"
        ),
        sa.CheckConstraint(
            "assessment_completeness IN ('complete', 'incomplete')",
            name="ck_assessment_report_completeness",
        ),
        sa.CheckConstraint(
            "headline_status IN ('assessment_incomplete', 'action_required', "
            "'attention_recommended', 'no_open_supported_findings')",
            name="ck_assessment_report_headline_status",
        ),
        sa.CheckConstraint("report_version >= 1", name="ck_assessment_report_version_positive"),
    )
    op.create_index(
        "ix_assessment_reports_organization_id", "assessment_reports", ["organization_id"]
    )
    op.create_index("ix_assessment_reports_target_id", "assessment_reports", ["target_id"])
    op.create_index("ix_assessment_reports_operation_id", "assessment_reports", ["operation_id"])
    op.create_index(
        "ix_assessment_reports_snapshot_digest", "assessment_reports", ["snapshot_digest"]
    )
    op.create_index(
        "ix_assessment_reports_org_generated_at",
        "assessment_reports",
        ["organization_id", "generated_at"],
    )
    op.create_index(
        "ix_assessment_reports_target_generated_at",
        "assessment_reports",
        ["target_id", "generated_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_assessment_reports_target_generated_at", table_name="assessment_reports")
    op.drop_index("ix_assessment_reports_org_generated_at", table_name="assessment_reports")
    op.drop_index("ix_assessment_reports_snapshot_digest", table_name="assessment_reports")
    op.drop_index("ix_assessment_reports_operation_id", table_name="assessment_reports")
    op.drop_index("ix_assessment_reports_target_id", table_name="assessment_reports")
    op.drop_index("ix_assessment_reports_organization_id", table_name="assessment_reports")
    op.drop_table("assessment_reports")
