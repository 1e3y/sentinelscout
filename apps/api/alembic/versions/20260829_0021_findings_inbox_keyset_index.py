"""findings inbox keyset index

Revision ID: 20260829_0021
Revises: 20260826_0020
Create Date: 2026-08-29 16:05:00.000000

Supports the M30 findings inbox keyset page, which filters on organization_id and
orders by created_at DESC, id DESC. Measured on 6,000 findings in one organization
(24,000 total, 10,800 retest attempts):

                        without index          with index
  page (no filter)      18.4 ms /   836 buf    0.15 ms /  333 buf
  retest_state=none     16.3 ms / 10417 buf    0.20 ms /  199 buf
  retest_state=failed   27.6 ms / 14645 buf    2.57 ms / 3049 buf
  retest_state=passed   24.0 ms / 14645 buf    1.84 ms / 1893 buf

Without it every branch scans and sorts all of the organization's findings; with
it the work is bounded by the page. No other schema object is added.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "20260829_0021"
down_revision: str | Sequence[str] | None = "20260826_0020"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index(
        "ix_findings_org_created_at_id",
        "findings",
        ["organization_id", "created_at", "id"],
        unique=False,
        postgresql_ops={"created_at": "DESC", "id": "DESC"},
    )


def downgrade() -> None:
    op.drop_index("ix_findings_org_created_at_id", table_name="findings")
