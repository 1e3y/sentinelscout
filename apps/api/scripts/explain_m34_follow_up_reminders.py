"""EXPLAIN helpers for Milestone 34 follow-up reminder discovery/claim.

Usage (from apps/api with DATABASE_URL set):

  uv run python -m scripts.explain_m34_follow_up_reminders
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import text
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.core.db import engine
from app.services.reports.summary import OPEN_FINDING_STATUSES


def _explain(db: Session, label: str, sql: str, params: dict) -> None:
    print(f"\n=== {label} ===")
    rows = db.execute(text(f"EXPLAIN (ANALYZE, BUFFERS) {sql}"), params).all()
    for row in rows:
        print(row[0])


def main() -> None:
    settings = get_settings()
    print(f"database={settings.database_url.split('@')[-1]}")
    SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        open_statuses = sorted(OPEN_FINDING_STATUSES)
        _explain(
            db,
            "discovery first batch (enabled orgs + due unresolved findings)",
            """
            SELECT f.id
            FROM findings f
            WHERE f.organization_id IN (
              SELECT organization_id
              FROM organization_notification_settings
              WHERE finding_follow_up_reminders_enabled = true
            )
              AND f.status = ANY(:statuses)
              AND f.assigned_to_user_id IS NOT NULL
              AND f.follow_up_due_at IS NOT NULL
              AND f.follow_up_due_at <= :now
            ORDER BY f.follow_up_due_at ASC, f.id ASC
            LIMIT 100
            """,
            {"statuses": open_statuses, "now": now},
        )
        _explain(
            db,
            "pending reminder claim candidate",
            """
            SELECT j.id
            FROM finding_follow_up_reminder_jobs j
            JOIN organization_notification_settings s
              ON s.organization_id = j.organization_id
            WHERE s.finding_follow_up_reminders_enabled = true
              AND (
                (j.status IN ('pending', 'failed') AND j.available_at <= :now)
                OR (
                  j.status = 'processing'
                  AND j.lease_expires_at IS NOT NULL
                  AND j.lease_expires_at <= :now
                )
              )
            ORDER BY j.available_at ASC
            LIMIT 1
            """,
            {"now": now},
        )
        _explain(
            db,
            "send-time current generation lookup",
            """
            SELECT c.id
            FROM finding_follow_up_changes c
            WHERE c.finding_id = (
              SELECT id FROM findings ORDER BY created_at DESC LIMIT 1
            )
            ORDER BY c.created_at DESC, c.id DESC
            LIMIT 1
            """,
            {},
        )
        print(
            "\nIndex decision: correctness UNIQUE + claim/lease partial indexes only."
            " Do not add findings eligibility index unless this EXPLAIN shows"
            " sequential scans that dominate at realistic volume."
        )
    finally:
        db.close()


if __name__ == "__main__":
    main()
