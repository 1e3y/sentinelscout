"""Measure M35 reminder status/history EXPLAIN for index decision."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from app.core.db import Base
from app.core.config import get_settings
from app.models import *  # noqa: F401,F403
from app.models.asset import Asset
from app.models.candidate import SecurityCandidate
from app.models.finding import Finding
from app.models.finding_follow_up import FindingFollowUpChange
from app.models.finding_follow_up_reminder import FindingFollowUpReminderJob
from app.models.operation import Operation
from app.models.organization import Organization, OrganizationMembership
from app.models.target import AuthorizedTarget
from app.models.user import User
from app.models.validation import ValidationAttempt


def main() -> None:
    settings = get_settings()
    engine = create_engine(settings.database_url)
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    db: Session = SessionLocal()
    try:
        org = Organization(clerk_org_id=f"org_{uuid4().hex}", name="M35")
        user = User(
            clerk_user_id=f"user_{uuid4().hex}",
            email="m35@example.com",
            email_verified=True,
            name="M35",
        )
        db.add_all([org, user])
        db.flush()
        db.add(
            OrganizationMembership(
                organization_id=org.id, user_id=user.id, role="org:admin"
            )
        )
        target = AuthorizedTarget(
            organization_id=org.id,
            created_by_user_id=user.id,
            domain="m35.example",
            status="verified",
        )
        db.add(target)
        db.flush()
        operation = Operation(
            organization_id=org.id,
            target_id=target.id,
            created_by_user_id=user.id,
            status="completed",
            source="manual",
            completed_at=datetime.now(UTC),
        )
        db.add(operation)
        db.flush()
        asset = Asset(
            organization_id=org.id,
            target_id=target.id,
            hostname=target.domain,
            url=f"https://{target.domain}",
        )
        db.add(asset)
        db.flush()
        candidate = SecurityCandidate(
            organization_id=org.id,
            operation_id=operation.id,
            asset_id=asset.id,
            candidate_type="staging_dev_exposed",
            title="t",
            summary="s",
            status="supported",
            evidence={},
        )
        db.add(candidate)
        db.flush()
        db.add(
            ValidationAttempt(
                organization_id=org.id,
                operation_id=operation.id,
                candidate_id=candidate.id,
                asset_id=asset.id,
                status="supported",
                validation_method="http_recheck",
                summary="ok",
                evidence={},
            )
        )
        finding = Finding(
            organization_id=org.id,
            operation_id=operation.id,
            candidate_id=candidate.id,
            asset_id=asset.id,
            title="t",
            summary="s",
            severity="medium",
            status="open",
            business_impact="x",
            remediation_guidance="x",
            evidence={},
            assigned_to_user_id=user.id,
            follow_up_due_at=datetime.now(UTC) - timedelta(hours=1),
        )
        db.add(finding)
        db.flush()
        base = datetime.now(UTC)
        for i in range(30):
            change = FindingFollowUpChange(
                organization_id=org.id,
                finding_id=finding.id,
                changed_by_user_id=user.id,
                previous_assigned_to_user_id=None,
                new_assigned_to_user_id=user.id,
                previous_due_at=None,
                new_due_at=finding.follow_up_due_at,
                created_at=base - timedelta(minutes=i),
            )
            db.add(change)
            db.flush()
            db.add(
                FindingFollowUpReminderJob(
                    organization_id=org.id,
                    finding_id=finding.id,
                    follow_up_change_id=change.id,
                    assigned_to_user_id=user.id,
                    due_at=finding.follow_up_due_at,
                    reminder_kind="due",
                    status="delivered" if i else "pending",
                    available_at=finding.follow_up_due_at,
                    attempt_count=1,
                    created_at=base - timedelta(minutes=i),
                    delivered_at=base - timedelta(minutes=i) if i else None,
                )
            )
        db.commit()

        current_sql = text(
            """
            EXPLAIN (FORMAT TEXT)
            SELECT id, status, last_error_code, created_at, delivered_at
            FROM finding_follow_up_reminder_jobs
            WHERE finding_id = :fid
              AND follow_up_change_id = :cid
              AND reminder_kind = 'due'
            """
        )
        history_sql = text(
            """
            EXPLAIN (FORMAT TEXT)
            SELECT id, status, last_error_code, created_at, delivered_at,
                   assigned_to_user_id, due_at, reminder_kind
            FROM finding_follow_up_reminder_jobs
            WHERE finding_id = :fid
            ORDER BY created_at DESC, id DESC
            LIMIT 21
            """
        )
        latest = db.scalar(
            text(
                "SELECT follow_up_change_id FROM finding_follow_up_reminder_jobs "
                "WHERE finding_id = :fid ORDER BY created_at DESC LIMIT 1"
            ),
            {"fid": finding.id},
        )
        print("===== current generation lookup =====")
        for row in db.execute(
            current_sql, {"fid": finding.id, "cid": latest}
        ):
            print(row[0])
        print("===== history first page =====")
        for row in db.execute(history_sql, {"fid": finding.id}):
            print(row[0])
    finally:
        db.close()
        engine.dispose()


if __name__ == "__main__":
    main()
