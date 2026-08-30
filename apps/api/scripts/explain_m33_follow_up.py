"""Measure M30/M32 EXPLAIN for Milestone 33 index decisions."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.core.db import Base
from app.models.asset import Asset
from app.models.candidate import SecurityCandidate
from app.models.finding import Finding
from app.models.finding_follow_up import FindingFollowUpChange
from app.models.operation import Operation
from app.models.organization import Organization, OrganizationMembership
from app.models.target import AuthorizedTarget
from app.models.user import User
from app.models.validation import ValidationAttempt
from app.services.findings.timeline import _timeline_statement
from app.services.findings_inbox import _page_statement


def main() -> None:
    settings = get_settings()
    engine = create_engine(settings.database_url)
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    db: Session = SessionLocal()
    try:
        org = Organization(clerk_org_id=f"org_{uuid4().hex}", name="Explain Org")
        user = User(
            clerk_user_id=f"user_{uuid4().hex}",
            email="explain@example.com",
            email_verified=True,
            name="Explain User",
        )
        db.add_all([org, user])
        db.flush()
        db.add(
            OrganizationMembership(
                organization_id=org.id, user_id=user.id, role="org:admin"
            )
        )
        base = datetime.now(UTC)
        findings: list[Finding] = []
        for index in range(80):
            target = AuthorizedTarget(
                organization_id=org.id,
                created_by_user_id=user.id,
                domain=f"explain-{index:03d}.example",
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
                completed_at=base,
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
                title=f"Finding {index}",
                summary="x",
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
                title=f"Finding {index}",
                summary="x",
                severity="medium",
                status="open",
                business_impact="x",
                remediation_guidance="x",
                evidence={},
                assigned_to_user_id=user.id if index % 3 == 0 else None,
                follow_up_due_at=base + timedelta(days=1) if index % 5 == 0 else None,
                created_at=base - timedelta(minutes=index),
            )
            db.add(finding)
            findings.append(finding)
        db.flush()
        for index, finding in enumerate(findings[:40]):
            db.add(
                FindingFollowUpChange(
                    organization_id=org.id,
                    finding_id=finding.id,
                    changed_by_user_id=user.id,
                    previous_assigned_to_user_id=None,
                    new_assigned_to_user_id=user.id,
                    previous_due_at=None,
                    new_due_at=base,
                    created_at=base - timedelta(minutes=index),
                )
            )
        db.commit()

        cases = {
            "m30_default": _page_statement(
                organization_id=org.id,
                size=50,
                cursor=None,
                finding_status=None,
                severity=None,
                target_id=None,
                retest_state=None,
                assigned_to_user_id=None,
                unassigned=None,
            ),
            "m30_assigned": _page_statement(
                organization_id=org.id,
                size=50,
                cursor=None,
                finding_status=None,
                severity=None,
                target_id=None,
                retest_state=None,
                assigned_to_user_id=user.id,
                unassigned=None,
            ),
            "m30_unassigned": _page_statement(
                organization_id=org.id,
                size=50,
                cursor=None,
                finding_status=None,
                severity=None,
                target_id=None,
                retest_state=None,
                assigned_to_user_id=None,
                unassigned=True,
            ),
            "m32_timeline": _timeline_statement(
                finding_id=findings[0].id,
                organization_id=org.id,
                promoted_at=findings[0].created_at,
                size=50,
                cursor_position=None,
            ),
        }
        for name, statement in cases.items():
            compiled = statement.compile(
                dialect=engine.dialect, compile_kwargs={"literal_binds": True}
            )
            print(f"\n===== {name} =====")
            print(compiled)
            rows = db.execute(text(f"EXPLAIN (FORMAT TEXT) {compiled}")).fetchall()
            for row in rows:
                print(row[0])
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


if __name__ == "__main__":
    main()
