"""Insert-only assessment report generation.

Eligibility fails closed, authorization is asserted at the service boundary so a
future route cannot bypass it, and version allocation retries with the *same*
already-built content so a caller never receives a report whose digest differs
from the content it requested.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from fastapi import HTTPException, status
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.coverage import OperationCoverageSummary
from app.models.diff import OperationDiffSummary
from app.models.operation import Operation
from app.models.organization import Organization, OrganizationMembership
from app.models.report import REPORT_SCHEMA_VERSION, AssessmentReport
from app.services.audit import record_audit
from app.services.authorization import AuthorizedOrgActor, assert_admin_actor, merge_auth_audit
from app.services.coverage import TERMINAL_STATUSES
from app.services.operation_controls import get_control_snapshot
from app.services.operations import get_operation_or_404
from app.services.reports.snapshot import build_report_content, content_digest

MAX_VERSION_ALLOCATION_ATTEMPTS = 5

NOT_FOUND_DETAIL = "Operation not found"
REPORT_NOT_FOUND_DETAIL = "Assessment report not found"


def _conflict(detail: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_409_CONFLICT, detail=detail)


def _latest_report(db: Session, operation_id: UUID) -> AssessmentReport | None:
    return db.scalar(
        select(AssessmentReport)
        .where(AssessmentReport.operation_id == operation_id)
        .order_by(AssessmentReport.report_version.desc())
        .limit(1)
    )


def _member_org_ids(db: Session, user_id: UUID) -> set[UUID]:
    return set(
        db.scalars(
            select(OrganizationMembership.organization_id).where(
                OrganizationMembership.user_id == user_id
            )
        ).all()
    )


def _insert_report(
    db: Session,
    *,
    operation: Operation,
    actor: AuthorizedOrgActor,
    version: int,
    digest: str,
    content: dict[str, Any],
) -> AssessmentReport:
    summary = content["summary"]
    report_id = uuid4()
    generated_at = datetime.now(UTC)
    report = AssessmentReport(
        id=report_id,
        organization_id=operation.organization_id,
        target_id=operation.target_id,
        operation_id=operation.id,
        created_by_user_id=actor.user_id,
        target_domain=str(content["identity"]["target_domain"]),
        report_version=version,
        schema_version=REPORT_SCHEMA_VERSION,
        snapshot_digest=digest,
        snapshot_json={
            "report_schema_version": REPORT_SCHEMA_VERSION,
            # Envelope is deliberately excluded from the digest.
            "envelope": {
                "report_id": str(report_id),
                "report_version": version,
                "snapshot_digest": digest,
                "generated_at": generated_at.isoformat(),
                "generated_by": {"user_id": str(actor.user_id)},
            },
            "content": content,
        },
        operation_status_at_generation=operation.status,
        assessment_completeness=summary["assessment_completeness"],
        headline_status=summary["headline_status"],
        findings_total=int(summary["findings_total"]),
        findings_open=int(summary["findings_open"]),
        findings_resolved=int(summary["findings_resolved"]),
        regression_count=int(summary["regression_count"]),
        coverage_limitation_count=int(summary["coverage_limitation_count"]),
        severity_counts=dict(summary["severity_counts_open"]),
        generated_at=generated_at,
    )
    db.add(report)
    db.flush()
    return report


def generate_assessment_report(
    db: Session,
    *,
    operation_id: UUID,
    actor: AuthorizedOrgActor,
) -> tuple[AssessmentReport, bool]:
    """Return (report, created). Isolation 404 precedes the admin 403."""
    operation = get_operation_or_404(db, operation_id=operation_id, user_id=actor.user_id)
    assert_admin_actor(actor, operation.organization_id, not_found=NOT_FOUND_DETAIL)

    if operation.status not in TERMINAL_STATUSES:
        raise _conflict("Operation has not reached a reportable state")

    control_snapshot = get_control_snapshot(db, operation_id=operation.id)
    if control_snapshot is None:
        raise _conflict("Operation control snapshot is not available")

    coverage_row = db.scalar(
        select(OperationCoverageSummary).where(
            OperationCoverageSummary.operation_id == operation.id
        )
    )
    if coverage_row is None:
        # Fail closed. Report generation never creates or repairs coverage.
        raise _conflict("Operation coverage snapshot is not available")

    organization = db.get(Organization, operation.organization_id)
    if organization is None:
        raise _conflict("Operation organization is not available")

    diff_row = db.scalar(
        select(OperationDiffSummary).where(
            OperationDiffSummary.operation_id == operation.id
        )
    )

    content = build_report_content(
        db,
        operation,
        organization=organization,
        control_snapshot=control_snapshot,
        coverage_row=coverage_row,
        diff_row=diff_row,
    )
    digest = content_digest(content)

    # Serialize version allocation for this operation. Retry still compares digest
    # so a concurrent insert of different content cannot be returned as ours.
    db.execute(
        text("SELECT pg_advisory_xact_lock(hashtext(:lock_key))"),
        {"lock_key": f"assessment_report:{operation.id}"},
    )

    for _ in range(MAX_VERSION_ALLOCATION_ATTEMPTS):
        latest = _latest_report(db, operation.id)
        if latest is not None and latest.snapshot_digest == digest:
            db.commit()
            db.refresh(latest)
            return latest, False

        next_version = (latest.report_version + 1) if latest is not None else 1
        try:
            with db.begin_nested():
                report = _insert_report(
                    db,
                    operation=operation,
                    actor=actor,
                    version=next_version,
                    digest=digest,
                    content=content,
                )
        except IntegrityError:
            # Another generation won this version number. Re-read and compare the
            # same digest rather than trusting whatever landed.
            db.expire_all()
            continue

        record_audit(
            db,
            organization_id=operation.organization_id,
            actor_type="user",
            actor_user_id=actor.user_id,
            action="assessment_report.generated",
            resource_type="assessment_report",
            resource_id=report.id,
            summary="Assessment report generated.",
            metadata=merge_auth_audit(
                actor,
                {
                    "report_id": str(report.id),
                    "report_version": report.report_version,
                    "schema_version": report.schema_version,
                    "snapshot_digest": report.snapshot_digest,
                    "operation_id": str(operation.id),
                    "target_id": str(operation.target_id),
                    "operation_status": operation.status,
                    "headline_status": report.headline_status,
                    "assessment_completeness": report.assessment_completeness,
                    "findings_total": report.findings_total,
                    "findings_open": report.findings_open,
                },
            ),
        )
        db.commit()
        db.refresh(report)
        return report, True

    raise _conflict(
        "Assessment report generation could not allocate a version. Try again."
    )


def list_assessment_reports(
    db: Session,
    *,
    user_id: UUID,
    target_id: UUID | None = None,
    operation_id: UUID | None = None,
    limit: int = 100,
) -> list[AssessmentReport]:
    org_ids = _member_org_ids(db, user_id)
    if not org_ids:
        return []
    stmt = (
        select(AssessmentReport)
        .where(AssessmentReport.organization_id.in_(org_ids))
        .order_by(
            AssessmentReport.generated_at.desc(),
            AssessmentReport.report_version.desc(),
        )
        .limit(min(max(limit, 1), 500))
    )
    if target_id is not None:
        stmt = stmt.where(AssessmentReport.target_id == target_id)
    if operation_id is not None:
        stmt = stmt.where(AssessmentReport.operation_id == operation_id)
    return list(db.scalars(stmt).all())


def list_operation_assessment_reports(
    db: Session,
    *,
    operation_id: UUID,
    user_id: UUID,
) -> list[AssessmentReport]:
    operation = get_operation_or_404(db, operation_id=operation_id, user_id=user_id)
    return list(
        db.scalars(
            select(AssessmentReport)
            .where(AssessmentReport.operation_id == operation.id)
            .order_by(AssessmentReport.report_version.asc())
        ).all()
    )


def get_assessment_report_or_404(
    db: Session,
    *,
    report_id: UUID,
    user_id: UUID,
) -> AssessmentReport:
    """Reads touch only assessment_reports; historical snapshots never re-join live state."""
    report = db.get(AssessmentReport, report_id)
    if report is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=REPORT_NOT_FOUND_DETAIL
        )
    membership = db.scalar(
        select(OrganizationMembership).where(
            OrganizationMembership.user_id == user_id,
            OrganizationMembership.organization_id == report.organization_id,
        )
    )
    if membership is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=REPORT_NOT_FOUND_DETAIL
        )
    return report
