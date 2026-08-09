"""Finding remediation lifecycle transitions.

Resolved is set only by a passing RetestAttempt (see retest_runtime).
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.finding import ALLOWED_REMEDIATION_TRANSITIONS, Finding
from app.models.operation import Operation
from app.models.organization import OrganizationMembership
from app.services.audit import record_audit
from app.services.operations import append_event


def _require_org_membership(db: Session, *, user_id: UUID, organization_id: UUID) -> None:
    membership = db.scalar(
        select(OrganizationMembership).where(
            OrganizationMembership.user_id == user_id,
            OrganizationMembership.organization_id == organization_id,
        )
    )
    if membership is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")


def get_finding_or_404(db: Session, *, finding_id: UUID, user_id: UUID) -> Finding:
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    _require_org_membership(
        db, user_id=user_id, organization_id=finding.organization_id
    )
    return finding


def list_findings_for_user(db: Session, *, user_id: UUID) -> list[Finding]:
    org_ids = set(
        db.scalars(
            select(OrganizationMembership.organization_id).where(
                OrganizationMembership.user_id == user_id
            )
        ).all()
    )
    if not org_ids:
        return []
    return list(
        db.scalars(
            select(Finding)
            .where(Finding.organization_id.in_(org_ids))
            .order_by(Finding.created_at.desc())
        ).all()
    )


def _transition(
    db: Session,
    *,
    finding: Finding,
    target_status: str,
    event_type: str,
    summary: str,
    actor_user_id: UUID,
) -> Finding:
    allowed = ALLOWED_REMEDIATION_TRANSITIONS.get(finding.status, frozenset())
    if target_status == "resolved":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Resolved status requires a successful retest",
        )
    if target_status not in allowed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot transition finding from '{finding.status}' to '{target_status}'",
        )

    previous = finding.status
    finding.status = target_status
    finding.updated_at = datetime.now(timezone.utc)
    operation = db.get(Operation, finding.operation_id)
    if operation is not None:
        append_event(
            db,
            operation,
            event_type=event_type,
            summary=summary,
            metadata={
                "finding_id": str(finding.id),
                "candidate_id": str(finding.candidate_id),
                "asset_id": str(finding.asset_id),
                "status": finding.status,
                "severity": finding.severity,
            },
        )
    record_audit(
        db,
        organization_id=finding.organization_id,
        actor_type="user",
        actor_user_id=actor_user_id,
        action=event_type,
        resource_type="finding",
        resource_id=finding.id,
        summary=summary,
        metadata={
            "finding_id": str(finding.id),
            "candidate_id": str(finding.candidate_id),
            "asset_id": str(finding.asset_id),
            "operation_id": str(finding.operation_id),
            "previous_status": previous,
            "new_status": finding.status,
            "severity": finding.severity,
        },
    )
    db.commit()
    db.refresh(finding)
    return finding


def start_remediation(db: Session, *, finding_id: UUID, user_id: UUID) -> Finding:
    finding = get_finding_or_404(db, finding_id=finding_id, user_id=user_id)
    return _transition(
        db,
        finding=finding,
        target_status="in_progress",
        event_type="finding.remediation_started",
        summary=f"Remediation started for finding: {finding.title}",
        actor_user_id=user_id,
    )


def mark_ready_for_retest(db: Session, *, finding_id: UUID, user_id: UUID) -> Finding:
    finding = get_finding_or_404(db, finding_id=finding_id, user_id=user_id)
    return _transition(
        db,
        finding=finding,
        target_status="ready_for_retest",
        event_type="finding.ready_for_retest",
        summary=f"Finding marked ready for retest: {finding.title}",
        actor_user_id=user_id,
    )
