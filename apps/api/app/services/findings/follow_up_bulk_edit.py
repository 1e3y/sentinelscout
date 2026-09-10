"""Atomic bulk Finding follow-up owner and due-date update (Milestone 52)."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from app.models.finding import OPEN_FINDING_STATUSES, Finding
from app.models.finding_follow_up import FindingFollowUpChange
from app.models.organization import Organization
from app.schemas.finding_follow_up_bulk_edit import (
    BulkFollowUpEditItem,
    BulkFollowUpEditResponse,
)
from app.services.audit import record_audit
from app.services.authorization import AuthorizedOrgActor, merge_auth_audit
from app.services.clerk import ClerkDirectory
from app.services.findings.follow_up import canonicalize_due_at, due_instants_equal
from app.services.organization_members import verify_assignable_org_member

INACTIVE_DETAIL = "Selected findings are no longer active. Refresh and try again."
CHANGED_DETAIL = "Selected findings changed. Refresh and try again."
MEMBERSHIP_FAILURE_DETAIL = "Failed to verify organization membership"


def _validate_rows(
    rows: list[Finding],
    *,
    by_id: dict[UUID, BulkFollowUpEditItem],
    expected_count: int,
) -> None:
    if len(rows) != expected_count:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found",
        )
    for row in rows:
        if row.status not in OPEN_FINDING_STATUSES:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=INACTIVE_DETAIL,
            )
        expected = by_id[row.id].expected_follow_up
        if row.assigned_to_user_id != expected.assigned_to_user_id or not due_instants_equal(
            row.follow_up_due_at,
            expected.follow_up_due_at,
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=CHANGED_DETAIL,
            )


def _verify_assignee(
    db: Session,
    *,
    directory: ClerkDirectory,
    organization: Organization,
    assigned_to_user_id: UUID,
) -> None:
    """Normalize only provider-verification gateway failures at the M52 boundary."""
    try:
        verify_assignable_org_member(
            db,
            directory=directory,
            organization=organization,
            user_id=assigned_to_user_id,
        )
    except HTTPException as exc:
        if exc.status_code != status.HTTP_502_BAD_GATEWAY:
            raise
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=MEMBERSHIP_FAILURE_DETAIL,
        ) from exc


def bulk_edit_finding_follow_up(
    db: Session,
    *,
    organization: Organization,
    actor: AuthorizedOrgActor,
    directory: ClerkDirectory,
    assigned_to_user_id: UUID,
    follow_up_due_at: datetime,
    items: list[BulkFollowUpEditItem],
) -> BulkFollowUpEditResponse:
    """Replace owner and due after preflight, provider verification, and locked recheck."""
    requested_due = canonicalize_due_at(follow_up_due_at)
    assert requested_due is not None
    by_id = {item.finding_id: item for item in items}
    finding_ids = sorted(by_id)

    preflight_rows = list(
        db.scalars(
            select(Finding)
            .where(
                Finding.id.in_(finding_ids),
                Finding.organization_id == organization.id,
            )
            .order_by(Finding.id.asc())
        ).all()
    )
    _validate_rows(
        preflight_rows,
        by_id=by_id,
        expected_count=len(finding_ids),
    )

    _verify_assignee(
        db,
        directory=directory,
        organization=organization,
        assigned_to_user_id=assigned_to_user_id,
    )

    locked_rows = list(
        db.scalars(
            select(Finding)
            .where(
                Finding.id.in_(finding_ids),
                Finding.organization_id == organization.id,
            )
            .order_by(Finding.id.asc())
            .with_for_update()
            .execution_options(populate_existing=True)
        ).all()
    )
    _validate_rows(
        locked_rows,
        by_id=by_id,
        expected_count=len(finding_ids),
    )

    changed_count = 0
    unchanged_count = 0
    try:
        for row in locked_rows:
            same_owner = row.assigned_to_user_id == assigned_to_user_id
            same_due = due_instants_equal(row.follow_up_due_at, requested_due)
            if same_owner and same_due:
                unchanged_count += 1
                continue

            change = FindingFollowUpChange(
                id=uuid4(),
                organization_id=row.organization_id,
                finding_id=row.id,
                changed_by_user_id=actor.user_id,
                previous_assigned_to_user_id=row.assigned_to_user_id,
                new_assigned_to_user_id=assigned_to_user_id,
                previous_due_at=row.follow_up_due_at,
                new_due_at=requested_due,
            )
            db.add(change)

            previous_updated_at = row.updated_at
            row.assigned_to_user_id = assigned_to_user_id
            row.follow_up_due_at = requested_due
            row.updated_at = previous_updated_at
            flag_modified(row, "updated_at")

            record_audit(
                db,
                organization_id=row.organization_id,
                actor_type="user",
                actor_user_id=actor.user_id,
                action="finding.follow_up_changed",
                resource_type="finding_follow_up_change",
                resource_id=change.id,
                summary=f"Follow-up changed for finding: {row.title}",
                metadata=merge_auth_audit(
                    actor,
                    {
                        "finding_id": str(row.id),
                        "follow_up_change_id": str(change.id),
                        "previous_assigned_to_user_id": (
                            str(change.previous_assigned_to_user_id)
                            if change.previous_assigned_to_user_id
                            else None
                        ),
                        "new_assigned_to_user_id": str(change.new_assigned_to_user_id),
                        "previous_due_at": (
                            change.previous_due_at.isoformat()
                            if change.previous_due_at is not None
                            else None
                        ),
                        "new_due_at": change.new_due_at.isoformat(),
                    },
                ),
            )
            changed_count += 1

        db.commit()
    except Exception:
        db.rollback()
        raise

    return BulkFollowUpEditResponse(
        selected_count=len(locked_rows),
        changed_count=changed_count,
        unchanged_count=unchanged_count,
    )
