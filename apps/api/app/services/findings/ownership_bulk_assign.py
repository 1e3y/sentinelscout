"""Atomic bulk Finding ownership assignment (Milestone 49).

Do not call the M33 follow-up mutator: that helper replaces owner and due
and commits internally. M49 changes owner only, preserves due dates, and uses
one domain commit after Clerk verification and Finding FOR UPDATE.
"""

from __future__ import annotations

from uuid import UUID, uuid4

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from app.models.finding import OPEN_FINDING_STATUSES, Finding
from app.models.finding_follow_up import FindingFollowUpChange
from app.models.organization import Organization
from app.schemas.finding_ownership_bulk_assign import (
    BulkOwnershipAssignItem,
    BulkOwnershipAssignResponse,
)
from app.services.audit import record_audit
from app.services.authorization import AuthorizedOrgActor, merge_auth_audit
from app.services.clerk import ClerkDirectory
from app.services.findings.follow_up import due_instants_equal
from app.services.organization_members import (
    verify_assignable_org_member,
    warm_local_org_membership,
)

INACTIVE_DETAIL = "Selected findings are no longer active. Refresh and try again."
CHANGED_DETAIL = "Selected findings changed. Refresh and try again."


def bulk_assign_finding_ownership(
    db: Session,
    *,
    organization: Organization,
    actor: AuthorizedOrgActor,
    directory: ClerkDirectory,
    assigned_to_user_id: UUID,
    items: list[BulkOwnershipAssignItem],
) -> BulkOwnershipAssignResponse:
    by_id = {item.finding_id: item for item in items}
    finding_ids = sorted(by_id)

    assignee = verify_assignable_org_member(
        db,
        directory=directory,
        organization=organization,
        user_id=assigned_to_user_id,
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
        ).all()
    )
    if len(locked_rows) != len(finding_ids):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found",
        )

    for row in locked_rows:
        if row.status not in OPEN_FINDING_STATUSES:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=INACTIVE_DETAIL,
            )
        expected = by_id[row.id].expected_follow_up
        same_owner = row.assigned_to_user_id == expected.assigned_to_user_id
        same_due = due_instants_equal(row.follow_up_due_at, expected.follow_up_due_at)
        if not same_owner or not same_due:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=CHANGED_DETAIL,
            )

    warm_local_org_membership(
        db,
        organization=organization,
        user=assignee,
    )

    changed_count = 0
    unchanged_count = 0
    for row in locked_rows:
        if row.assigned_to_user_id == assigned_to_user_id:
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
            new_due_at=row.follow_up_due_at,
        )
        db.add(change)
        previous_updated_at = row.updated_at
        row.assigned_to_user_id = assigned_to_user_id
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
                    "new_assigned_to_user_id": (
                        str(change.new_assigned_to_user_id)
                        if change.new_assigned_to_user_id
                        else None
                    ),
                    "previous_due_at": (
                        change.previous_due_at.isoformat()
                        if change.previous_due_at is not None
                        else None
                    ),
                    "new_due_at": (
                        change.new_due_at.isoformat()
                        if change.new_due_at is not None
                        else None
                    ),
                },
            ),
        )
        changed_count += 1

    db.commit()
    return BulkOwnershipAssignResponse(
        selected_count=len(locked_rows),
        changed_count=changed_count,
        unchanged_count=unchanged_count,
    )
