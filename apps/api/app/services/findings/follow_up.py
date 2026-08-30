"""Mutate Finding ownership and follow-up due date (Milestone 33)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import UUID, uuid4

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from app.models.finding import Finding
from app.models.finding_follow_up import FindingFollowUpChange
from app.models.organization import Organization
from app.models.user import User
from app.schemas.finding_follow_up import FindingFollowUpResponse, FindingOwnerResponse
from app.services.audit import record_audit
from app.services.authorization import AuthorizedOrgActor, assert_actor_org, merge_auth_audit
from app.services.clerk import ClerkDirectory
from app.services.organization_members import (
    assert_assignable_org_member,
    clerk_user_is_org_member,
)


def canonicalize_due_at(value: datetime | None) -> datetime | None:
    """Require aware input (enforced by schema); persist UTC instant."""
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        raise HTTPException(
            status_code=422,
            detail="follow_up_due_at must be timezone-aware",
        )
    return value.astimezone(timezone.utc)


def due_instants_equal(left: datetime | None, right: datetime | None) -> bool:
    if left is None and right is None:
        return True
    if left is None or right is None:
        return False
    return canonicalize_due_at(left) == canonicalize_due_at(right)


def build_owner_response(
    *,
    user: User | None,
    current_member: bool,
) -> FindingOwnerResponse | None:
    if user is None:
        return None
    return FindingOwnerResponse(
        user_id=user.id,
        display_name=user.name,
        current_member=current_member,
    )


def resolve_follow_up_response(
    db: Session,
    *,
    directory: ClerkDirectory,
    organization: Organization,
    assigned_to_user_id: UUID | None,
    follow_up_due_at: datetime | None,
) -> FindingFollowUpResponse:
    if assigned_to_user_id is None:
        return FindingFollowUpResponse(owner=None, follow_up_due_at=follow_up_due_at)
    user = db.get(User, assigned_to_user_id)
    if user is None:
        # FK should prevent this; treat as unassigned presentation rather than inventing.
        return FindingFollowUpResponse(owner=None, follow_up_due_at=follow_up_due_at)
    try:
        current_member = clerk_user_is_org_member(
            directory,
            clerk_user_id=user.clerk_user_id,
            clerk_org_id=organization.clerk_org_id,
        )
    except Exception:
        # Fail closed on membership presentation: treat as not current.
        current_member = False
    return FindingFollowUpResponse(
        owner=build_owner_response(user=user, current_member=current_member),
        follow_up_due_at=follow_up_due_at,
    )


def batch_owner_membership(
    directory: ClerkDirectory,
    *,
    organization: Organization,
    users: dict[UUID, User],
) -> dict[UUID, bool]:
    """Map user_id → current_member using authoritative Clerk memberships."""
    result: dict[UUID, bool] = {}
    for user_id, user in users.items():
        try:
            result[user_id] = clerk_user_is_org_member(
                directory,
                clerk_user_id=user.clerk_user_id,
                clerk_org_id=organization.clerk_org_id,
            )
        except Exception:
            result[user_id] = False
    return result


@dataclass(frozen=True)
class FollowUpMutationResult:
    finding: Finding
    follow_up: FindingFollowUpResponse
    changed: bool


def update_finding_follow_up(
    db: Session,
    *,
    finding_id: UUID,
    actor: AuthorizedOrgActor,
    directory: ClerkDirectory,
    assigned_to_user_id: UUID | None,
    follow_up_due_at: datetime | None,
) -> FollowUpMutationResult:
    locked = db.scalar(
        select(Finding).where(Finding.id == finding_id).with_for_update()
    )
    if locked is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    assert_actor_org(actor, locked.organization_id, not_found="Finding not found")
    if locked.status == "resolved":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Resolved findings cannot change follow-up ownership or due date",
        )

    organization = db.get(Organization, locked.organization_id)
    if organization is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")

    if assigned_to_user_id is not None:
        assert_assignable_org_member(
            db,
            directory=directory,
            organization=organization,
            user_id=assigned_to_user_id,
        )

    requested_due = canonicalize_due_at(follow_up_due_at)
    same_owner = locked.assigned_to_user_id == assigned_to_user_id
    same_due = due_instants_equal(locked.follow_up_due_at, requested_due)
    if same_owner and same_due:
        follow_up = resolve_follow_up_response(
            db,
            directory=directory,
            organization=organization,
            assigned_to_user_id=locked.assigned_to_user_id,
            follow_up_due_at=locked.follow_up_due_at,
        )
        return FollowUpMutationResult(
            finding=locked, follow_up=follow_up, changed=False
        )

    change = FindingFollowUpChange(
        id=uuid4(),
        organization_id=locked.organization_id,
        finding_id=locked.id,
        changed_by_user_id=actor.user_id,
        previous_assigned_to_user_id=locked.assigned_to_user_id,
        new_assigned_to_user_id=assigned_to_user_id,
        previous_due_at=locked.follow_up_due_at,
        new_due_at=requested_due,
    )
    db.add(change)
    # Keep Finding.updated_at stable: ownership/due are operational workflow
    # fields and must not alone version assessment report digests.
    # Column.onupdate would otherwise fire because an unchanged timestamp is
    # omitted from SET; flag_modified forces the prior value into the UPDATE.
    previous_updated_at = locked.updated_at
    locked.assigned_to_user_id = assigned_to_user_id
    locked.follow_up_due_at = requested_due
    locked.updated_at = previous_updated_at
    flag_modified(locked, "updated_at")
    record_audit(
        db,
        organization_id=locked.organization_id,
        actor_type="user",
        actor_user_id=actor.user_id,
        action="finding.follow_up_changed",
        resource_type="finding_follow_up_change",
        resource_id=change.id,
        summary=f"Follow-up changed for finding: {locked.title}",
        metadata=merge_auth_audit(
            actor,
            {
                "finding_id": str(locked.id),
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
    db.commit()
    db.refresh(locked)
    follow_up = resolve_follow_up_response(
        db,
        directory=directory,
        organization=organization,
        assigned_to_user_id=locked.assigned_to_user_id,
        follow_up_due_at=locked.follow_up_due_at,
    )
    return FollowUpMutationResult(finding=locked, follow_up=follow_up, changed=True)
