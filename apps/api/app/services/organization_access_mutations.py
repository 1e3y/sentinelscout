"""Organization access mutations — provider-authoritative (Milestone 39).

Correction 1 — last-admin concurrency:
Clerk Backend API docs/OpenAPI for
``PATCH /organizations/{organization_id}/memberships/{user_id}`` and
``DELETE /organizations/{organization_id}/memberships/{user_id}`` do **not**
document an atomic last-administrator rejection. Frontend SDK UX (e.g. clerk-js
PR #1721 disabling the last-admin role toggle) is not a BAPI contract.

``LAST_ADMIN_PROVIDER_ATOMIC_GUARANTEE`` is therefore False. M39 rejects all
recognized-admin demotion and removal (including self). Member→admin and
removal of recognized ordinary members remain allowed.
"""

from __future__ import annotations

import logging
from typing import Literal
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.organization import Organization, OrganizationMembership
from app.models.user import User
from app.schemas.organization_access import OrganizationAccessMember
from app.schemas.organization_access_mutations import (
    LocalRecordingState,
    OrganizationMemberRemovalResponse,
    OrganizationMemberRoleUpdateResponse,
)
from app.services.audit import record_audit
from app.services.authorization import NormalizedRole, persistable_org_role
from app.services.clerk import (
    ClerkDirectory,
    ClerkMembershipNotFound,
    ClerkOrganizationMembershipRaw,
    OrganizationAccessWriteAmbiguous,
    OrganizationAccessWriteUnavailable,
)
from app.services.organization_access import (
    classify_provider_role,
    local_mirror_state_for,
    provider_display_name,
)

logger = logging.getLogger("scout.organization_access.mutations")

# Documented product policy switch (Correction 1).
LAST_ADMIN_PROVIDER_ATOMIC_GUARANTEE = False

MEMBER_NOT_FOUND_DETAIL = "Organization member not found."
UNRECOGNIZED_ROLE_DETAIL = (
    "Current organization role is not recognized by Sentinel Scout."
)
ADMIN_MUTATION_FORBIDDEN_DETAIL = (
    "Organization administrators cannot be demoted or removed."
)
UPDATE_UNAVAILABLE_DETAIL = "Organization access could not be updated."
AUDIT_ACTION_ROLE_CHANGED = "organization.member_role_changed"
AUDIT_ACTION_REMOVED = "organization.member_removed"
AUDIT_RESOURCE_TYPE = "organization_member"
AUDIT_PERSIST_ATTEMPTS = 3

MutationType = Literal["role_change", "removal"]


def raise_member_not_found() -> None:
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=MEMBER_NOT_FOUND_DETAIL,
    )


def raise_update_unavailable() -> None:
    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail=UPDATE_UNAVAILABLE_DETAIL,
    )


def _build_linked_member(
    db: Session,
    *,
    organization: Organization,
    user: User,
    raw: ClerkOrganizationMembershipRaw,
) -> OrganizationAccessMember:
    role, role_state = classify_provider_role(raw.external_role)
    local = db.scalar(
        select(OrganizationMembership).where(
            OrganizationMembership.organization_id == organization.id,
            OrganizationMembership.user_id == user.id,
        )
    )
    return OrganizationAccessMember(
        user_id=user.id,
        display_name=user.name or provider_display_name(raw),
        role=role,
        role_state=role_state,
        account_link_state="linked",
        local_mirror_state=local_mirror_state_for(
            account_link_state="linked",
            role=role,
            role_state=role_state,
            local_membership=local,
        ),
    )


def _resolve_linked_target_privately(
    db: Session,
    *,
    organization: Organization,
    directory: ClerkDirectory,
    target_user_id: UUID,
) -> tuple[User, ClerkOrganizationMembershipRaw, NormalizedRole | None, str]:
    """Resolve mutation target without cross-org presentation leakage.

    Returns (user, authoritative membership, recognized role or None, role_state).
    Uniform 404 for any non-mutable / non-current membership.
    """
    if not organization.clerk_org_id or not organization.clerk_org_id.strip():
        raise_update_unavailable()

    user = db.get(User, target_user_id)
    if user is None or not user.clerk_user_id:
        raise_member_not_found()

    try:
        raw = directory.get_organization_membership(
            organization.clerk_org_id,
            user.clerk_user_id,
        )
    except ClerkMembershipNotFound:
        raise_member_not_found()
    except OrganizationAccessWriteUnavailable:
        raise_update_unavailable()
    except OrganizationAccessWriteAmbiguous:
        # Pre-write verification must be definite.
        raise_update_unavailable()
    except HTTPException:
        raise_update_unavailable()
    except Exception:
        raise_update_unavailable()

    role, role_state = classify_provider_role(raw.external_role)
    return user, raw, role, role_state


def _reject_unrecognized(role_state: str) -> None:
    if role_state == "unrecognized":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=UNRECOGNIZED_ROLE_DETAIL,
        )


def _reject_recognized_admin_mutation(current_role: NormalizedRole | None) -> None:
    """Product policy when provider last-admin atomicity is unconfirmed."""
    if not LAST_ADMIN_PROVIDER_ATOMIC_GUARANTEE and current_role == "admin":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=ADMIN_MUTATION_FORBIDDEN_DETAIL,
        )


def _reconcile_role_after_ambiguous(
    directory: ClerkDirectory,
    *,
    clerk_org_id: str,
    clerk_user_id: str,
    requested: NormalizedRole,
) -> ClerkOrganizationMembershipRaw:
    try:
        raw = directory.get_organization_membership(clerk_org_id, clerk_user_id)
    except ClerkMembershipNotFound:
        raise_update_unavailable()
    except Exception:
        raise_update_unavailable()
    role, role_state = classify_provider_role(raw.external_role)
    if role_state != "recognized" or role != requested:
        raise_update_unavailable()
    return raw


def _reconcile_removal_after_ambiguous(
    directory: ClerkDirectory,
    *,
    clerk_org_id: str,
    clerk_user_id: str,
) -> None:
    try:
        directory.get_organization_membership(clerk_org_id, clerk_user_id)
    except ClerkMembershipNotFound:
        return
    except Exception:
        raise_update_unavailable()
    # Still present — write did not take effect (or cannot be confirmed as removed).
    raise_update_unavailable()


def _persist_audit_with_retry(
    db: Session,
    *,
    organization_id: UUID,
    actor_user_id: UUID,
    action: str,
    resource_id: UUID,
    summary: str,
    metadata: dict,
) -> bool:
    for _attempt in range(AUDIT_PERSIST_ATTEMPTS):
        try:
            record_audit(
                db,
                organization_id=organization_id,
                actor_type="user",
                actor_user_id=actor_user_id,
                action=action,
                resource_type=AUDIT_RESOURCE_TYPE,
                resource_id=resource_id,
                summary=summary,
                metadata=metadata,
                commit=True,
            )
            return True
        except Exception:
            try:
                db.rollback()
            except Exception:
                pass
    return False


def _emit_audit_degraded(
    *,
    organization_id: UUID,
    target_user_id: UUID,
    mutation_type: MutationType,
) -> None:
    logger.error(
        "organization_access_audit_degraded",
        extra={
            "organization_app_id": str(organization_id),
            "target_user_id": str(target_user_id),
            "mutation_type": mutation_type,
        },
    )


def _update_local_role_cache_if_present(
    db: Session,
    *,
    organization_id: UUID,
    user_id: UUID,
    role: NormalizedRole,
) -> None:
    try:
        row = db.scalar(
            select(OrganizationMembership).where(
                OrganizationMembership.organization_id == organization_id,
                OrganizationMembership.user_id == user_id,
            )
        )
        if row is None:
            return
        row.role = persistable_org_role(role)
        db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass


def _delete_local_membership_cache_if_present(
    db: Session,
    *,
    organization_id: UUID,
    user_id: UUID,
) -> None:
    try:
        row = db.scalar(
            select(OrganizationMembership).where(
                OrganizationMembership.organization_id == organization_id,
                OrganizationMembership.user_id == user_id,
            )
        )
        if row is None:
            return
        db.delete(row)
        db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass


def update_organization_member_role(
    db: Session,
    *,
    organization: Organization,
    directory: ClerkDirectory,
    actor_user_id: UUID,
    target_user_id: UUID,
    requested_role: NormalizedRole,
) -> OrganizationMemberRoleUpdateResponse:
    user, raw, current_role, role_state = _resolve_linked_target_privately(
        db,
        organization=organization,
        directory=directory,
        target_user_id=target_user_id,
    )
    _reject_unrecognized(role_state)
    assert current_role is not None

    # No-op: same recognized role — zero provider PATCH / audit / cache write.
    if current_role == requested_role:
        return OrganizationMemberRoleUpdateResponse(
            member=_build_linked_member(
                db, organization=organization, user=user, raw=raw
            ),
            local_recording_state="complete",
        )

    # Recognized admin demotion blocked without provider atomic last-admin guarantee.
    if current_role == "admin" and requested_role == "member":
        _reject_recognized_admin_mutation(current_role)

    assert organization.clerk_org_id is not None
    provider_role = persistable_org_role(requested_role)
    previous_role = current_role
    authoritative: ClerkOrganizationMembershipRaw

    try:
        authoritative = directory.update_organization_membership_role(
            organization.clerk_org_id,
            user.clerk_user_id,
            role=provider_role,
        )
    except ClerkMembershipNotFound:
        raise_member_not_found()
    except OrganizationAccessWriteAmbiguous:
        authoritative = _reconcile_role_after_ambiguous(
            directory,
            clerk_org_id=organization.clerk_org_id,
            clerk_user_id=user.clerk_user_id,
            requested=requested_role,
        )
    except OrganizationAccessWriteUnavailable:
        raise_update_unavailable()
    except Exception:
        raise_update_unavailable()

    # Prefer authoritative response role when sufficient; otherwise one readback.
    result_role, result_state = classify_provider_role(authoritative.external_role)
    if result_state != "recognized" or result_role != requested_role:
        try:
            authoritative = directory.get_organization_membership(
                organization.clerk_org_id,
                user.clerk_user_id,
            )
        except Exception:
            raise_update_unavailable()
        result_role, result_state = classify_provider_role(authoritative.external_role)
        if result_state != "recognized" or result_role != requested_role:
            raise_update_unavailable()

    audit_ok = _persist_audit_with_retry(
        db,
        organization_id=organization.id,
        actor_user_id=actor_user_id,
        action=AUDIT_ACTION_ROLE_CHANGED,
        resource_id=user.id,
        summary="Organization member role changed",
        metadata={
            "target_user_id": str(user.id),
            "previous_role": previous_role,
            "new_role": requested_role,
        },
    )
    recording: LocalRecordingState = "complete"
    if not audit_ok:
        recording = "audit_degraded"
        _emit_audit_degraded(
            organization_id=organization.id,
            target_user_id=user.id,
            mutation_type="role_change",
        )

    try:
        _update_local_role_cache_if_present(
            db,
            organization_id=organization.id,
            user_id=user.id,
            role=requested_role,
        )
    except Exception:
        pass

    return OrganizationMemberRoleUpdateResponse(
        member=_build_linked_member(
            db, organization=organization, user=user, raw=authoritative
        ),
        local_recording_state=recording,
    )


def remove_organization_member(
    db: Session,
    *,
    organization: Organization,
    directory: ClerkDirectory,
    actor_user_id: UUID,
    target_user_id: UUID,
) -> OrganizationMemberRemovalResponse:
    user, _raw, current_role, role_state = _resolve_linked_target_privately(
        db,
        organization=organization,
        directory=directory,
        target_user_id=target_user_id,
    )
    _reject_unrecognized(role_state)
    assert current_role is not None
    _reject_recognized_admin_mutation(current_role)

    assert organization.clerk_org_id is not None
    previous_role = current_role

    try:
        directory.delete_organization_membership(
            organization.clerk_org_id,
            user.clerk_user_id,
        )
    except ClerkMembershipNotFound:
        raise_member_not_found()
    except OrganizationAccessWriteAmbiguous:
        _reconcile_removal_after_ambiguous(
            directory,
            clerk_org_id=organization.clerk_org_id,
            clerk_user_id=user.clerk_user_id,
        )
    except OrganizationAccessWriteUnavailable:
        raise_update_unavailable()
    except Exception:
        raise_update_unavailable()

    audit_ok = _persist_audit_with_retry(
        db,
        organization_id=organization.id,
        actor_user_id=actor_user_id,
        action=AUDIT_ACTION_REMOVED,
        resource_id=user.id,
        summary="Organization member removed",
        metadata={
            "target_user_id": str(user.id),
            "previous_role": previous_role,
        },
    )
    recording: LocalRecordingState = "complete"
    if not audit_ok:
        recording = "audit_degraded"
        _emit_audit_degraded(
            organization_id=organization.id,
            target_user_id=user.id,
            mutation_type="removal",
        )

    try:
        _delete_local_membership_cache_if_present(
            db,
            organization_id=organization.id,
            user_id=user.id,
        )
    except Exception:
        pass

    return OrganizationMemberRemovalResponse(
        removed_user_id=user.id,
        local_recording_state=recording,
    )
