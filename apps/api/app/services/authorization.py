"""Verified organization authorization context for human mutations.

Grant path is the verified JWT active-org role, after known Clerk encodings
are normalized. Fresh Clerk directory memberships fetched on the same request
may veto an admin grant; they never elevate a member or unknown JWT role.
OrganizationMembership.role is never the grant source.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal
from uuid import UUID

from fastapi import HTTPException, status

NormalizedRole = Literal["admin", "member"]
AUTHORIZATION_BASIS = "verified_active_org_role"

_ADMIN_ENCODINGS = frozenset({"org:admin", "admin"})
_MEMBER_ENCODINGS = frozenset({"org:member", "member"})


def normalize_org_role(raw: str | None) -> NormalizedRole | None:
    if not isinstance(raw, str):
        return None
    value = raw.strip().lower()
    if not value:
        return None
    if value in _ADMIN_ENCODINGS:
        return "admin"
    if value in _MEMBER_ENCODINGS:
        return "member"
    return None


def persistable_org_role(role: NormalizedRole) -> str:
    return "org:admin" if role == "admin" else "org:member"


def effective_authorized_role(
    jwt_role: str | None, directory_role: str | None
) -> NormalizedRole | None:
    """JWT is the grant; Clerk directory may only deny admin, never elevate."""
    jwt_n = normalize_org_role(jwt_role)
    directory_n = normalize_org_role(directory_role)
    if jwt_n == "admin":
        if directory_n == "admin":
            return "admin"
        if directory_n == "member":
            return "member"
        return None
    if jwt_n == "member":
        return "member"
    return None


@dataclass(frozen=True)
class AuthorizedOrgActor:
    user_id: UUID
    organization_id: UUID
    normalized_role: NormalizedRole | None
    authorization_basis: str = AUTHORIZATION_BASIS

    @property
    def is_admin(self) -> bool:
        return self.normalized_role == "admin"


def explicit_org_actor(
    *,
    user_id: UUID,
    organization_id: UUID,
    normalized_role: NormalizedRole | None,
) -> AuthorizedOrgActor:
    """Construct a verified-shaped actor. Callers must not read DB role."""
    return AuthorizedOrgActor(
        user_id=user_id,
        organization_id=organization_id,
        normalized_role=normalized_role,
        authorization_basis=AUTHORIZATION_BASIS,
    )


def auth_audit_metadata(actor: AuthorizedOrgActor) -> dict[str, str]:
    metadata = {"authorization_basis": actor.authorization_basis}
    if actor.normalized_role in {"admin", "member"}:
        metadata["authorization_role"] = actor.normalized_role
    return metadata


def merge_auth_audit(actor: AuthorizedOrgActor, metadata: dict | None = None) -> dict:
    merged = dict(metadata or {})
    merged.update(auth_audit_metadata(actor))
    return merged


def assert_actor_org(
    actor: AuthorizedOrgActor,
    organization_id: UUID,
    *,
    not_found: str,
) -> None:
    if actor.organization_id != organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=not_found)


def assert_admin_actor(
    actor: AuthorizedOrgActor,
    organization_id: UUID,
    *,
    not_found: str,
) -> None:
    assert_actor_org(actor, organization_id, not_found=not_found)
    if actor.normalized_role is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Verified organization role is required",
        )
    if actor.normalized_role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Organization admin required",
        )


def may_stop_operation(operation, actor: AuthorizedOrgActor) -> bool:
    if actor.organization_id != getattr(operation, "organization_id", None):
        return False
    if actor.normalized_role == "admin":
        return True
    source = getattr(operation, "source", None) or "manual"
    created_by = getattr(operation, "created_by_user_id", None)
    if (
        source == "manual"
        and created_by is not None
        and created_by == actor.user_id
    ):
        return True
    return False


def require_stop_permission(operation, actor: AuthorizedOrgActor) -> None:
    assert_actor_org(actor, operation.organization_id, not_found="Operation not found")
    if may_stop_operation(operation, actor):
        return
    if actor.normalized_role is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Verified organization role is required",
        )
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Organization admin required",
    )
