"""Organization access review — authoritative CURRENT membership (Milestone 38).

Authoritative source: Clerk organization memberships page for the active org.
Local User rows are linkage / display only. OrganizationMembership is a local
access-cache diagnostic and never defines roster membership or elevates role.

This service performs zero identity-directory mutations. Viewer auth middleware
may still sync the current viewer before the route runs; that is not M38 roster
repair.
"""

from __future__ import annotations

import binascii
from base64 import urlsafe_b64decode, urlsafe_b64encode
from typing import Literal

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.organization import Organization, OrganizationMembership
from app.models.user import User
from app.schemas.organization_access import (
    OrganizationAccessMember,
    OrganizationAccessOrg,
    OrganizationAccessResponse,
)
from app.services.authorization import normalize_org_role
from app.services.clerk import (
    ClerkDirectory,
    ClerkOrganizationMembershipRaw,
    CurrentAccessUnavailable,
)

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 100
CURSOR_VERSION = "v1"
INVALID_CURSOR_DETAIL = "Invalid organization access cursor"
CURRENT_ACCESS_UNAVAILABLE_DETAIL = "Current organization access could not be verified."

RoleState = Literal["recognized", "unrecognized"]
AccessRole = Literal["admin", "member"]
AccountLinkState = Literal["linked", "not_linked"]
LocalMirrorState = Literal[
    "not_applicable",
    "missing",
    "role_matches",
    "role_differs",
]


def raise_current_access_unavailable() -> None:
    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail=CURRENT_ACCESS_UNAVAILABLE_DETAIL,
    )


def encode_access_cursor(*, offset: int) -> str:
    payload = f"{CURSOR_VERSION}|{offset}"
    return urlsafe_b64encode(payload.encode("utf-8")).decode("ascii").rstrip("=")


def decode_access_cursor(raw: str) -> int:
    if not raw or not raw.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=INVALID_CURSOR_DETAIL,
        )
    padded = raw + ("=" * (-len(raw) % 4))
    try:
        decoded = urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=INVALID_CURSOR_DETAIL,
        ) from exc
    parts = decoded.split("|")
    if len(parts) != 2 or parts[0] != CURSOR_VERSION:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=INVALID_CURSOR_DETAIL,
        )
    try:
        offset = int(parts[1])
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=INVALID_CURSOR_DETAIL,
        ) from exc
    if offset < 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=INVALID_CURSOR_DETAIL,
        )
    return offset


def classify_provider_role(
    external_role: str | None,
) -> tuple[AccessRole | None, RoleState]:
    """Map provider role for display. Unknown roles stay visible as unrecognized."""
    normalized = normalize_org_role(external_role)
    if normalized is None:
        return None, "unrecognized"
    return normalized, "recognized"


def provider_display_name(row: ClerkOrganizationMembershipRaw) -> str | None:
    parts = [p for p in (row.first_name, row.last_name) if p]
    if not parts:
        return None
    return " ".join(parts)


def local_mirror_state_for(
    *,
    account_link_state: AccountLinkState,
    role: AccessRole | None,
    role_state: RoleState,
    local_membership: OrganizationMembership | None,
) -> LocalMirrorState:
    if account_link_state == "not_linked":
        return "not_applicable"
    if local_membership is None:
        return "missing"
    if role_state == "unrecognized" or role is None:
        # Do not pretend local role resolves an unrecognized provider role.
        return "not_applicable"
    local_role = normalize_org_role(local_membership.role)
    if local_role == role:
        return "role_matches"
    return "role_differs"


def list_organization_access(
    db: Session,
    *,
    organization: Organization,
    directory: ClerkDirectory,
    page_size: int = DEFAULT_PAGE_SIZE,
    cursor: str | None = None,
) -> OrganizationAccessResponse:
    """Read-only authoritative current-membership page for the active organization.

    Call count after rate-limit gate (caller responsibility):
    - exactly one ``list_organization_memberships_raw``
    - one batched User SELECT by clerk_user_id
    - one batched OrganizationMembership SELECT for linked app user IDs

    No User/OrganizationMembership writes, no get_user, no audit events.
    """
    size = min(max(page_size, 1), MAX_PAGE_SIZE)
    offset = decode_access_cursor(cursor) if cursor else 0

    if not organization.clerk_org_id or not organization.clerk_org_id.strip():
        raise_current_access_unavailable()

    try:
        rows, total_members = directory.list_organization_memberships_raw(
            organization.clerk_org_id,
            limit=size,
            offset=offset,
        )
    except CurrentAccessUnavailable:
        raise_current_access_unavailable()
    except HTTPException:
        # Do not leak alternate Clerk HTTP contracts onto this endpoint.
        raise_current_access_unavailable()
    except Exception:
        raise_current_access_unavailable()

    provider_ids = [row.provider_user_id for row in rows]
    users_by_clerk: dict[str, User] = {}
    if provider_ids:
        linked_users = db.scalars(
            select(User).where(User.clerk_user_id.in_(provider_ids))
        ).all()
        users_by_clerk = {user.clerk_user_id: user for user in linked_users}

    memberships_by_user_id: dict = {}
    linked_user_ids = [user.id for user in users_by_clerk.values()]
    if linked_user_ids:
        memberships = db.scalars(
            select(OrganizationMembership).where(
                OrganizationMembership.organization_id == organization.id,
                OrganizationMembership.user_id.in_(linked_user_ids),
            )
        ).all()
        memberships_by_user_id = {row.user_id: row for row in memberships}

    items: list[OrganizationAccessMember] = []
    for row in rows:
        role, role_state = classify_provider_role(row.external_role)
        linked = users_by_clerk.get(row.provider_user_id)
        if linked is None:
            account_link_state: AccountLinkState = "not_linked"
            user_id = None
            display_name = provider_display_name(row)
            local_membership = None
        else:
            account_link_state = "linked"
            user_id = linked.id
            display_name = linked.name or provider_display_name(row)
            local_membership = memberships_by_user_id.get(linked.id)

        mirror = local_mirror_state_for(
            account_link_state=account_link_state,
            role=role,
            role_state=role_state,
            local_membership=local_membership,
        )
        items.append(
            OrganizationAccessMember(
                user_id=user_id,
                display_name=display_name,
                role=role,
                role_state=role_state,
                account_link_state=account_link_state,
                local_mirror_state=mirror,
            )
        )

    next_offset = offset + len(rows)
    if total_members is not None:
        next_cursor = (
            encode_access_cursor(offset=next_offset)
            if next_offset < total_members
            else None
        )
    else:
        next_cursor = (
            encode_access_cursor(offset=next_offset) if len(rows) == size else None
        )

    return OrganizationAccessResponse(
        organization=OrganizationAccessOrg(
            id=organization.id,
            name=organization.name,
        ),
        source="authoritative_current_membership",
        page_size=size,
        next_cursor=next_cursor,
        total_members=total_members,
        items=items,
    )
