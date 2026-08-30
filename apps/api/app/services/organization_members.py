"""Authoritative active-organization member listing for finding ownership.

OrganizationMembership rows are maintained per authenticating user via
``sync_user_from_clerk`` → ``sync_memberships`` (Clerk user memberships). That
local table is therefore NOT a complete org roster.

M33 assignability and the member picker both use live Clerk Backend API reads:

* picker: ``ClerkDirectory.list_organization_members`` (org-scoped, paginated)
* assign: ``ClerkDirectory.list_organization_memberships`` for the assignee and
  require the active org's ``clerk_org_id`` to be present

FakeClerk derives both from the same membership map so the picker/PUT invariant
holds in tests.
"""

from __future__ import annotations

import binascii
from base64 import urlsafe_b64decode, urlsafe_b64encode
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.organization import Organization, OrganizationMembership
from app.models.user import User
from app.schemas.organization_members import (
    OrganizationMemberItem,
    OrganizationMembersResponse,
)
from app.services.clerk import ClerkDirectory, ClerkOrganizationMember, ClerkUserInfo
from app.services.sync import upsert_user

DEFAULT_MEMBER_PAGE_SIZE = 50
MAX_MEMBER_PAGE_SIZE = 100
MEMBER_CURSOR_VERSION = "v1"
INVALID_MEMBER_CURSOR_DETAIL = "Invalid organization members cursor"


def encode_members_cursor(*, offset: int) -> str:
    payload = f"{MEMBER_CURSOR_VERSION}|{offset}"
    return urlsafe_b64encode(payload.encode("utf-8")).decode("ascii").rstrip("=")


def decode_members_cursor(raw: str) -> int:
    if not raw or not raw.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=INVALID_MEMBER_CURSOR_DETAIL,
        )
    padded = raw + ("=" * (-len(raw) % 4))
    try:
        decoded = urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=INVALID_MEMBER_CURSOR_DETAIL,
        ) from exc
    parts = decoded.split("|")
    if len(parts) != 2 or parts[0] != MEMBER_CURSOR_VERSION:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=INVALID_MEMBER_CURSOR_DETAIL,
        )
    try:
        offset = int(parts[1])
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=INVALID_MEMBER_CURSOR_DETAIL,
        ) from exc
    if offset < 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=INVALID_MEMBER_CURSOR_DETAIL,
        )
    return offset


def clerk_user_is_org_member(
    directory: ClerkDirectory,
    *,
    clerk_user_id: str,
    clerk_org_id: str,
) -> bool:
    """Authoritative assignability: live Clerk memberships for this user."""
    memberships = directory.list_organization_memberships(clerk_user_id)
    return any(row.clerk_org_id == clerk_org_id for row in memberships)


def _upsert_member_user(
    db: Session,
    *,
    organization: Organization,
    member: ClerkOrganizationMember,
) -> User:
    user = upsert_user(
        db,
        ClerkUserInfo(
            clerk_user_id=member.clerk_user_id,
            email=member.email,
            name=member.name,
            email_verified=member.email_verified,
        ),
    )
    # Read-through warm of local membership (not the assignability source).
    existing = db.scalar(
        select(OrganizationMembership).where(
            OrganizationMembership.organization_id == organization.id,
            OrganizationMembership.user_id == user.id,
        )
    )
    if existing is None:
        db.add(
            OrganizationMembership(
                organization_id=organization.id,
                user_id=user.id,
                role="org:member",
            )
        )
        db.flush()
    return user


def list_active_organization_members(
    db: Session,
    *,
    organization: Organization,
    directory: ClerkDirectory,
    page_size: int = DEFAULT_MEMBER_PAGE_SIZE,
    cursor: str | None = None,
) -> OrganizationMembersResponse:
    size = min(max(page_size, 1), MAX_MEMBER_PAGE_SIZE)
    offset = decode_members_cursor(cursor) if cursor else 0
    members, total = directory.list_organization_members(
        organization.clerk_org_id,
        limit=size,
        offset=offset,
    )
    items: list[OrganizationMemberItem] = []
    for member in members:
        user = _upsert_member_user(db, organization=organization, member=member)
        items.append(
            OrganizationMemberItem(user_id=user.id, display_name=user.name)
        )
    db.commit()
    next_offset = offset + len(members)
    next_cursor = (
        encode_members_cursor(offset=next_offset) if next_offset < total else None
    )
    return OrganizationMembersResponse(
        page_size=size,
        next_cursor=next_cursor,
        items=items,
    )


def assert_assignable_org_member(
    db: Session,
    *,
    directory: ClerkDirectory,
    organization: Organization,
    user_id: UUID,
) -> User:
    """Fail closed unless Clerk says this app user is a current org member."""
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Assignee must be a current organization member",
        )
    try:
        is_member = clerk_user_is_org_member(
            directory,
            clerk_user_id=user.clerk_user_id,
            clerk_org_id=organization.clerk_org_id,
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Failed to verify organization membership",
        ) from exc
    if not is_member:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Assignee must be a current organization member",
        )
    # Warm local membership after authoritative accept.
    existing = db.scalar(
        select(OrganizationMembership).where(
            OrganizationMembership.organization_id == organization.id,
            OrganizationMembership.user_id == user.id,
        )
    )
    if existing is None:
        db.add(
            OrganizationMembership(
                organization_id=organization.id,
                user_id=user.id,
                role="org:member",
            )
        )
        db.flush()
    return user
