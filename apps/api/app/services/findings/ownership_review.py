"""Organization finding ownership review (Milestone 44).

Read-only. DB page of active Findings, then one bounded Clerk membership-presence
lookup for unique assignees on that page. Local OrganizationMembership is never
authoritative. Never mutates assignment.
"""

from __future__ import annotations

import binascii
import logging
from base64 import urlsafe_b64decode, urlsafe_b64encode
from datetime import datetime
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.finding import OPEN_FINDING_STATUSES, Finding
from app.models.organization import Organization
from app.models.target import AuthorizedTarget
from app.models.user import User
from app.schemas.finding_ownership_review import (
    FindingOwnershipAssignee,
    FindingOwnershipReviewItem,
    FindingOwnershipReviewResponse,
)
from app.services.clerk import ClerkDirectory, FindingOwnershipPresenceUnavailable

logger = logging.getLogger("scout.finding_ownership_review")

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 100
CURSOR_VERSION = "v1"
INVALID_CURSOR_DETAIL = "Invalid finding ownership review cursor"
UNAVAILABLE_DETAIL = "Finding ownership could not be verified."
OPEN_STATUS_LIST = sorted(OPEN_FINDING_STATUSES)


def raise_ownership_unavailable() -> None:
    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail=UNAVAILABLE_DETAIL,
    )


def encode_ownership_review_cursor(*, created_at: datetime, finding_id: UUID) -> str:
    payload = f"{CURSOR_VERSION}|{created_at.isoformat()}|{finding_id}"
    return urlsafe_b64encode(payload.encode("utf-8")).decode("ascii").rstrip("=")


def decode_ownership_review_cursor(raw: str) -> tuple[datetime, UUID]:
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
    if len(parts) != 3 or parts[0] != CURSOR_VERSION:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=INVALID_CURSOR_DETAIL,
        )
    try:
        created_at = datetime.fromisoformat(parts[1])
        finding_id = UUID(parts[2])
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=INVALID_CURSOR_DETAIL,
        ) from exc
    if created_at.tzinfo is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=INVALID_CURSOR_DETAIL,
        )
    return created_at, finding_id


def list_finding_ownership_review(
    db: Session,
    *,
    organization: Organization,
    directory: ClerkDirectory,
    page_size: int = DEFAULT_PAGE_SIZE,
    cursor: str | None = None,
) -> FindingOwnershipReviewResponse:
    if not organization.clerk_org_id or not organization.clerk_org_id.strip():
        raise_ownership_unavailable()

    size = min(max(page_size, 1), MAX_PAGE_SIZE)
    stmt = (
        select(
            Finding.id.label("finding_id"),
            Finding.title,
            Finding.severity,
            Finding.status,
            Finding.assigned_to_user_id,
            Finding.follow_up_due_at,
            Finding.created_at,
            AuthorizedTarget.id.label("target_id"),
            AuthorizedTarget.domain.label("target_label"),
        )
        .join(Asset, Asset.id == Finding.asset_id)
        .join(AuthorizedTarget, AuthorizedTarget.id == Asset.target_id)
        .where(
            Finding.organization_id == organization.id,
            AuthorizedTarget.organization_id == organization.id,
            Finding.status.in_(OPEN_STATUS_LIST),
        )
        .order_by(Finding.created_at.desc(), Finding.id.desc())
        .limit(size + 1)
    )
    if cursor:
        cursor_created_at, cursor_id = decode_ownership_review_cursor(cursor)
        stmt = stmt.where(
            or_(
                Finding.created_at < cursor_created_at,
                and_(
                    Finding.created_at == cursor_created_at,
                    Finding.id < cursor_id,
                ),
            )
        )

    rows = list(db.execute(stmt).all())
    has_more = len(rows) > size
    page_rows = rows[:size]

    assignee_ids = sorted(
        {row.assigned_to_user_id for row in page_rows if row.assigned_to_user_id is not None}
    )
    users_by_id: dict[UUID, tuple[str | None, str]] = {}
    if assignee_ids:
        user_rows = db.execute(
            select(User.id, User.name, User.clerk_user_id).where(User.id.in_(assignee_ids))
        ).all()
        if len(user_rows) != len(assignee_ids):
            raise_ownership_unavailable()
        for user_id, name, clerk_user_id in user_rows:
            if not isinstance(clerk_user_id, str) or not clerk_user_id.strip():
                raise_ownership_unavailable()
            users_by_id[user_id] = (name, clerk_user_id.strip())

    provider_ids = sorted({clerk_id for _name, clerk_id in users_by_id.values()})
    present_provider_ids: frozenset[str] = frozenset()
    if provider_ids:
        if len(provider_ids) > size or len(provider_ids) > 100:
            raise_ownership_unavailable()
        try:
            present_provider_ids = directory.list_organization_membership_presence(
                organization.clerk_org_id,
                provider_user_ids=tuple(provider_ids),
            )
        except FindingOwnershipPresenceUnavailable:
            logger.error(
                "finding_ownership_presence_unavailable",
                extra={
                    "organization_app_id": str(organization.id),
                    "operation": "finding_ownership_presence",
                    "requested_count": len(provider_ids),
                },
            )
            raise_ownership_unavailable()
        if not present_provider_ids.issubset(set(provider_ids)):
            raise_ownership_unavailable()

    items: list[FindingOwnershipReviewItem] = []
    for row in page_rows:
        if row.status not in OPEN_FINDING_STATUSES:
            raise_ownership_unavailable()
        assignee: FindingOwnershipAssignee | None = None
        assignment_state: str
        if row.assigned_to_user_id is None:
            assignment_state = "unassigned"
        else:
            mapped = users_by_id.get(row.assigned_to_user_id)
            if mapped is None:
                raise_ownership_unavailable()
            display_name, clerk_user_id = mapped
            assignee = FindingOwnershipAssignee(
                user_id=row.assigned_to_user_id,
                display_name=display_name,
            )
            if clerk_user_id in present_provider_ids:
                assignment_state = "current_member"
            else:
                assignment_state = "not_current_member"
        items.append(
            FindingOwnershipReviewItem(
                finding_id=row.finding_id,
                target_id=row.target_id,
                target_label=row.target_label,
                title=row.title,
                severity=row.severity,
                status=row.status,
                assignment_state=assignment_state,  # type: ignore[arg-type]
                assignee=assignee,
                follow_up_due_at=row.follow_up_due_at,
                created_at=row.created_at,
            )
        )

    next_cursor = None
    if has_more and page_rows:
        last = page_rows[-1]
        next_cursor = encode_ownership_review_cursor(
            created_at=last.created_at,
            finding_id=last.finding_id,
        )

    return FindingOwnershipReviewResponse(items=items, next_cursor=next_cursor)
