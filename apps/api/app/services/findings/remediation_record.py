from __future__ import annotations

import binascii
from base64 import urlsafe_b64decode, urlsafe_b64encode
from dataclasses import dataclass
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import and_, func, or_, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.finding import Finding
from app.models.finding_remediation import FindingRemediationRevision
from app.models.user import User
from app.schemas.finding_remediation import (
    FindingRemediationHistoryResponse,
    FindingRemediationRevisionResponse,
)
from app.services.audit import record_audit
from app.services.authorization import AuthorizedOrgActor, assert_actor_org, merge_auth_audit
from app.services.findings.remediation import get_finding_or_404

DEFAULT_REMEDIATION_PAGE_SIZE = 20
MAX_REMEDIATION_PAGE_SIZE = 50
REMEDIATION_CURSOR_VERSION = "v1"
INVALID_REMEDIATION_CURSOR_DETAIL = "Invalid remediation history cursor"
MAX_REVISION_ALLOCATION_ATTEMPTS = 2


@dataclass(frozen=True)
class CreatedRemediationRevision:
    revision: FindingRemediationRevision
    created_by_name: str | None


def encode_remediation_cursor(*, revision_number: int, revision_id: UUID) -> str:
    payload = f"{REMEDIATION_CURSOR_VERSION}|{revision_number}|{revision_id}"
    return urlsafe_b64encode(payload.encode("utf-8")).decode("ascii").rstrip("=")


def _invalid_cursor() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=INVALID_REMEDIATION_CURSOR_DETAIL,
    )


def decode_remediation_cursor(raw: str) -> tuple[int, UUID]:
    padded = raw + ("=" * (-len(raw) % 4))
    try:
        decoded = urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
        raise _invalid_cursor() from exc
    parts = decoded.split("|")
    if len(parts) != 3 or parts[0] != REMEDIATION_CURSOR_VERSION:
        raise _invalid_cursor()
    try:
        revision_number = int(parts[1])
        revision_id = UUID(parts[2])
    except (TypeError, ValueError) as exc:
        raise _invalid_cursor() from exc
    if revision_number < 1:
        raise _invalid_cursor()
    return revision_number, revision_id


def _response(
    revision: FindingRemediationRevision,
    created_by_name: str | None,
) -> FindingRemediationRevisionResponse:
    return FindingRemediationRevisionResponse(
        id=revision.id,
        revision_number=revision.revision_number,
        summary=revision.summary,
        created_at=revision.created_at,
        created_by_user_id=revision.created_by_user_id,
        created_by_name=created_by_name,
    )


def list_remediation_revisions(
    db: Session,
    *,
    finding_id: UUID,
    user_id: UUID,
    page_size: int = DEFAULT_REMEDIATION_PAGE_SIZE,
    cursor: str | None = None,
) -> FindingRemediationHistoryResponse:
    finding = get_finding_or_404(db, finding_id=finding_id, user_id=user_id)
    size = min(max(page_size, 1), MAX_REMEDIATION_PAGE_SIZE)
    cursor_position = decode_remediation_cursor(cursor) if cursor else None

    revision_count = int(
        db.scalar(
            select(func.count())
            .select_from(FindingRemediationRevision)
            .where(
                FindingRemediationRevision.finding_id == finding.id,
                FindingRemediationRevision.organization_id == finding.organization_id,
            )
        )
        or 0
    )

    page_stmt = (
        select(FindingRemediationRevision, User.name.label("created_by_name"))
        .join(User, User.id == FindingRemediationRevision.created_by_user_id)
        .where(
            FindingRemediationRevision.finding_id == finding.id,
            FindingRemediationRevision.organization_id == finding.organization_id,
        )
        .order_by(
            FindingRemediationRevision.revision_number.desc(),
            FindingRemediationRevision.id.desc(),
        )
        .limit(size + 1)
    )
    if cursor_position is not None:
        cursor_number, cursor_id = cursor_position
        page_stmt = page_stmt.where(
            or_(
                FindingRemediationRevision.revision_number < cursor_number,
                and_(
                    FindingRemediationRevision.revision_number == cursor_number,
                    FindingRemediationRevision.id < cursor_id,
                ),
            )
        )

    rows = list(db.execute(page_stmt).all())
    has_more = len(rows) > size
    page = rows[:size]
    revisions = [_response(row[0], row.created_by_name) for row in page]

    latest: FindingRemediationRevisionResponse | None = None
    if revision_count:
        if cursor_position is None and page:
            latest = revisions[0]
        else:
            latest_row = db.execute(
                select(FindingRemediationRevision, User.name.label("created_by_name"))
                .join(User, User.id == FindingRemediationRevision.created_by_user_id)
                .where(
                    FindingRemediationRevision.finding_id == finding.id,
                    FindingRemediationRevision.organization_id == finding.organization_id,
                )
                .order_by(
                    FindingRemediationRevision.revision_number.desc(),
                    FindingRemediationRevision.id.desc(),
                )
                .limit(1)
            ).one()
            latest = _response(latest_row[0], latest_row.created_by_name)

    next_cursor = None
    if has_more and page:
        last_revision = page[-1][0]
        next_cursor = encode_remediation_cursor(
            revision_number=last_revision.revision_number,
            revision_id=last_revision.id,
        )

    return FindingRemediationHistoryResponse(
        finding_id=finding.id,
        revision_count=revision_count,
        latest=latest,
        page_size=size,
        next_cursor=next_cursor,
        revisions=revisions,
    )


def record_remediation_revision(
    db: Session,
    *,
    finding: Finding,
    summary: str,
    actor: AuthorizedOrgActor,
) -> CreatedRemediationRevision:
    assert_actor_org(actor, finding.organization_id, not_found="Finding not found")

    # Serialize against a passing retest updating the same finding and refresh
    # the status under that row lock before deciding whether recording is valid.
    locked_finding = db.scalar(
        select(Finding).where(Finding.id == finding.id).with_for_update()
    )
    if locked_finding is None or locked_finding.organization_id != actor.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    if locked_finding.status == "resolved":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Resolved findings cannot receive new remediation revisions",
        )

    db.execute(
        text("SELECT pg_advisory_xact_lock(hashtext(:lock_key))"),
        {"lock_key": f"finding_remediation:{locked_finding.id}"},
    )

    revision: FindingRemediationRevision | None = None
    for attempt in range(MAX_REVISION_ALLOCATION_ATTEMPTS):
        next_number = int(
            db.scalar(
                select(
                    func.coalesce(
                        func.max(FindingRemediationRevision.revision_number),
                        0,
                    )
                    + 1
                ).where(
                    FindingRemediationRevision.finding_id == locked_finding.id,
                    FindingRemediationRevision.organization_id
                    == locked_finding.organization_id,
                )
            )
            or 1
        )
        candidate = FindingRemediationRevision(
            organization_id=locked_finding.organization_id,
            finding_id=locked_finding.id,
            revision_number=next_number,
            summary=summary,
            created_by_user_id=actor.user_id,
        )
        try:
            with db.begin_nested():
                db.add(candidate)
                db.flush()
            revision = candidate
            break
        except IntegrityError:
            # begin_nested rolled back the failed savepoint; the outer
            # transaction and advisory lock remain valid for one fresh retry.
            db.expire_all()
            if attempt + 1 == MAX_REVISION_ALLOCATION_ATTEMPTS:
                db.rollback()
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Could not allocate remediation revision number",
                ) from None

    assert revision is not None
    record_audit(
        db,
        organization_id=locked_finding.organization_id,
        actor_type="user",
        actor_user_id=actor.user_id,
        action="finding.remediation_recorded",
        resource_type="finding_remediation_revision",
        resource_id=revision.id,
        summary=f"Remediation recorded for finding: {locked_finding.title}",
        metadata=merge_auth_audit(
            actor,
            {
                "finding_id": str(locked_finding.id),
                "remediation_revision_id": str(revision.id),
                "revision_number": revision.revision_number,
            },
        ),
    )
    created_by_name = db.scalar(select(User.name).where(User.id == actor.user_id))
    db.commit()
    db.refresh(revision)
    return CreatedRemediationRevision(
        revision=revision,
        created_by_name=created_by_name,
    )
