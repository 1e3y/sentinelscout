"""Read-only organization findings inbox.

Current operational state only. This module reads ``findings``, ``assets``,
``authorized_targets``, ``security_candidates``, ``retest_attempts`` and compact
metadata from ``finding_remediation_revisions``. It never reads remediation
text, touches coverage freezes, diff summaries, report snapshots, shares,
deliveries, or audit rows, and it performs no writes.

Finding rows already mean promoted/supported findings: the sole insert path is
``promote_candidate_to_finding``, which requires a ``supported`` candidate backed
by a ``supported`` ValidationAttempt. Reading the table therefore cannot upgrade
a candidate, hypothesis, or dismissed row into a finding, and no validation logic
is re-run here.

There is no score, grade, weighting, or ranking. Attention is an unordered set of
explicit boolean facts, and severity is passed through as stored.
"""

from __future__ import annotations

import binascii
from base64 import urlsafe_b64decode, urlsafe_b64encode
from datetime import datetime
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import Select, and_, func, or_, select, true
from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.candidate import SecurityCandidate
from app.models.finding import Finding
from app.models.finding_remediation import FindingRemediationRevision
from app.models.organization import Organization
from app.models.retest import ACTIVE_RETEST_STATUSES, RetestAttempt
from app.models.target import AuthorizedTarget
from app.schemas.findings_inbox import (
    FindingInboxAttentionReason,
    FindingInboxLatestTerminalRetest,
    FindingInboxRemediation,
    FindingInboxResponse,
    FindingInboxRetests,
    FindingInboxRow,
    FindingInboxSummary,
    FindingInboxTarget,
    FindingInboxWorkflow,
)
from app.services.reports.summary import OPEN_FINDING_STATUSES

DEFAULT_PAGE_SIZE = 20
MAX_PAGE_SIZE = 50
CURSOR_VERSION = "v1"
INVALID_CURSOR_DETAIL = "Invalid findings inbox cursor"

VERIFIED_STATUS = "verified"

# Sorted so the emitted SQL is stable across runs.
ACTIVE_STATUS_LIST = sorted(ACTIVE_RETEST_STATUSES)
OPEN_STATUS_LIST = sorted(OPEN_FINDING_STATUSES)

RETEST_STATE_NONE = "none"
RETEST_STATE_IN_PROGRESS = "in_progress"
TERMINAL_RETEST_STATES = ("passed", "failed", "inconclusive", "error")

# findings.status -> workflow state. A pure rename, not an inference.
WORKFLOW_STATE_BY_FINDING_STATUS: dict[str, str] = {
    "open": "not_started",
    "in_progress": "in_progress",
    "ready_for_retest": "ready_for_retest",
    "resolved": "resolved_by_retest",
}

REASON_REMEDIATION_NOT_STARTED = "REMEDIATION_NOT_STARTED"
REASON_AWAITING_RETEST = "AWAITING_RETEST"
REASON_LATEST_RETEST_FAILED = "LATEST_RETEST_FAILED"
REASON_LATEST_RETEST_INCONCLUSIVE = "LATEST_RETEST_INCONCLUSIVE"
REASON_LATEST_RETEST_ERROR = "LATEST_RETEST_ERROR"
REASON_TARGET_NOT_VERIFIED = "TARGET_NOT_VERIFIED"

ATTENTION_LABELS: dict[str, str] = {
    REASON_REMEDIATION_NOT_STARTED: "Remediation not started",
    REASON_AWAITING_RETEST: "Ready for retest, none run",
    REASON_LATEST_RETEST_FAILED: "Latest retest failed",
    REASON_LATEST_RETEST_INCONCLUSIVE: "Latest retest inconclusive",
    REASON_LATEST_RETEST_ERROR: "Latest retest errored",
    REASON_TARGET_NOT_VERIFIED: "Target not verified",
}

ATTENTION_PROVENANCE: dict[str, str] = {
    REASON_REMEDIATION_NOT_STARTED: "finding_workflow",
    REASON_AWAITING_RETEST: "finding_workflow",
    REASON_LATEST_RETEST_FAILED: "retest_state",
    REASON_LATEST_RETEST_INCONCLUSIVE: "retest_state",
    REASON_LATEST_RETEST_ERROR: "retest_state",
    REASON_TARGET_NOT_VERIFIED: "target_authorization",
}

# A terminal result only becomes a follow-up reason when it is the current state.
REASON_BY_TERMINAL_RETEST_STATE: dict[str, str] = {
    "failed": REASON_LATEST_RETEST_FAILED,
    "inconclusive": REASON_LATEST_RETEST_INCONCLUSIVE,
    "error": REASON_LATEST_RETEST_ERROR,
}


def encode_inbox_cursor(*, created_at: datetime, finding_id: UUID) -> str:
    payload = f"{CURSOR_VERSION}|{created_at.isoformat()}|{finding_id}"
    return urlsafe_b64encode(payload.encode("utf-8")).decode("ascii").rstrip("=")


def decode_inbox_cursor(raw: str) -> tuple[datetime, UUID]:
    padded = raw + ("=" * (-len(raw) % 4))
    try:
        decoded = urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
        raise _invalid_cursor() from exc
    parts = decoded.split("|")
    if len(parts) != 3 or parts[0] != CURSOR_VERSION:
        raise _invalid_cursor()
    try:
        created_at = datetime.fromisoformat(parts[1])
        finding_id = UUID(parts[2])
    except (AttributeError, TypeError, ValueError) as exc:
        raise _invalid_cursor() from exc
    return created_at, finding_id


def _invalid_cursor() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST, detail=INVALID_CURSOR_DETAIL
    )


def _reason(code: str) -> FindingInboxAttentionReason:
    return FindingInboxAttentionReason(
        code=code,
        label=ATTENTION_LABELS[code],
        provenance=ATTENTION_PROVENANCE[code],
    )


def _active_retest_exists():
    return (
        select(RetestAttempt.id)
        .where(
            RetestAttempt.finding_id == Finding.id,
            RetestAttempt.status.in_(ACTIVE_STATUS_LIST),
        )
        .exists()
    )


def _any_retest_exists():
    return (
        select(RetestAttempt.id).where(RetestAttempt.finding_id == Finding.id).exists()
    )


def _latest_terminal_lateral():
    return (
        select(RetestAttempt.status.label("status"))
        .where(
            RetestAttempt.finding_id == Finding.id,
            RetestAttempt.status.not_in(ACTIVE_STATUS_LIST),
        )
        .order_by(
            RetestAttempt.completed_at.desc().nullslast(),
            RetestAttempt.created_at.desc(),
            RetestAttempt.id.desc(),
        )
        .limit(1)
        .lateral("latest_terminal_retest")
    )


def _apply_retest_state(stmt: Select, value: str) -> Select:
    """Filter on current_retest_state.

    Each branch is shaped for its own access path rather than reusing one plan.
    `in_progress` rides the partial unique index over active attempts and `none`
    is a plain anti-join. The terminal branches use a LATERAL rather than a
    correlated scalar subquery: measured on 6k findings, the correlated form
    forces the planner to evaluate the ordered lookup once per organization row
    (6000 loops, ~19k buffers), while the LATERAL keeps the keyset index scan as
    the driver and stops once the page fills (285 loops, ~2.7k buffers).
    """
    if value == RETEST_STATE_IN_PROGRESS:
        return stmt.where(_active_retest_exists())
    if value == RETEST_STATE_NONE:
        return stmt.where(~_any_retest_exists())
    latest = _latest_terminal_lateral()
    return stmt.join(latest, true()).where(
        latest.c.status == value, ~_active_retest_exists()
    )


def _page_statement(
    *,
    organization_id: UUID,
    size: int,
    cursor: str | None,
    finding_status: str | None,
    severity: str | None,
    target_id: UUID | None,
    retest_state: str | None,
) -> Select:
    """Explicit column list: findings.evidence is never selected."""
    stmt = (
        select(
            Finding.id.label("finding_id"),
            Finding.title,
            Finding.severity,
            Finding.status.label("finding_status"),
            Finding.created_at.label("promoted_at"),
            Finding.updated_at.label("last_updated_at"),
            Finding.resolved_at,
            SecurityCandidate.candidate_type.label("finding_type"),
            Asset.hostname.label("asset_hostname"),
            AuthorizedTarget.id.label("target_id"),
            AuthorizedTarget.domain,
            AuthorizedTarget.status.label("authorization_status"),
        )
        .join(Asset, Asset.id == Finding.asset_id)
        .join(AuthorizedTarget, AuthorizedTarget.id == Asset.target_id)
        .join(SecurityCandidate, SecurityCandidate.id == Finding.candidate_id)
        .where(
            Finding.organization_id == organization_id,
            # Redundant with the finding predicate, kept as a second boundary.
            AuthorizedTarget.organization_id == organization_id,
        )
        .order_by(Finding.created_at.desc(), Finding.id.desc())
        .limit(size + 1)
    )
    if finding_status is not None:
        stmt = stmt.where(Finding.status == finding_status)
    if severity is not None:
        stmt = stmt.where(Finding.severity == severity)
    if target_id is not None:
        stmt = stmt.where(AuthorizedTarget.id == target_id)
    if retest_state is not None:
        stmt = _apply_retest_state(stmt, retest_state)
    if cursor:
        cursor_created_at, cursor_id = decode_inbox_cursor(cursor)
        stmt = stmt.where(
            or_(
                Finding.created_at < cursor_created_at,
                and_(
                    Finding.created_at == cursor_created_at,
                    Finding.id < cursor_id,
                ),
            )
        )
    return stmt


def _latest_terminal_by_finding(
    db: Session, *, finding_ids: list[UUID]
) -> dict[UUID, FindingInboxLatestTerminalRetest]:
    """Matches the M22 snapshot rule so the inbox and reports cannot disagree."""
    rows = db.execute(
        select(
            RetestAttempt.finding_id,
            RetestAttempt.id,
            RetestAttempt.status,
            RetestAttempt.created_at,
            RetestAttempt.completed_at,
        )
        .distinct(RetestAttempt.finding_id)
        .where(
            RetestAttempt.finding_id.in_(finding_ids),
            RetestAttempt.status.not_in(ACTIVE_STATUS_LIST),
        )
        .order_by(
            RetestAttempt.finding_id,
            RetestAttempt.completed_at.desc().nullslast(),
            RetestAttempt.created_at.desc(),
            RetestAttempt.id.desc(),
        )
    ).all()
    return {
        row.finding_id: FindingInboxLatestTerminalRetest(
            retest_attempt_id=row.id,
            status=row.status,
            created_at=row.created_at,
            completed_at=row.completed_at,
        )
        for row in rows
    }


def _retest_rollup_by_finding(
    db: Session, *, finding_ids: list[UUID]
) -> dict[UUID, tuple[int, bool]]:
    rows = db.execute(
        select(
            RetestAttempt.finding_id,
            func.count().label("attempt_count"),
            func.bool_or(RetestAttempt.status.in_(ACTIVE_STATUS_LIST)).label(
                "has_active"
            ),
        )
        .where(RetestAttempt.finding_id.in_(finding_ids))
        .group_by(RetestAttempt.finding_id)
    ).all()
    return {
        row.finding_id: (int(row.attempt_count or 0), bool(row.has_active))
        for row in rows
    }


def _remediation_rollup_by_finding(
    db: Session, *, finding_ids: list[UUID]
) -> dict[UUID, tuple[int, datetime | None]]:
    rows = db.execute(
        select(
            FindingRemediationRevision.finding_id,
            func.count().label("revision_count"),
            func.max(FindingRemediationRevision.created_at).label(
                "latest_recorded_at"
            ),
        )
        .where(FindingRemediationRevision.finding_id.in_(finding_ids))
        .group_by(FindingRemediationRevision.finding_id)
    ).all()
    return {
        row.finding_id: (
            int(row.revision_count or 0),
            row.latest_recorded_at,
        )
        for row in rows
    }


def _current_retest_state(
    *, has_active: bool, latest_terminal: FindingInboxLatestTerminalRetest | None
) -> str:
    """One mutually exclusive state. An active attempt outranks any older result."""
    if has_active:
        return RETEST_STATE_IN_PROGRESS
    if latest_terminal is None:
        return RETEST_STATE_NONE
    return latest_terminal.status


def _attention_reasons(
    *,
    finding_status: str,
    authorization_status: str,
    current_retest_state: str,
) -> list[FindingInboxAttentionReason]:
    """Independent boolean facts. Emission order is declaration order, not priority."""
    unresolved = finding_status in OPEN_FINDING_STATUSES
    codes: list[str] = []

    if finding_status == "open":
        codes.append(REASON_REMEDIATION_NOT_STARTED)
    if (
        finding_status == "ready_for_retest"
        and current_retest_state != RETEST_STATE_IN_PROGRESS
    ):
        codes.append(REASON_AWAITING_RETEST)
    # Gated on current state, so an in-flight retest suppresses the older result.
    terminal_reason = REASON_BY_TERMINAL_RETEST_STATE.get(current_retest_state)
    if unresolved and terminal_reason is not None:
        codes.append(terminal_reason)
    if authorization_status != VERIFIED_STATUS:
        codes.append(REASON_TARGET_NOT_VERIFIED)

    return [_reason(code) for code in codes]


def _organization_summary(db: Session, *, organization_id: UUID) -> FindingInboxSummary:
    no_retest = ~_any_retest_exists()
    row = db.execute(
        select(
            func.count().label("finding_count"),
            func.count().filter(Finding.status.in_(OPEN_STATUS_LIST)).label("open_count"),
            func.count().filter(no_retest).label("without_retest"),
        )
        .select_from(Finding)
        .where(Finding.organization_id == organization_id)
    ).one()
    return FindingInboxSummary(
        finding_count=int(row.finding_count or 0),
        open_finding_count=int(row.open_count or 0),
        findings_without_any_retest=int(row.without_retest or 0),
    )


def list_findings_inbox(
    db: Session,
    *,
    organization: Organization,
    page_size: int = DEFAULT_PAGE_SIZE,
    cursor: str | None = None,
    finding_status: str | None = None,
    severity: str | None = None,
    target_id: UUID | None = None,
    retest_state: str | None = None,
) -> FindingInboxResponse:
    organization_id = organization.id
    size = min(max(page_size, 1), MAX_PAGE_SIZE)

    rows = list(
        db.execute(
            _page_statement(
                organization_id=organization_id,
                size=size,
                cursor=cursor,
                finding_status=finding_status,
                severity=severity,
                target_id=target_id,
                retest_state=retest_state,
            )
        ).all()
    )
    has_more = len(rows) > size
    page = rows[:size]
    next_cursor = None
    if has_more and page:
        last = page[-1]
        next_cursor = encode_inbox_cursor(
            created_at=last.promoted_at, finding_id=last.finding_id
        )

    summary = _organization_summary(db, organization_id=organization_id)
    if not page:
        return FindingInboxResponse(
            organization_id=organization_id,
            page_size=size,
            next_cursor=None,
            summary=summary,
            items=[],
        )

    finding_ids = [row.finding_id for row in page]
    latest_terminal = _latest_terminal_by_finding(db, finding_ids=finding_ids)
    rollup = _retest_rollup_by_finding(db, finding_ids=finding_ids)
    remediation_rollup = _remediation_rollup_by_finding(
        db, finding_ids=finding_ids
    )

    items: list[FindingInboxRow] = []
    for row in page:
        attempt_count, has_active = rollup.get(row.finding_id, (0, False))
        terminal = latest_terminal.get(row.finding_id)
        current_state = _current_retest_state(
            has_active=has_active, latest_terminal=terminal
        )
        revision_count, latest_recorded_at = remediation_rollup.get(
            row.finding_id, (0, None)
        )
        items.append(
            FindingInboxRow(
                finding_id=row.finding_id,
                target=FindingInboxTarget(
                    target_id=row.target_id,
                    domain=row.domain,
                    authorization_status=row.authorization_status,
                    asset_hostname=row.asset_hostname,
                ),
                title=row.title,
                finding_type=row.finding_type,
                severity=row.severity,
                status=row.finding_status,
                workflow=FindingInboxWorkflow(
                    state=WORKFLOW_STATE_BY_FINDING_STATUS[row.finding_status],
                    resolved_at=row.resolved_at,
                ),
                remediation=FindingInboxRemediation(
                    revision_count=revision_count,
                    latest_recorded_at=latest_recorded_at,
                ),
                retests=FindingInboxRetests(
                    current_state=current_state,
                    attempt_count=attempt_count,
                    latest_terminal=terminal,
                ),
                promoted_at=row.promoted_at,
                last_updated_at=row.last_updated_at,
                attention_reasons=_attention_reasons(
                    finding_status=row.finding_status,
                    authorization_status=row.authorization_status,
                    current_retest_state=current_state,
                ),
            )
        )

    return FindingInboxResponse(
        organization_id=organization_id,
        page_size=size,
        next_cursor=next_cursor,
        summary=summary,
        items=items,
    )
