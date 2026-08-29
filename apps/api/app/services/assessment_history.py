"""Read-only target assessment history. Frozen M17/M18 + report metadata only."""

from __future__ import annotations

import binascii
from base64 import urlsafe_b64decode, urlsafe_b64encode
from datetime import datetime
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session, defer, load_only

from app.models.coverage import OperationCoverageSummary
from app.models.diff import OperationDiffSummary
from app.models.operation import Operation
from app.models.report import AssessmentReport
from app.models.target import AuthorizedTarget
from app.schemas.assessment_history import (
    AssessmentHistoryLatestReport,
    AssessmentHistoryResponse,
    AssessmentHistoryRow,
)
from app.services.frozen_projection import (
    comparison_from_row,
    coverage_from_row,
    ended_at_expr,
    operation_ended_at,
    select_latest_report,
    signals_from_row,
    surface_changes_from_row,
)
from app.services.reports.summary import HEADLINE_LABELS

TERMINAL_HISTORY_STATUSES = frozenset({"completed", "failed", "stopped"})
DEFAULT_PAGE_SIZE = 20
MAX_PAGE_SIZE = 50
CURSOR_VERSION = "v1"
INVALID_CURSOR_DETAIL = "Invalid assessment history cursor"

__all__ = [
    "DEFAULT_PAGE_SIZE",
    "MAX_PAGE_SIZE",
    "TERMINAL_HISTORY_STATUSES",
    "decode_history_cursor",
    "encode_history_cursor",
    "list_assessment_history",
    "operation_ended_at",
]


def encode_history_cursor(*, ended_at: datetime, operation_id: UUID) -> str:
    payload = f"{CURSOR_VERSION}|{ended_at.isoformat()}|{operation_id}"
    return urlsafe_b64encode(payload.encode("utf-8")).decode("ascii").rstrip("=")


def decode_history_cursor(raw: str) -> tuple[datetime, UUID]:
    if not raw or not raw.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=INVALID_CURSOR_DETAIL
        )
    padded = raw + ("=" * (-len(raw) % 4))
    try:
        decoded = urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=INVALID_CURSOR_DETAIL
        ) from exc
    parts = decoded.split("|")
    if len(parts) != 3 or parts[0] != CURSOR_VERSION:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=INVALID_CURSOR_DETAIL
        )
    try:
        ended_at = datetime.fromisoformat(parts[1])
        operation_id = UUID(parts[2])
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=INVALID_CURSOR_DETAIL
        ) from exc
    return ended_at, operation_id


def _report_from_rows(
    rows: list[AssessmentReport],
) -> AssessmentHistoryLatestReport | None:
    selected = select_latest_report(rows)
    if selected is None:
        return None
    latest, version_count = selected
    return AssessmentHistoryLatestReport(
        id=latest.id,
        report_version=latest.report_version,
        version_count=version_count,
        generation_origin=latest.generation_origin,
        generated_at=latest.generated_at,
        headline_status=latest.headline_status,
        headline_label=HEADLINE_LABELS.get(latest.headline_status, latest.headline_status),
        assessment_completeness=latest.assessment_completeness,
        findings_total=latest.findings_total,
        findings_open=latest.findings_open,
        findings_resolved=latest.findings_resolved,
        regression_count=latest.regression_count,
        coverage_limitation_count=latest.coverage_limitation_count,
        severity_counts=dict(latest.severity_counts or {}),
    )


def _row_from_parts(
    operation: Operation,
    coverage: OperationCoverageSummary | None,
    diff: OperationDiffSummary | None,
    baseline_completed_at: datetime | None,
    reports: list[AssessmentReport],
) -> AssessmentHistoryRow:
    status = operation.status
    completeness = "complete" if status == "completed" else "incomplete"
    return AssessmentHistoryRow(
        operation_id=operation.id,
        status=status,
        source=operation.source,
        testing_profile=operation.testing_profile,
        created_at=operation.created_at,
        started_at=operation.started_at,
        ended_at=operation_ended_at(operation),
        completed_at=operation.completed_at,
        failed_at=operation.failed_at,
        stopped_at=operation.stopped_at,
        error_code=operation.error_code,
        error_message=operation.error_message,
        completeness=completeness,
        coverage=coverage_from_row(coverage) if coverage is not None else None,
        comparison=(
            comparison_from_row(diff, baseline_completed_at) if diff is not None else None
        ),
        surface_changes=surface_changes_from_row(diff) if diff is not None else None,
        signals=signals_from_row(diff) if diff is not None else None,
        latest_report=_report_from_rows(reports),
    )


def list_assessment_history(
    db: Session,
    *,
    target: AuthorizedTarget,
    page_size: int = DEFAULT_PAGE_SIZE,
    cursor: str | None = None,
) -> AssessmentHistoryResponse:
    size = min(max(page_size, 1), MAX_PAGE_SIZE)
    ended_at = ended_at_expr()
    stmt = (
        select(Operation)
        .where(
            Operation.target_id == target.id,
            Operation.organization_id == target.organization_id,
            Operation.status.in_(TERMINAL_HISTORY_STATUSES),
        )
        .order_by(ended_at.desc(), Operation.id.desc())
        .limit(size + 1)
    )
    if cursor:
        cursor_ended_at, cursor_id = decode_history_cursor(cursor)
        stmt = stmt.where(
            or_(
                ended_at < cursor_ended_at,
                and_(ended_at == cursor_ended_at, Operation.id < cursor_id),
            )
        )

    operations = list(db.scalars(stmt).all())
    has_more = len(operations) > size
    page = operations[:size]
    next_cursor = None
    if has_more and page:
        last = page[-1]
        next_cursor = encode_history_cursor(
            ended_at=operation_ended_at(last), operation_id=last.id
        )

    if not page:
        return AssessmentHistoryResponse(
            target_id=target.id,
            target_domain=target.domain,
            page_size=size,
            next_cursor=None,
            items=[],
        )

    operation_ids = [row.id for row in page]
    coverage_rows = list(
        db.scalars(
            select(OperationCoverageSummary)
            .options(defer(OperationCoverageSummary.capability_snapshot))
            .where(OperationCoverageSummary.operation_id.in_(operation_ids))
        ).all()
    )
    diff_rows = list(
        db.scalars(
            select(OperationDiffSummary)
            .options(
                defer(OperationDiffSummary.comparison_snapshot),
                defer(OperationDiffSummary.changes),
            )
            .where(OperationDiffSummary.operation_id.in_(operation_ids))
        ).all()
    )
    report_rows = list(
        db.scalars(
            select(AssessmentReport)
            .options(
                load_only(
                    AssessmentReport.id,
                    AssessmentReport.operation_id,
                    AssessmentReport.report_version,
                    AssessmentReport.generation_origin,
                    AssessmentReport.generated_at,
                    AssessmentReport.headline_status,
                    AssessmentReport.assessment_completeness,
                    AssessmentReport.findings_total,
                    AssessmentReport.findings_open,
                    AssessmentReport.findings_resolved,
                    AssessmentReport.regression_count,
                    AssessmentReport.coverage_limitation_count,
                    AssessmentReport.severity_counts,
                )
            )
            .where(AssessmentReport.operation_id.in_(operation_ids))
        ).all()
    )

    coverage_by_op = {row.operation_id: row for row in coverage_rows}
    diff_by_op = {row.operation_id: row for row in diff_rows}
    reports_by_op: dict[UUID, list[AssessmentReport]] = {}
    for report in report_rows:
        reports_by_op.setdefault(report.operation_id, []).append(report)

    baseline_ids = {
        row.baseline_operation_id
        for row in diff_rows
        if row.baseline_operation_id is not None
    }
    baseline_completed: dict[UUID, datetime | None] = {}
    if baseline_ids:
        baseline_completed = {
            row.id: row.completed_at
            for row in db.scalars(
                select(Operation)
                .options(load_only(Operation.id, Operation.completed_at))
                .where(Operation.id.in_(baseline_ids))
            ).all()
        }

    items = [
        _row_from_parts(
            operation,
            coverage_by_op.get(operation.id),
            diff_by_op.get(operation.id),
            baseline_completed.get(diff_by_op[operation.id].baseline_operation_id)
            if operation.id in diff_by_op
            and diff_by_op[operation.id].baseline_operation_id is not None
            else None,
            reports_by_op.get(operation.id, []),
        )
        for operation in page
    ]
    return AssessmentHistoryResponse(
        target_id=target.id,
        target_domain=target.domain,
        page_size=size,
        next_cursor=next_cursor,
        items=items,
    )
