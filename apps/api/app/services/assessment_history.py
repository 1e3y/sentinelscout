"""Read-only target assessment history. Frozen M17/M18 + report metadata only."""

from __future__ import annotations

import binascii
from base64 import urlsafe_b64decode, urlsafe_b64encode
from datetime import datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session, defer, load_only

from app.models.coverage import OperationCoverageSummary
from app.models.diff import OperationDiffSummary
from app.models.operation import Operation
from app.models.report import AssessmentReport
from app.models.target import AuthorizedTarget
from app.schemas.assessment_history import (
    AssessmentHistoryComparison,
    AssessmentHistoryCoverage,
    AssessmentHistoryLatestReport,
    AssessmentHistoryResponse,
    AssessmentHistoryRow,
    AssessmentHistorySignals,
    AssessmentHistorySurfaceChanges,
    CoverageRatioResponse,
)
from app.services.diff import (
    CHANGE_CANDIDATE_GONE,
    CHANGE_CANDIDATE_NEW,
    CHANGE_HOSTNAME_NEWLY_DISCOVERED,
    CHANGE_HOSTNAME_NO_LONGER_DISCOVERED,
    CHANGE_HTTP_OBSERVATION_GAINED,
    CHANGE_HTTP_OBSERVATION_LOST,
    CHANGE_REGRESSION_HEADER_EVIDENCE,
    CHANGE_REGRESSION_HSTS,
    CHANGE_REGRESSION_RESOLVED,
    COMPARABILITY_COMPARABLE,
    COMPARABILITY_PARTIAL_CAPABILITY,
)
from app.services.reports.summary import HEADLINE_LABELS

TERMINAL_HISTORY_STATUSES = frozenset({"completed", "failed", "stopped"})
DEFAULT_PAGE_SIZE = 20
MAX_PAGE_SIZE = 50
CURSOR_VERSION = "v1"
INVALID_CURSOR_DETAIL = "Invalid assessment history cursor"

_SURFACE_COMPARABLE = frozenset(
    {COMPARABILITY_COMPARABLE, COMPARABILITY_PARTIAL_CAPABILITY}
)


def operation_ended_at(operation: Operation) -> datetime:
    return (
        operation.completed_at
        or operation.failed_at
        or operation.stopped_at
        or operation.created_at
    )


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


def _ended_at_expr():
    return func.coalesce(
        Operation.completed_at,
        Operation.failed_at,
        Operation.stopped_at,
        Operation.created_at,
    )


def _int_count(counts: dict[str, Any], key: str) -> int:
    raw = counts.get(key, 0)
    try:
        return int(raw or 0)
    except (TypeError, ValueError):
        return 0


def _ratio_from_surface(surface: dict[str, Any]) -> CoverageRatioResponse | None:
    obtained = int(surface.get("http_observation_obtained") or 0)
    discovered = int(surface.get("in_scope_discovered") or 0)
    raw = (surface.get("ratios") or {}).get(
        "http_observation_obtained_of_in_scope_discovered"
    )
    if isinstance(raw, dict) and "numerator" in raw and "denominator" in raw:
        denominator = int(raw.get("denominator") or 0)
        numerator = int(raw.get("numerator") or 0)
        value = raw.get("value")
        if denominator <= 0:
            return CoverageRatioResponse(
                numerator=numerator, denominator=denominator, value=None
            )
        if value is None:
            value = round(numerator / denominator, 4)
        return CoverageRatioResponse(
            numerator=numerator, denominator=denominator, value=float(value)
        )
    if discovered <= 0:
        return CoverageRatioResponse(
            numerator=obtained, denominator=discovered, value=None
        )
    return CoverageRatioResponse(
        numerator=obtained,
        denominator=discovered,
        value=round(obtained / discovered, 4),
    )


def _coverage_from_row(
    row: OperationCoverageSummary,
) -> AssessmentHistoryCoverage:
    surface = dict(row.surface or {})
    http_evidence = dict(row.http_evidence or {})
    scope = dict(row.scope_boundaries or {})
    return AssessmentHistoryCoverage(
        frozen_at=row.frozen_at,
        source=row.source,
        operation_status_at_freeze=row.operation_status_at_freeze,
        capability_manifest_version=int(row.capability_manifest_version),
        headline=row.headline,
        in_scope_discovered=int(surface.get("in_scope_discovered") or 0),
        submitted_for_http_observation=int(
            surface.get("submitted_for_http_observation") or 0
        ),
        http_observation_obtained=int(surface.get("http_observation_obtained") or 0),
        http_observation_not_obtained=int(
            surface.get("http_observation_not_obtained") or 0
        ),
        incomplete_hostnames=int(surface.get("incomplete") or 0),
        surface_coverage_ratio=_ratio_from_surface(surface),
        headers_captured=int(http_evidence.get("headers_captured") or 0),
        http_observations=int(http_evidence.get("http_observations") or 0),
        header_evidence_unavailable=int(
            http_evidence.get("header_evidence_unavailable") or 0
        ),
        discovery_truncated=bool(scope.get("discovery_truncated")),
        discovered_results_discarded=int(
            scope.get("discovered_results_discarded") or 0
        ),
    )


def _comparison_from_row(
    row: OperationDiffSummary,
    baseline_completed_at: datetime | None,
) -> AssessmentHistoryComparison:
    return AssessmentHistoryComparison(
        comparability=row.comparability,
        baseline_operation_id=row.baseline_operation_id,
        baseline_completed_at=baseline_completed_at,
        headline=row.headline,
        security_signal_baseline_unavailable=bool(
            row.security_signal_baseline_unavailable
        ),
        security_signal_comparison_suppressed=bool(
            row.security_signal_comparison_suppressed
        ),
        security_signal_suppression_reason=row.security_signal_suppression_reason,
    )


def _surface_changes_from_row(
    row: OperationDiffSummary,
) -> AssessmentHistorySurfaceChanges | None:
    if row.comparability not in _SURFACE_COMPARABLE:
        return None
    counts = dict(row.counts or {})
    return AssessmentHistorySurfaceChanges(
        hostnames_newly_discovered=_int_count(counts, CHANGE_HOSTNAME_NEWLY_DISCOVERED),
        hostnames_no_longer_discovered=_int_count(
            counts, CHANGE_HOSTNAME_NO_LONGER_DISCOVERED
        ),
        http_observation_gained=_int_count(counts, CHANGE_HTTP_OBSERVATION_GAINED),
        http_observation_lost=_int_count(counts, CHANGE_HTTP_OBSERVATION_LOST),
    )


def _signals_from_row(row: OperationDiffSummary) -> AssessmentHistorySignals | None:
    if row.comparability != COMPARABILITY_COMPARABLE:
        return None
    if row.security_signal_comparison_suppressed:
        return None
    if row.security_signal_baseline_unavailable:
        return None
    counts = dict(row.counts or {})
    return AssessmentHistorySignals(
        candidates_newly_emitted=_int_count(counts, CHANGE_CANDIDATE_NEW),
        candidates_no_longer_emitted=_int_count(counts, CHANGE_CANDIDATE_GONE),
        conservative_regressions=_int_count(counts, "regressions"),
        regression_hsts_lost=_int_count(counts, CHANGE_REGRESSION_HSTS),
        regression_resolved_condition_reappeared=_int_count(
            counts, CHANGE_REGRESSION_RESOLVED
        ),
        regression_header_evidence_lost=_int_count(
            counts, CHANGE_REGRESSION_HEADER_EVIDENCE
        ),
    )


def _report_from_rows(
    rows: list[AssessmentReport],
) -> AssessmentHistoryLatestReport | None:
    if not rows:
        return None
    latest = max(rows, key=lambda row: row.report_version)
    return AssessmentHistoryLatestReport(
        id=latest.id,
        report_version=latest.report_version,
        version_count=len(rows),
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
        coverage=_coverage_from_row(coverage) if coverage is not None else None,
        comparison=(
            _comparison_from_row(diff, baseline_completed_at)
            if diff is not None
            else None
        ),
        surface_changes=_surface_changes_from_row(diff) if diff is not None else None,
        signals=_signals_from_row(diff) if diff is not None else None,
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
    ended_at_expr = _ended_at_expr()
    stmt = (
        select(Operation)
        .where(
            Operation.target_id == target.id,
            Operation.organization_id == target.organization_id,
            Operation.status.in_(TERMINAL_HISTORY_STATUSES),
        )
        .order_by(ended_at_expr.desc(), Operation.id.desc())
        .limit(size + 1)
    )
    if cursor:
        cursor_ended_at, cursor_id = decode_history_cursor(cursor)
        stmt = stmt.where(
            or_(
                ended_at_expr < cursor_ended_at,
                and_(ended_at_expr == cursor_ended_at, Operation.id < cursor_id),
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
