"""Shared read-only projection of frozen M17/M18 rows and immutable report metadata.

Every consumer (M28 target history, M29 organization overview) must project frozen
evidence through this module so comparability gating and coverage semantics have a
single implementation.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import func

from app.models.coverage import OperationCoverageSummary
from app.models.diff import OperationDiffSummary
from app.models.operation import Operation
from app.models.report import AssessmentReport
from app.schemas.assessment_history import (
    AssessmentHistoryComparison,
    AssessmentHistoryCoverage,
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

SURFACE_COMPARABLE = frozenset({COMPARABILITY_COMPARABLE, COMPARABILITY_PARTIAL_CAPABILITY})


def operation_ended_at(operation: Operation) -> datetime:
    return (
        operation.completed_at
        or operation.failed_at
        or operation.stopped_at
        or operation.created_at
    )


def ended_at_expr():
    return func.coalesce(
        Operation.completed_at,
        Operation.failed_at,
        Operation.stopped_at,
        Operation.created_at,
    )


def int_count(counts: dict[str, Any], key: str) -> int:
    raw = counts.get(key, 0)
    try:
        return int(raw or 0)
    except (TypeError, ValueError):
        return 0


def ratio_from_surface(surface: dict[str, Any]) -> CoverageRatioResponse | None:
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


def coverage_from_row(row: OperationCoverageSummary) -> AssessmentHistoryCoverage:
    """Project the stored M17 freeze. Never rebuilds the headline from live state."""
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
        surface_coverage_ratio=ratio_from_surface(surface),
        headers_captured=int(http_evidence.get("headers_captured") or 0),
        http_observations=int(http_evidence.get("http_observations") or 0),
        header_evidence_unavailable=int(
            http_evidence.get("header_evidence_unavailable") or 0
        ),
        discovery_truncated=bool(scope.get("discovery_truncated")),
        discovered_results_discarded=int(scope.get("discovered_results_discarded") or 0),
    )


def comparison_from_row(
    row: OperationDiffSummary,
    baseline_completed_at: datetime | None,
) -> AssessmentHistoryComparison:
    return AssessmentHistoryComparison(
        comparability=row.comparability,
        baseline_operation_id=row.baseline_operation_id,
        baseline_completed_at=baseline_completed_at,
        headline=row.headline,
        security_signal_baseline_unavailable=bool(row.security_signal_baseline_unavailable),
        security_signal_comparison_suppressed=bool(row.security_signal_comparison_suppressed),
        security_signal_suppression_reason=row.security_signal_suppression_reason,
    )


def surface_changes_from_row(
    row: OperationDiffSummary,
) -> AssessmentHistorySurfaceChanges | None:
    if row.comparability not in SURFACE_COMPARABLE:
        return None
    counts = dict(row.counts or {})
    return AssessmentHistorySurfaceChanges(
        hostnames_newly_discovered=int_count(counts, CHANGE_HOSTNAME_NEWLY_DISCOVERED),
        hostnames_no_longer_discovered=int_count(
            counts, CHANGE_HOSTNAME_NO_LONGER_DISCOVERED
        ),
        http_observation_gained=int_count(counts, CHANGE_HTTP_OBSERVATION_GAINED),
        http_observation_lost=int_count(counts, CHANGE_HTTP_OBSERVATION_LOST),
    )


def signals_are_supported(row: OperationDiffSummary) -> bool:
    """Frozen candidate/regression counts are only meaningful for an unsuppressed compare."""
    return (
        row.comparability == COMPARABILITY_COMPARABLE
        and not row.security_signal_comparison_suppressed
        and not row.security_signal_baseline_unavailable
    )


def signals_from_row(row: OperationDiffSummary) -> AssessmentHistorySignals | None:
    if not signals_are_supported(row):
        return None
    counts = dict(row.counts or {})
    return AssessmentHistorySignals(
        candidates_newly_emitted=int_count(counts, CHANGE_CANDIDATE_NEW),
        candidates_no_longer_emitted=int_count(counts, CHANGE_CANDIDATE_GONE),
        conservative_regressions=int_count(counts, "regressions"),
        regression_hsts_lost=int_count(counts, CHANGE_REGRESSION_HSTS),
        regression_resolved_condition_reappeared=int_count(
            counts, CHANGE_REGRESSION_RESOLVED
        ),
        regression_header_evidence_lost=int_count(counts, CHANGE_REGRESSION_HEADER_EVIDENCE),
    )


def select_latest_report(
    rows: list[AssessmentReport],
) -> tuple[AssessmentReport, int] | None:
    """Highest report_version plus the total version count for that operation."""
    if not rows:
        return None
    return max(rows, key=lambda row: row.report_version), len(rows)
