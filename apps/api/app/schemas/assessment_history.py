from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

AssessmentCompleteness = Literal["complete", "incomplete"]


class CoverageRatioResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    numerator: int
    denominator: int
    value: float | None = None


class AssessmentHistoryCoverage(BaseModel):
    """Frozen M17 discovery-layer projection. Null on the parent row if no freeze exists."""

    model_config = ConfigDict(extra="forbid")

    frozen_at: datetime
    source: str
    operation_status_at_freeze: str
    capability_manifest_version: int
    headline: str
    in_scope_discovered: int
    submitted_for_http_observation: int
    http_observation_obtained: int
    http_observation_not_obtained: int
    incomplete_hostnames: int
    surface_coverage_ratio: CoverageRatioResponse | None = None
    headers_captured: int
    http_observations: int
    header_evidence_unavailable: int
    discovery_truncated: bool
    discovered_results_discarded: int


class AssessmentHistoryComparison(BaseModel):
    """Frozen M18 comparison. Null on the parent row if no freeze exists."""

    model_config = ConfigDict(extra="forbid")

    comparability: str
    baseline_operation_id: UUID | None = None
    baseline_completed_at: datetime | None = None
    headline: str
    security_signal_baseline_unavailable: bool = False
    security_signal_comparison_suppressed: bool = False
    security_signal_suppression_reason: str | None = None


class AssessmentHistorySurfaceChanges(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hostnames_newly_discovered: int
    hostnames_no_longer_discovered: int
    http_observation_gained: int
    http_observation_lost: int


class AssessmentHistorySignals(BaseModel):
    """Frozen M18 candidate/regression counts. Never upgraded to finding language."""

    model_config = ConfigDict(extra="forbid")

    candidates_newly_emitted: int
    candidates_no_longer_emitted: int
    conservative_regressions: int
    regression_hsts_lost: int
    regression_resolved_condition_reappeared: int
    regression_header_evidence_lost: int


class AssessmentHistoryLatestReport(BaseModel):
    """Latest immutable report metadata. Does not include snapshot_json."""

    model_config = ConfigDict(extra="forbid")

    id: UUID
    report_version: int
    version_count: int
    generation_origin: str
    generated_at: datetime
    headline_status: str
    headline_label: str
    assessment_completeness: str
    findings_total: int
    findings_open: int
    findings_resolved: int
    regression_count: int
    coverage_limitation_count: int
    severity_counts: dict[str, Any] = Field(default_factory=dict)


class AssessmentHistoryRow(BaseModel):
    model_config = ConfigDict(extra="forbid")

    operation_id: UUID
    status: str
    source: str
    testing_profile: str
    created_at: datetime
    started_at: datetime | None = None
    ended_at: datetime
    completed_at: datetime | None = None
    failed_at: datetime | None = None
    stopped_at: datetime | None = None
    error_code: str | None = None
    error_message: str | None = None
    completeness: AssessmentCompleteness
    coverage: AssessmentHistoryCoverage | None = None
    comparison: AssessmentHistoryComparison | None = None
    surface_changes: AssessmentHistorySurfaceChanges | None = None
    signals: AssessmentHistorySignals | None = None
    latest_report: AssessmentHistoryLatestReport | None = None


class AssessmentHistoryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_id: UUID
    target_domain: str
    page_size: int
    next_cursor: str | None = None
    items: list[AssessmentHistoryRow] = Field(default_factory=list)
