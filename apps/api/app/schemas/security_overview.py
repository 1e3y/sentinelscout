from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.assessment_history import (
    AssessmentHistoryComparison,
    AssessmentHistoryCoverage,
    AssessmentHistorySignals,
)

AttentionProvenance = Literal["operation_history", "frozen_assessment", "current_state"]
StalenessBasis = Literal["monitoring_cadence", "not_applicable"]


class SecurityOverviewAttentionReason(BaseModel):
    """A factual reason to look at this target. Not a score, grade, or ranking."""

    model_config = ConfigDict(extra="forbid")

    code: str
    label: str
    provenance: AttentionProvenance


class SecurityOverviewLatestTerminal(BaseModel):
    """Most recent completed, failed, or stopped run. Not necessarily an assessment."""

    model_config = ConfigDict(extra="forbid")

    operation_id: UUID
    status: str
    source: str
    ended_at: datetime


class SecurityOverviewLatestCompleted(BaseModel):
    """Most recent completed run. The only source of frozen evidence on this row."""

    model_config = ConfigDict(extra="forbid")

    operation_id: UUID
    completed_at: datetime
    source: str


class SecurityOverviewReport(BaseModel):
    """Immutable report metadata. Never loads snapshot_json or report-time counts."""

    model_config = ConfigDict(extra="forbid")

    id: UUID
    report_version: int
    version_count: int
    generation_origin: str
    generated_at: datetime
    headline_status: str
    headline_label: str
    assessment_completeness: str


class SecurityOverviewAlerts(BaseModel):
    """Current alert-episode state. Not part of any frozen assessment snapshot."""

    model_config = ConfigDict(extra="forbid")

    active_episode_count: int
    unacknowledged_active_episode_count: int


class SecurityOverviewAutomation(BaseModel):
    """Current monitoring/report/delivery configuration. Recipient addresses excluded."""

    model_config = ConfigDict(extra="forbid")

    monitoring_enabled: bool
    frequency: str | None = None
    next_run_at: datetime | None = None
    last_run_at: datetime | None = None
    disabled_reason: str | None = None
    auto_generate_reports: bool
    auto_deliver_reports: bool
    auto_deliver_expires_in: str | None = None
    delivery_recipient_count: int
    email_delivery_enabled: bool


class SecurityOverviewStaleness(BaseModel):
    """Operational freshness against an active monitoring cadence. Not severity."""

    model_config = ConfigDict(extra="forbid")

    is_stale: bool | None = None
    threshold_days: int | None = None
    threshold_basis: StalenessBasis
    days_since_last_completed: int | None = None


class SecurityOverviewRow(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_id: UUID
    domain: str
    authorization_status: str
    verified_at: datetime | None = None
    revoked_at: datetime | None = None
    latest_terminal: SecurityOverviewLatestTerminal | None = None
    latest_completed: SecurityOverviewLatestCompleted | None = None
    coverage: AssessmentHistoryCoverage | None = None
    comparison: AssessmentHistoryComparison | None = None
    signals: AssessmentHistorySignals | None = None
    latest_report: SecurityOverviewReport | None = None
    alerts: SecurityOverviewAlerts
    automation: SecurityOverviewAutomation
    staleness: SecurityOverviewStaleness
    attention_reasons: list[SecurityOverviewAttentionReason] = Field(default_factory=list)


class SecurityOverviewSummary(BaseModel):
    """Counts across every target in the active organization, not just this page."""

    model_config = ConfigDict(extra="forbid")

    scope: Literal["organization"] = "organization"
    target_count: int
    verified_targets_without_completed_assessment: int
    targets_with_active_alert_episode: int


class SecurityOverviewResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    organization_id: UUID
    page_size: int
    sort: Literal["domain_asc"] = "domain_asc"
    next_cursor: str | None = None
    summary: SecurityOverviewSummary
    items: list[SecurityOverviewRow] = Field(default_factory=list)
