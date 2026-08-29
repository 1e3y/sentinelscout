"""Read-only organization security overview.

Combines three kinds of fact and never mixes them:

  operation_history  - which runs exist and how they ended
  frozen_assessment  - M17 coverage / M18 comparison / immutable report metadata
  current_state      - open alert episodes, monitoring and delivery configuration

There is no score, grade, weighting, or ranking anywhere in this module. Attention is
an unordered set of explicit boolean facts.
"""

from __future__ import annotations

import binascii
from base64 import urlsafe_b64decode, urlsafe_b64encode
from datetime import UTC, datetime
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import Select, and_, func, or_, select
from sqlalchemy.orm import Session, defer, load_only

from app.models.alert import Alert, AlertEpisode
from app.models.coverage import OperationCoverageSummary
from app.models.diff import OperationDiffSummary
from app.models.monitoring import (
    MonitoringConfiguration,
    MonitoringReportDeliveryRecipient,
)
from app.models.operation import Operation
from app.models.organization import Organization
from app.models.report import AssessmentReport
from app.models.target import AuthorizedTarget
from app.schemas.assessment_history import (
    AssessmentHistoryComparison,
    AssessmentHistoryCoverage,
    AssessmentHistorySignals,
)
from app.schemas.security_overview import (
    SecurityOverviewAlerts,
    SecurityOverviewAttentionReason,
    SecurityOverviewAutomation,
    SecurityOverviewLatestCompleted,
    SecurityOverviewLatestTerminal,
    SecurityOverviewReport,
    SecurityOverviewResponse,
    SecurityOverviewRow,
    SecurityOverviewStaleness,
    SecurityOverviewSummary,
)
from app.services.diff import COMPARABILITY_COMPARABLE
from app.services.frozen_projection import (
    comparison_from_row,
    coverage_from_row,
    ended_at_expr,
    operation_ended_at,
    select_latest_report,
    signals_from_row,
)
from app.services.reports.summary import HEADLINE_LABELS

DEFAULT_PAGE_SIZE = 20
MAX_PAGE_SIZE = 50
CURSOR_VERSION = "v1"
INVALID_CURSOR_DETAIL = "Invalid security overview cursor"

TERMINAL_STATUSES = frozenset({"completed", "failed", "stopped"})
VERIFIED_STATUS = "verified"

REASON_NO_COMPLETED_ASSESSMENT = "NO_COMPLETED_ASSESSMENT"
REASON_LATEST_ASSESSMENT_INCOMPLETE = "LATEST_ASSESSMENT_INCOMPLETE"
REASON_FROZEN_REGRESSION_PRESENT = "FROZEN_REGRESSION_PRESENT"
REASON_COVERAGE_UNAVAILABLE = "COVERAGE_UNAVAILABLE"
REASON_COVERAGE_LIMITED = "COVERAGE_LIMITED"
REASON_COMPARISON_UNAVAILABLE = "COMPARISON_UNAVAILABLE"
REASON_ACTIVE_ALERT_EPISODE = "ACTIVE_ALERT_EPISODE"
REASON_ASSESSMENT_STALE = "ASSESSMENT_STALE"

ATTENTION_LABELS: dict[str, str] = {
    REASON_NO_COMPLETED_ASSESSMENT: "No completed assessment",
    REASON_LATEST_ASSESSMENT_INCOMPLETE: "Latest run did not complete",
    REASON_FROZEN_REGRESSION_PRESENT: "Frozen security regressions recorded",
    REASON_COVERAGE_UNAVAILABLE: "Coverage snapshot unavailable",
    REASON_COVERAGE_LIMITED: "Coverage limitations recorded",
    REASON_COMPARISON_UNAVAILABLE: "Comparison unavailable",
    REASON_ACTIVE_ALERT_EPISODE: "Active alert episode",
    REASON_ASSESSMENT_STALE: "Assessment older than monitoring cadence",
}

ATTENTION_PROVENANCE: dict[str, str] = {
    REASON_NO_COMPLETED_ASSESSMENT: "operation_history",
    REASON_LATEST_ASSESSMENT_INCOMPLETE: "operation_history",
    REASON_FROZEN_REGRESSION_PRESENT: "frozen_assessment",
    REASON_COVERAGE_UNAVAILABLE: "frozen_assessment",
    REASON_COVERAGE_LIMITED: "frozen_assessment",
    REASON_COMPARISON_UNAVAILABLE: "frozen_assessment",
    REASON_ACTIVE_ALERT_EPISODE: "current_state",
    REASON_ASSESSMENT_STALE: "current_state",
}

# Two expected intervals of the configured cadence. Mirrors compute_next_run_at.
STALENESS_THRESHOLD_DAYS: dict[str, int] = {"daily": 2, "weekly": 14}

_NO_ALERTS = SecurityOverviewAlerts(
    active_episode_count=0, unacknowledged_active_episode_count=0
)


def encode_overview_cursor(*, domain: str, target_id: UUID) -> str:
    payload = f"{CURSOR_VERSION}|{domain}|{target_id}"
    return urlsafe_b64encode(payload.encode("utf-8")).decode("ascii").rstrip("=")


def decode_overview_cursor(raw: str) -> tuple[str, UUID]:
    padded = raw + ("=" * (-len(raw) % 4))
    try:
        decoded = urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
        raise _invalid_cursor() from exc
    parts = decoded.split("|")
    if len(parts) < 3 or parts[0] != CURSOR_VERSION:
        raise _invalid_cursor()
    # Rejoin the middle so a delimiter inside a domain cannot shift the target id.
    domain = "|".join(parts[1:-1])
    try:
        target_id = UUID(parts[-1])
    except (AttributeError, TypeError, ValueError) as exc:
        raise _invalid_cursor() from exc
    if not domain:
        raise _invalid_cursor()
    return domain, target_id


def _invalid_cursor() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST, detail=INVALID_CURSOR_DETAIL
    )


def _reason(code: str) -> SecurityOverviewAttentionReason:
    return SecurityOverviewAttentionReason(
        code=code,
        label=ATTENTION_LABELS[code],
        provenance=ATTENTION_PROVENANCE[code],
    )


def _target_page(
    *, organization_id: UUID, size: int, cursor: str | None
) -> Select[tuple[AuthorizedTarget]]:
    stmt = (
        select(AuthorizedTarget)
        .options(
            load_only(
                AuthorizedTarget.id,
                AuthorizedTarget.organization_id,
                AuthorizedTarget.domain,
                AuthorizedTarget.status,
                AuthorizedTarget.verified_at,
                AuthorizedTarget.revoked_at,
            )
        )
        .where(AuthorizedTarget.organization_id == organization_id)
        .order_by(AuthorizedTarget.domain.asc(), AuthorizedTarget.id.asc())
        .limit(size + 1)
    )
    if cursor:
        cursor_domain, cursor_id = decode_overview_cursor(cursor)
        stmt = stmt.where(
            or_(
                AuthorizedTarget.domain > cursor_domain,
                and_(
                    AuthorizedTarget.domain == cursor_domain,
                    AuthorizedTarget.id > cursor_id,
                ),
            )
        )
    return stmt


def _latest_terminal_by_target(
    db: Session, *, organization_id: UUID, target_ids: list[UUID]
) -> dict[UUID, Operation]:
    ended_at = ended_at_expr()
    rows = db.scalars(
        select(Operation)
        .distinct(Operation.target_id)
        .where(
            Operation.organization_id == organization_id,
            Operation.target_id.in_(target_ids),
            Operation.status.in_(TERMINAL_STATUSES),
        )
        .order_by(Operation.target_id, ended_at.desc(), Operation.id.desc())
    ).all()
    return {row.target_id: row for row in rows}


def _latest_completed_by_target(
    db: Session, *, organization_id: UUID, target_ids: list[UUID]
) -> dict[UUID, Operation]:
    rows = db.scalars(
        select(Operation)
        .distinct(Operation.target_id)
        .where(
            Operation.organization_id == organization_id,
            Operation.target_id.in_(target_ids),
            Operation.status == "completed",
            Operation.completed_at.is_not(None),
        )
        .order_by(
            Operation.target_id,
            Operation.completed_at.desc(),
            Operation.id.desc(),
        )
    ).all()
    return {row.target_id: row for row in rows}


def _alert_state_by_target(
    db: Session, *, organization_id: UUID, target_ids: list[UUID]
) -> dict[UUID, SecurityOverviewAlerts]:
    unacknowledged = (
        select(Alert.id)
        .where(Alert.episode_id == AlertEpisode.id, Alert.acknowledged_at.is_(None))
        .exists()
    )
    rows = db.execute(
        select(
            AlertEpisode.target_id,
            func.count().label("active"),
            func.count().filter(unacknowledged).label("unacknowledged"),
        )
        .where(
            AlertEpisode.organization_id == organization_id,
            AlertEpisode.target_id.in_(target_ids),
            AlertEpisode.status == "open",
        )
        .group_by(AlertEpisode.target_id)
    ).all()
    return {
        row.target_id: SecurityOverviewAlerts(
            active_episode_count=int(row.active or 0),
            unacknowledged_active_episode_count=int(row.unacknowledged or 0),
        )
        for row in rows
    }


def _automation_for(
    config: MonitoringConfiguration | None,
    *,
    recipient_count: int,
    email_delivery_enabled: bool,
) -> SecurityOverviewAutomation:
    if config is None:
        return SecurityOverviewAutomation(
            monitoring_enabled=False,
            frequency=None,
            next_run_at=None,
            last_run_at=None,
            disabled_reason=None,
            auto_generate_reports=False,
            auto_deliver_reports=False,
            auto_deliver_expires_in=None,
            delivery_recipient_count=0,
            email_delivery_enabled=email_delivery_enabled,
        )
    return SecurityOverviewAutomation(
        monitoring_enabled=bool(config.enabled),
        frequency=config.frequency,
        next_run_at=config.next_run_at,
        last_run_at=config.last_run_at,
        disabled_reason=config.disabled_reason,
        auto_generate_reports=bool(config.auto_generate_reports),
        auto_deliver_reports=bool(config.auto_deliver_reports),
        auto_deliver_expires_in=config.auto_deliver_expires_in,
        delivery_recipient_count=recipient_count,
        email_delivery_enabled=email_delivery_enabled,
    )


def _staleness_for(
    *,
    target_status: str,
    config: MonitoringConfiguration | None,
    completed_at: datetime | None,
    now: datetime,
) -> SecurityOverviewStaleness:
    """Freshness against an active cadence only. Absent cadence means unknown, not fresh."""
    if completed_at is None:
        return SecurityOverviewStaleness(
            is_stale=None,
            threshold_days=None,
            threshold_basis="not_applicable",
            days_since_last_completed=None,
        )
    reference = completed_at
    if reference.tzinfo is None:
        reference = reference.replace(tzinfo=UTC)
    elapsed = now - reference
    days_since = max(int(elapsed.total_seconds() // 86400), 0)

    # A cadence only defines expected freshness while monitoring can actually run.
    cadence_active = (
        config is not None
        and bool(config.enabled)
        and target_status == VERIFIED_STATUS
        and config.frequency in STALENESS_THRESHOLD_DAYS
    )
    if not cadence_active:
        return SecurityOverviewStaleness(
            is_stale=None,
            threshold_days=None,
            threshold_basis="not_applicable",
            days_since_last_completed=days_since,
        )

    assert config is not None
    threshold_days = STALENESS_THRESHOLD_DAYS[config.frequency]
    return SecurityOverviewStaleness(
        is_stale=elapsed.total_seconds() > threshold_days * 86400,
        threshold_days=threshold_days,
        threshold_basis="monitoring_cadence",
        days_since_last_completed=days_since,
    )


def _coverage_is_limited(coverage: AssessmentHistoryCoverage) -> bool:
    return (
        coverage.http_observation_not_obtained > 0
        or coverage.incomplete_hostnames > 0
        or coverage.discovery_truncated
        or coverage.header_evidence_unavailable > 0
    )


def _comparison_is_unavailable(comparison: AssessmentHistoryComparison | None) -> bool:
    if comparison is None:
        return True
    return (
        comparison.comparability != COMPARABILITY_COMPARABLE
        or comparison.security_signal_comparison_suppressed
        or comparison.security_signal_baseline_unavailable
    )


def _attention_reasons(
    *,
    target_status: str,
    latest_terminal: Operation | None,
    latest_completed: Operation | None,
    coverage: AssessmentHistoryCoverage | None,
    comparison: AssessmentHistoryComparison | None,
    signals: AssessmentHistorySignals | None,
    alerts: SecurityOverviewAlerts,
    staleness: SecurityOverviewStaleness,
) -> list[SecurityOverviewAttentionReason]:
    """Independent boolean facts. Emission order is declaration order, not priority."""
    verified = target_status == VERIFIED_STATUS
    codes: list[str] = []

    if latest_completed is None and verified:
        codes.append(REASON_NO_COMPLETED_ASSESSMENT)
    if latest_terminal is not None and latest_terminal.status != "completed":
        codes.append(REASON_LATEST_ASSESSMENT_INCOMPLETE)
    if signals is not None and signals.conservative_regressions > 0:
        codes.append(REASON_FROZEN_REGRESSION_PRESENT)
    if latest_completed is not None and coverage is None:
        codes.append(REASON_COVERAGE_UNAVAILABLE)
    if coverage is not None and _coverage_is_limited(coverage):
        codes.append(REASON_COVERAGE_LIMITED)
    if latest_completed is not None and _comparison_is_unavailable(comparison):
        codes.append(REASON_COMPARISON_UNAVAILABLE)
    if alerts.active_episode_count > 0:
        codes.append(REASON_ACTIVE_ALERT_EPISODE)
    if staleness.is_stale is True:
        codes.append(REASON_ASSESSMENT_STALE)

    return [_reason(code) for code in codes]


def _report_for(rows: list[AssessmentReport]) -> SecurityOverviewReport | None:
    selected = select_latest_report(rows)
    if selected is None:
        return None
    latest, version_count = selected
    return SecurityOverviewReport(
        id=latest.id,
        report_version=latest.report_version,
        version_count=version_count,
        generation_origin=latest.generation_origin,
        generated_at=latest.generated_at,
        headline_status=latest.headline_status,
        headline_label=HEADLINE_LABELS.get(latest.headline_status, latest.headline_status),
        assessment_completeness=latest.assessment_completeness,
    )


def _organization_summary(
    db: Session, *, organization_id: UUID
) -> SecurityOverviewSummary:
    target_count = int(
        db.scalar(
            select(func.count())
            .select_from(AuthorizedTarget)
            .where(AuthorizedTarget.organization_id == organization_id)
        )
        or 0
    )
    completed_exists = (
        select(Operation.id)
        .where(
            Operation.target_id == AuthorizedTarget.id,
            Operation.status == "completed",
        )
        .exists()
    )
    verified_without_completed = int(
        db.scalar(
            select(func.count())
            .select_from(AuthorizedTarget)
            .where(
                AuthorizedTarget.organization_id == organization_id,
                AuthorizedTarget.status == VERIFIED_STATUS,
                ~completed_exists,
            )
        )
        or 0
    )
    with_active_alerts = int(
        db.scalar(
            select(func.count(func.distinct(AlertEpisode.target_id))).where(
                AlertEpisode.organization_id == organization_id,
                AlertEpisode.status == "open",
            )
        )
        or 0
    )
    return SecurityOverviewSummary(
        target_count=target_count,
        verified_targets_without_completed_assessment=verified_without_completed,
        targets_with_active_alert_episode=with_active_alerts,
    )


def list_security_overview(
    db: Session,
    *,
    organization: Organization,
    email_delivery_enabled: bool,
    page_size: int = DEFAULT_PAGE_SIZE,
    cursor: str | None = None,
    now: datetime | None = None,
) -> SecurityOverviewResponse:
    organization_id = organization.id
    size = min(max(page_size, 1), MAX_PAGE_SIZE)
    moment = now or datetime.now(UTC)

    targets = list(
        db.scalars(
            _target_page(organization_id=organization_id, size=size, cursor=cursor)
        ).all()
    )
    has_more = len(targets) > size
    page = targets[:size]
    next_cursor = None
    if has_more and page:
        last = page[-1]
        next_cursor = encode_overview_cursor(domain=last.domain, target_id=last.id)

    summary = _organization_summary(db, organization_id=organization_id)
    if not page:
        return SecurityOverviewResponse(
            organization_id=organization_id,
            page_size=size,
            next_cursor=None,
            summary=summary,
            items=[],
        )

    target_ids = [target.id for target in page]
    latest_terminal = _latest_terminal_by_target(
        db, organization_id=organization_id, target_ids=target_ids
    )
    latest_completed = _latest_completed_by_target(
        db, organization_id=organization_id, target_ids=target_ids
    )
    completed_ids = [row.id for row in latest_completed.values()]

    coverage_by_op: dict[UUID, OperationCoverageSummary] = {}
    diff_by_op: dict[UUID, OperationDiffSummary] = {}
    reports_by_op: dict[UUID, list[AssessmentReport]] = {}
    baseline_completed: dict[UUID, datetime | None] = {}
    if completed_ids:
        coverage_by_op = {
            row.operation_id: row
            for row in db.scalars(
                select(OperationCoverageSummary)
                .options(defer(OperationCoverageSummary.capability_snapshot))
                .where(OperationCoverageSummary.operation_id.in_(completed_ids))
            ).all()
        }
        diff_rows = list(
            db.scalars(
                select(OperationDiffSummary)
                .options(
                    defer(OperationDiffSummary.comparison_snapshot),
                    defer(OperationDiffSummary.changes),
                )
                .where(OperationDiffSummary.operation_id.in_(completed_ids))
            ).all()
        )
        diff_by_op = {row.operation_id: row for row in diff_rows}
        for report in db.scalars(
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
                )
            )
            .where(AssessmentReport.operation_id.in_(completed_ids))
        ).all():
            reports_by_op.setdefault(report.operation_id, []).append(report)

        baseline_ids = {
            row.baseline_operation_id
            for row in diff_rows
            if row.baseline_operation_id is not None
        }
        if baseline_ids:
            baseline_completed = {
                row.id: row.completed_at
                for row in db.scalars(
                    select(Operation)
                    .options(load_only(Operation.id, Operation.completed_at))
                    .where(Operation.id.in_(baseline_ids))
                ).all()
            }

    monitoring_by_target = {
        row.target_id: row
        for row in db.scalars(
            select(MonitoringConfiguration).where(
                MonitoringConfiguration.organization_id == organization_id,
                MonitoringConfiguration.target_id.in_(target_ids),
            )
        ).all()
    }
    # Count only. Recipient addresses are never selected into this process.
    recipient_counts = {
        row.target_id: int(row.recipient_count or 0)
        for row in db.execute(
            select(
                MonitoringReportDeliveryRecipient.target_id,
                func.count().label("recipient_count"),
            )
            .where(
                MonitoringReportDeliveryRecipient.organization_id == organization_id,
                MonitoringReportDeliveryRecipient.target_id.in_(target_ids),
            )
            .group_by(MonitoringReportDeliveryRecipient.target_id)
        ).all()
    }
    alerts_by_target = _alert_state_by_target(
        db, organization_id=organization_id, target_ids=target_ids
    )

    items: list[SecurityOverviewRow] = []
    for target in page:
        terminal = latest_terminal.get(target.id)
        completed = latest_completed.get(target.id)
        coverage_row = coverage_by_op.get(completed.id) if completed else None
        diff_row = diff_by_op.get(completed.id) if completed else None
        reports = reports_by_op.get(completed.id, []) if completed else []

        coverage = coverage_from_row(coverage_row) if coverage_row is not None else None
        comparison = None
        signals = None
        if diff_row is not None:
            baseline_at = (
                baseline_completed.get(diff_row.baseline_operation_id)
                if diff_row.baseline_operation_id is not None
                else None
            )
            comparison = comparison_from_row(diff_row, baseline_at)
            signals = signals_from_row(diff_row)

        config = monitoring_by_target.get(target.id)
        alerts = alerts_by_target.get(target.id, _NO_ALERTS)
        staleness = _staleness_for(
            target_status=target.status,
            config=config,
            completed_at=completed.completed_at if completed else None,
            now=moment,
        )

        items.append(
            SecurityOverviewRow(
                target_id=target.id,
                domain=target.domain,
                authorization_status=target.status,
                verified_at=target.verified_at,
                revoked_at=target.revoked_at,
                latest_terminal=(
                    SecurityOverviewLatestTerminal(
                        operation_id=terminal.id,
                        status=terminal.status,
                        source=terminal.source,
                        ended_at=operation_ended_at(terminal),
                    )
                    if terminal is not None
                    else None
                ),
                latest_completed=(
                    SecurityOverviewLatestCompleted(
                        operation_id=completed.id,
                        completed_at=completed.completed_at,
                        source=completed.source,
                    )
                    if completed is not None
                    else None
                ),
                coverage=coverage,
                comparison=comparison,
                signals=signals,
                latest_report=_report_for(reports),
                alerts=alerts,
                automation=_automation_for(
                    config,
                    recipient_count=recipient_counts.get(target.id, 0),
                    email_delivery_enabled=email_delivery_enabled,
                ),
                staleness=staleness,
                attention_reasons=_attention_reasons(
                    target_status=target.status,
                    latest_terminal=terminal,
                    latest_completed=completed,
                    coverage=coverage,
                    comparison=comparison,
                    signals=signals,
                    alerts=alerts,
                    staleness=staleness,
                ),
            )
        )

    return SecurityOverviewResponse(
        organization_id=organization_id,
        page_size=size,
        next_cursor=next_cursor,
        summary=summary,
        items=items,
    )
