"""Organization audit trail explorer (Milestone 37).

Admin-only, active-org, fail-closed allowlist, JSON-scalar metadata only.
Never selects AuditEvent.metadata as a whole object.
"""

from __future__ import annotations

import binascii
from base64 import urlsafe_b64decode, urlsafe_b64encode
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import and_, or_, select, true
from sqlalchemy.orm import Session, load_only

from app.models.alert import Alert
from app.models.audit import AuditEvent
from app.models.finding import Finding
from app.models.operation import Operation
from app.models.report import AssessmentReport
from app.models.target import AuthorizedTarget
from app.models.user import User
from app.schemas.organization_audit import (
    AlertAcknowledgedAuditDetail,
    AssessmentAuditDetail,
    CandidateDismissedAuditDetail,
    CustomerAuditAction,
    CustomerAuditResourceKind,
    FindingCreatedAuditDetail,
    FollowUpChangedAuditDetail,
    MonitoringAuditDetail,
    NotificationSettingsAuditDetail,
    OrganizationAuditActor,
    OrganizationAuditDetail,
    OrganizationAuditEventsResponse,
    OrganizationAuditResource,
    OrganizationAuditRow,
    RemediationRecordedAuditDetail,
    RemediationWorkflowAuditDetail,
    ReportGeneratedAuditDetail,
    ReportShareAuditDetail,
    RetestAuditDetail,
    TargetAuditDetail,
)

DEFAULT_PAGE_SIZE = 20
MAX_PAGE_SIZE = 50
CURSOR_VERSION = "v1"
INVALID_CURSOR_DETAIL = "Invalid audit events cursor"
UNAVAILABLE_RESOURCE_LABEL = "Deleted or unavailable resource"


@dataclass(frozen=True)
class VisibleActionSpec:
    internal_action: str
    customer_action: CustomerAuditAction
    label: str
    resource_kind: CustomerAuditResourceKind
    # Internal resource_type values that may appear for this action.
    internal_resource_types: frozenset[str]
    scalar_keys: frozenset[str]


# Frozen M37-visible map (Correction: fail closed for anything else).
_VISIBLE_SPECS: tuple[VisibleActionSpec, ...] = (
    VisibleActionSpec(
        "target.created",
        "target_created",
        "Target created",
        "target",
        frozenset({"target"}),
        frozenset({"domain", "status"}),
    ),
    VisibleActionSpec(
        "target.verification_started",
        "target_verification_started",
        "Target verification started",
        "target",
        frozenset({"target"}),
        frozenset({"domain", "status"}),
    ),
    VisibleActionSpec(
        "target.verified",
        "target_verified",
        "Target verified",
        "target",
        frozenset({"target"}),
        frozenset({"domain", "status"}),
    ),
    VisibleActionSpec(
        "target.scope_updated",
        "target_scope_changed",
        "Target scope changed",
        "target",
        frozenset({"target"}),
        frozenset({"domain", "status", "include_subdomains", "exclusions_count", "scope_root"}),
    ),
    VisibleActionSpec(
        "target.revoked",
        "target_revoked",
        "Target revoked",
        "target",
        frozenset({"target"}),
        frozenset({"domain", "status"}),
    ),
    VisibleActionSpec(
        "operation.created",
        "assessment_created",
        "Assessment created",
        "assessment",
        frozenset({"operation"}),
        frozenset({"domain", "source"}),
    ),
    VisibleActionSpec(
        "operation.started",
        "assessment_started",
        "Assessment started",
        "assessment",
        frozenset({"operation"}),
        frozenset({"domain", "source"}),
    ),
    VisibleActionSpec(
        "operation.stopped",
        "assessment_stopped",
        "Assessment stopped",
        "assessment",
        frozenset({"operation"}),
        frozenset({"domain", "source"}),
    ),
    VisibleActionSpec(
        "operation.completed",
        "assessment_completed",
        "Assessment completed",
        "assessment",
        frozenset({"operation"}),
        frozenset({"domain", "source"}),
    ),
    VisibleActionSpec(
        "operation.failed",
        "assessment_failed",
        "Assessment failed",
        "assessment",
        frozenset({"operation"}),
        frozenset({"domain", "source"}),
    ),
    VisibleActionSpec(
        "monitoring.enabled",
        "monitoring_changed",
        "Monitoring enabled",
        "monitoring",
        frozenset({"monitoring"}),
        frozenset(
            {
                "enabled",
                "frequency",
                "auto_generate_reports",
                "auto_deliver_reports",
                "expires_in",
                "recipient_count",
                "domain",
            }
        ),
    ),
    VisibleActionSpec(
        "monitoring.disabled",
        "monitoring_changed",
        "Monitoring disabled",
        "monitoring",
        frozenset({"monitoring"}),
        frozenset(
            {
                "enabled",
                "frequency",
                "auto_generate_reports",
                "auto_deliver_reports",
                "expires_in",
                "recipient_count",
                "domain",
            }
        ),
    ),
    VisibleActionSpec(
        "monitoring.auto_reports_enabled",
        "monitoring_changed",
        "Automatic report generation enabled",
        "monitoring",
        frozenset({"monitoring"}),
        frozenset({"auto_generate_reports", "domain"}),
    ),
    VisibleActionSpec(
        "monitoring.auto_reports_disabled",
        "monitoring_changed",
        "Automatic report generation disabled",
        "monitoring",
        frozenset({"monitoring"}),
        frozenset({"auto_generate_reports", "domain"}),
    ),
    VisibleActionSpec(
        "monitoring.auto_delivery_enabled",
        "monitoring_changed",
        "Automatic report delivery enabled",
        "monitoring",
        frozenset({"monitoring"}),
        frozenset({"auto_deliver_reports", "expires_in", "recipient_count", "domain"}),
    ),
    VisibleActionSpec(
        "monitoring.auto_delivery_disabled",
        "monitoring_changed",
        "Automatic report delivery disabled",
        "monitoring",
        frozenset({"monitoring"}),
        frozenset({"auto_deliver_reports", "expires_in", "recipient_count", "domain"}),
    ),
    VisibleActionSpec(
        "monitoring.auto_delivery_recipients_updated",
        "monitoring_changed",
        "Automatic report delivery recipients updated",
        "monitoring",
        frozenset({"monitoring"}),
        frozenset({"recipient_count", "expires_in", "domain"}),
    ),
    VisibleActionSpec(
        "notification.settings.updated",
        "notification_settings_changed",
        "Notification settings changed",
        "notification_settings",
        frozenset({"organization"}),
        frozenset(
            {
                "email_enabled",
                "email_min_priority",
                "finding_follow_up_reminders_enabled",
                "recipient_count",
            }
        ),
    ),
    VisibleActionSpec(
        "finding.created",
        "finding_created",
        "Finding created",
        "finding",
        frozenset({"finding"}),
        frozenset({"severity", "candidate_type"}),
    ),
    VisibleActionSpec(
        "finding.remediation_started",
        "remediation_started",
        "Remediation started",
        "finding",
        frozenset({"finding"}),
        frozenset({"previous_status", "new_status"}),
    ),
    VisibleActionSpec(
        "finding.ready_for_retest",
        "ready_for_retest",
        "Marked ready for retest",
        "finding",
        frozenset({"finding"}),
        frozenset({"previous_status", "new_status"}),
    ),
    VisibleActionSpec(
        "finding.remediation_recorded",
        "remediation_recorded",
        "Remediation note recorded",
        "finding",
        frozenset({"finding_remediation_revision"}),
        frozenset({"revision_number", "finding_id"}),
    ),
    VisibleActionSpec(
        "finding.follow_up_changed",
        "finding_follow_up_changed",
        "Finding follow-up changed",
        "finding",
        frozenset({"finding_follow_up_change"}),
        frozenset(
            {
                "previous_assigned_to_user_id",
                "new_assigned_to_user_id",
                "previous_due_at",
                "new_due_at",
                "finding_id",
            }
        ),
    ),
    VisibleActionSpec(
        "finding.resolved",
        "finding_resolved",
        "Finding resolved",
        "finding",
        frozenset({"finding"}),
        frozenset(),
    ),
    VisibleActionSpec(
        "retest.requested",
        "retest_requested",
        "Retest requested",
        "retest",
        frozenset({"retest_attempt"}),
        frozenset({"retest_id", "finding_id"}),
    ),
    VisibleActionSpec(
        "retest.completed",
        "retest_completed",
        "Retest completed",
        "retest",
        frozenset({"retest_attempt"}),
        frozenset({"retest_id", "retest_status", "finding_id"}),
    ),
    VisibleActionSpec(
        "candidate.dismissed",
        "candidate_dismissed",
        "Candidate dismissed",
        "candidate",
        frozenset({"candidate"}),
        frozenset({"candidate_type"}),
    ),
    VisibleActionSpec(
        "alert.acknowledged",
        "alert_acknowledged",
        "Alert acknowledged",
        "alert",
        frozenset({"alert"}),
        frozenset({"alert_type"}),
    ),
    VisibleActionSpec(
        "assessment_report.generated",
        "report_generated",
        "Report generated",
        "report",
        frozenset({"assessment_report"}),
        frozenset(
            {"report_version", "generation_origin", "findings_total", "findings_open"}
        ),
    ),
    VisibleActionSpec(
        "assessment_report_share.created",
        "report_share_created",
        "Report share created",
        "report_share",
        frozenset({"assessment_report_share"}),
        frozenset({"report_id", "expires_at", "creation_origin"}),
    ),
    VisibleActionSpec(
        "assessment_report_share.revoked",
        "report_share_revoked",
        "Report share revoked",
        "report_share",
        frozenset({"assessment_report_share"}),
        frozenset({"report_id", "expires_at", "creation_origin"}),
    ),
)

VISIBLE_INTERNAL_ACTIONS: frozenset[str] = frozenset(
    spec.internal_action for spec in _VISIBLE_SPECS
)
_SPEC_BY_INTERNAL: dict[str, VisibleActionSpec] = {
    spec.internal_action: spec for spec in _VISIBLE_SPECS
}

_CUSTOMER_ACTION_TO_INTERNAL: dict[CustomerAuditAction, frozenset[str]] = {}
for _spec in _VISIBLE_SPECS:
    existing = _CUSTOMER_ACTION_TO_INTERNAL.get(_spec.customer_action, frozenset())
    _CUSTOMER_ACTION_TO_INTERNAL[_spec.customer_action] = existing | {
        _spec.internal_action
    }

# All scalar keys that may appear in the bounded detail SELECT.
_ALL_SCALAR_KEYS: frozenset[str] = frozenset().union(
    *(spec.scalar_keys for spec in _VISIBLE_SPECS)
)

# Customer resource → (action, internal resource_type) predicates.
# Compiled as OR of (action IN … AND resource_type IN …) per mapped kind.
_RESOURCE_KIND_PREDICATES: dict[CustomerAuditResourceKind, list[VisibleActionSpec]] = {}
for _spec in _VISIBLE_SPECS:
    _RESOURCE_KIND_PREDICATES.setdefault(_spec.resource_kind, []).append(_spec)


def encode_audit_cursor(*, created_at: datetime, event_id: UUID) -> str:
    payload = f"{CURSOR_VERSION}|{created_at.isoformat()}|{event_id}"
    return urlsafe_b64encode(payload.encode("utf-8")).decode("ascii").rstrip("=")


def decode_audit_cursor(raw: str) -> tuple[datetime, UUID]:
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
        event_id = UUID(parts[2])
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
    return created_at, event_id


def _cursor_condition(
    *,
    created_at,
    event_id,
    cursor_position: tuple[datetime, UUID] | None,
):
    if cursor_position is None:
        return true()
    cursor_at, cursor_id = cursor_position
    return or_(
        created_at < cursor_at,
        and_(created_at == cursor_at, event_id < cursor_id),
    )


def _meta(key: str):
    """PostgreSQL JSON scalar expression — never selects the whole metadata object."""
    return AuditEvent.event_metadata[key].as_string()


def _parse_uuid(raw: str | None) -> UUID | None:
    if raw is None or raw == "":
        return None
    try:
        return UUID(str(raw))
    except (TypeError, ValueError):
        return None


def _parse_bool(raw: str | None) -> bool | None:
    if raw is None or raw == "":
        return None
    if raw.lower() in {"true", "t", "1"}:
        return True
    if raw.lower() in {"false", "f", "0"}:
        return False
    return None


def _parse_int(raw: str | None) -> int | None:
    if raw is None or raw == "":
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _parse_dt(raw: str | None) -> datetime | None:
    if raw is None or raw == "":
        return None
    try:
        value = datetime.fromisoformat(raw)
    except (TypeError, ValueError):
        return None
    if value.tzinfo is None:
        return None
    return value.astimezone(timezone.utc)


def _resource_filter_clause(resource_type: CustomerAuditResourceKind | None):
    if resource_type is None:
        return true()
    specs = _RESOURCE_KIND_PREDICATES.get(resource_type, [])
    if not specs:
        return true()
    parts = []
    for spec in specs:
        parts.append(
            and_(
                AuditEvent.action == spec.internal_action,
                AuditEvent.resource_type.in_(list(spec.internal_resource_types)),
            )
        )
    return or_(*parts)


def build_organization_audit_page_statement(
    *,
    organization_id: UUID,
    size: int,
    cursor_position: tuple[datetime, UUID] | None,
    action: CustomerAuditAction | None,
    resource_type: CustomerAuditResourceKind | None,
    actor_user_id: UUID | None,
    created_from: datetime | None,
    created_to: datetime | None,
):
    """Primary page SELECT — no metadata column."""
    if action is not None:
        actions = _CUSTOMER_ACTION_TO_INTERNAL[action]
    else:
        actions = VISIBLE_INTERNAL_ACTIONS

    conditions = [
        AuditEvent.organization_id == organization_id,
        AuditEvent.action.in_(list(actions)),
        _resource_filter_clause(resource_type),
        _cursor_condition(
            created_at=AuditEvent.created_at,
            event_id=AuditEvent.id,
            cursor_position=cursor_position,
        ),
    ]
    if actor_user_id is not None:
        # Actor filter applies to human rows only (system must not match by stored creator id).
        conditions.append(AuditEvent.actor_type == "user")
        conditions.append(AuditEvent.actor_user_id == actor_user_id)
    if created_from is not None:
        conditions.append(AuditEvent.created_at >= created_from)
    if created_to is not None:
        conditions.append(AuditEvent.created_at <= created_to)

    return (
        select(
            AuditEvent.id,
            AuditEvent.organization_id,
            AuditEvent.actor_type,
            AuditEvent.actor_user_id,
            AuditEvent.action,
            AuditEvent.resource_type,
            AuditEvent.resource_id,
            AuditEvent.created_at,
        )
        .where(*conditions)
        .order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc())
        .limit(size + 1)
    )


def build_organization_audit_scalar_statement(
    *,
    organization_id: UUID,
    event_ids: list[UUID],
):
    """Bounded scalar-detail SELECT for final page IDs — never selects metadata object."""
    columns = [
        AuditEvent.id,
        AuditEvent.organization_id,
        AuditEvent.action,
    ]
    for key in sorted(_ALL_SCALAR_KEYS):
        columns.append(_meta(key).label(key))
    return select(*columns).where(
        AuditEvent.organization_id == organization_id,
        AuditEvent.id.in_(event_ids),
        AuditEvent.action.in_(list(VISIBLE_INTERNAL_ACTIONS)),
    )


def _build_detail(
    *,
    spec: VisibleActionSpec,
    scalars: dict[str, str | None],
) -> OrganizationAuditDetail | None:
    action = spec.customer_action
    if action.startswith("target_"):
        return TargetAuditDetail(
            domain=scalars.get("domain") or None,
            status=scalars.get("status") or None,
            include_subdomains=_parse_bool(scalars.get("include_subdomains")),
            exclusions_count=_parse_int(scalars.get("exclusions_count")),
            scope_root=scalars.get("scope_root") or None,
        )
    if action.startswith("assessment_"):
        return AssessmentAuditDetail(
            domain=scalars.get("domain") or None,
            source=scalars.get("source") or None,
        )
    if action == "monitoring_changed":
        return MonitoringAuditDetail(
            enabled=_parse_bool(scalars.get("enabled")),
            frequency=scalars.get("frequency") or None,
            auto_generate_reports=_parse_bool(scalars.get("auto_generate_reports")),
            auto_deliver_reports=_parse_bool(scalars.get("auto_deliver_reports")),
            expires_in=scalars.get("expires_in") or None,
            recipient_count=_parse_int(scalars.get("recipient_count")),
        )
    if action == "notification_settings_changed":
        return NotificationSettingsAuditDetail(
            email_enabled=_parse_bool(scalars.get("email_enabled")),
            email_min_priority=scalars.get("email_min_priority") or None,
            finding_follow_up_reminders_enabled=_parse_bool(
                scalars.get("finding_follow_up_reminders_enabled")
            ),
            recipient_count=_parse_int(scalars.get("recipient_count")),
        )
    if action == "finding_created":
        return FindingCreatedAuditDetail(
            severity=scalars.get("severity") or None,
            candidate_type=scalars.get("candidate_type") or None,
        )
    if action in {"remediation_started", "ready_for_retest"}:
        return RemediationWorkflowAuditDetail(
            previous_status=scalars.get("previous_status") or None,
            new_status=scalars.get("new_status") or None,
        )
    if action == "remediation_recorded":
        return RemediationRecordedAuditDetail(
            revision_number=_parse_int(scalars.get("revision_number")),
        )
    if action == "finding_follow_up_changed":
        return FollowUpChangedAuditDetail(
            previous_assigned_to_user_id=_parse_uuid(
                scalars.get("previous_assigned_to_user_id")
            ),
            new_assigned_to_user_id=_parse_uuid(scalars.get("new_assigned_to_user_id")),
            previous_due_at=_parse_dt(scalars.get("previous_due_at")),
            new_due_at=_parse_dt(scalars.get("new_due_at")),
        )
    if action in {"retest_requested", "retest_completed"}:
        return RetestAuditDetail(
            retest_id=_parse_uuid(scalars.get("retest_id")),
            retest_status=scalars.get("retest_status") or None,
        )
    if action == "candidate_dismissed":
        return CandidateDismissedAuditDetail(
            candidate_type=scalars.get("candidate_type") or None,
        )
    if action == "alert_acknowledged":
        return AlertAcknowledgedAuditDetail(
            alert_type=scalars.get("alert_type") or None,
        )
    if action == "report_generated":
        return ReportGeneratedAuditDetail(
            report_version=_parse_int(scalars.get("report_version")),
            generation_origin=scalars.get("generation_origin") or None,
            findings_total=_parse_int(scalars.get("findings_total")),
            findings_open=_parse_int(scalars.get("findings_open")),
        )
    if action in {"report_share_created", "report_share_revoked"}:
        return ReportShareAuditDetail(
            report_id=_parse_uuid(scalars.get("report_id")),
            expires_at=_parse_dt(scalars.get("expires_at")),
            creation_origin=scalars.get("creation_origin") or None,
        )
    if action == "finding_resolved":
        return None
    return None


def _actor_for_row(
    *,
    actor_type: str,
    actor_user_id: UUID | None,
    names: dict[UUID, str | None],
) -> OrganizationAuditActor:
    if actor_type != "user":
        return OrganizationAuditActor(kind="system")
    if actor_user_id is None:
        return OrganizationAuditActor(kind="unavailable_user")
    if actor_user_id not in names:
        return OrganizationAuditActor(
            kind="unavailable_user",
            user_id=actor_user_id,
        )
    return OrganizationAuditActor(
        kind="organization_member",
        user_id=actor_user_id,
        display_name=names.get(actor_user_id),
    )


def _enrich_resources(
    db: Session,
    *,
    organization_id: UUID,
    rows: list[Any],
    scalars_by_id: dict[UUID, dict[str, str | None]],
) -> dict[UUID, OrganizationAuditResource]:
    finding_ids: set[UUID] = set()
    target_ids: set[UUID] = set()
    operation_ids: set[UUID] = set()
    report_ids: set[UUID] = set()
    alert_ids: set[UUID] = set()

    for row in rows:
        spec = _SPEC_BY_INTERNAL.get(row.action)
        if spec is None:
            continue
        scalars = scalars_by_id.get(row.id, {})
        kind = spec.resource_kind
        if kind == "finding":
            fid = row.resource_id if row.resource_type == "finding" else None
            fid = fid or _parse_uuid(scalars.get("finding_id"))
            if fid:
                finding_ids.add(fid)
        elif kind == "target" and row.resource_id:
            target_ids.add(row.resource_id)
        elif kind == "assessment" and row.resource_id:
            operation_ids.add(row.resource_id)
        elif kind == "monitoring":
            # domain may be in scalars; target via live monitoring not required
            pass
        elif kind == "report" and row.resource_id:
            report_ids.add(row.resource_id)
        elif kind == "report_share":
            rid = _parse_uuid(scalars.get("report_id"))
            if rid:
                report_ids.add(rid)
        elif kind == "alert" and row.resource_id:
            alert_ids.add(row.resource_id)
        elif kind == "retest":
            fid = _parse_uuid(scalars.get("finding_id"))
            if fid:
                finding_ids.add(fid)

    findings: dict[UUID, Finding] = {}
    if finding_ids:
        for finding in db.scalars(
            select(Finding)
            .options(load_only(Finding.id, Finding.title, Finding.organization_id))
            .where(
                Finding.organization_id == organization_id,
                Finding.id.in_(finding_ids),
            )
        ).all():
            findings[finding.id] = finding

    targets: dict[UUID, AuthorizedTarget] = {}
    if target_ids:
        for target in db.scalars(
            select(AuthorizedTarget)
            .options(
                load_only(
                    AuthorizedTarget.id,
                    AuthorizedTarget.domain,
                    AuthorizedTarget.organization_id,
                )
            )
            .where(
                AuthorizedTarget.organization_id == organization_id,
                AuthorizedTarget.id.in_(target_ids),
            )
        ).all():
            targets[target.id] = target

    operations: dict[UUID, Operation] = {}
    op_target_ids: set[UUID] = set()
    if operation_ids:
        for op in db.scalars(
            select(Operation)
            .options(
                load_only(
                    Operation.id,
                    Operation.target_id,
                    Operation.organization_id,
                )
            )
            .where(
                Operation.organization_id == organization_id,
                Operation.id.in_(operation_ids),
            )
        ).all():
            operations[op.id] = op
            op_target_ids.add(op.target_id)
        if op_target_ids:
            for target in db.scalars(
                select(AuthorizedTarget)
                .options(
                    load_only(
                        AuthorizedTarget.id,
                        AuthorizedTarget.domain,
                        AuthorizedTarget.organization_id,
                    )
                )
                .where(
                    AuthorizedTarget.organization_id == organization_id,
                    AuthorizedTarget.id.in_(op_target_ids),
                )
            ).all():
                targets[target.id] = target

    reports: dict[UUID, AssessmentReport] = {}
    if report_ids:
        for report in db.scalars(
            select(AssessmentReport)
            .options(
                load_only(
                    AssessmentReport.id,
                    AssessmentReport.report_version,
                    AssessmentReport.target_domain,
                    AssessmentReport.organization_id,
                )
            )
            .where(
                AssessmentReport.organization_id == organization_id,
                AssessmentReport.id.in_(report_ids),
            )
        ).all():
            reports[report.id] = report

    alerts: dict[UUID, Alert] = {}
    if alert_ids:
        for alert in db.scalars(
            select(Alert)
            .options(
                load_only(
                    Alert.id,
                    Alert.alert_type,
                    Alert.organization_id,
                    Alert.target_id,
                )
            )
            .where(
                Alert.organization_id == organization_id,
                Alert.id.in_(alert_ids),
            )
        ).all():
            alerts[alert.id] = alert

    resources: dict[UUID, OrganizationAuditResource] = {}
    for row in rows:
        spec = _SPEC_BY_INTERNAL.get(row.action)
        if spec is None:
            continue
        scalars = scalars_by_id.get(row.id, {})
        kind = spec.resource_kind
        resource_id = row.resource_id
        label: str | None = None

        if kind == "target":
            audited_domain = scalars.get("domain") or None
            live = targets.get(resource_id) if resource_id else None
            label = audited_domain or (live.domain if live else None)
            if label is None:
                label = UNAVAILABLE_RESOURCE_LABEL
        elif kind == "assessment":
            audited_domain = scalars.get("domain") or None
            op = operations.get(resource_id) if resource_id else None
            live_domain = (
                targets.get(op.target_id).domain
                if op is not None and op.target_id in targets
                else None
            )
            label = audited_domain or live_domain or UNAVAILABLE_RESOURCE_LABEL
        elif kind == "monitoring":
            label = scalars.get("domain") or UNAVAILABLE_RESOURCE_LABEL
        elif kind == "notification_settings":
            label = "Notification settings"
            resource_id = organization_id
        elif kind == "finding":
            fid = (
                resource_id
                if row.resource_type == "finding"
                else _parse_uuid(scalars.get("finding_id"))
            )
            resource_id = fid
            finding = findings.get(fid) if fid else None
            label = finding.title if finding else UNAVAILABLE_RESOURCE_LABEL
        elif kind == "retest":
            fid = _parse_uuid(scalars.get("finding_id"))
            finding = findings.get(fid) if fid else None
            label = finding.title if finding else UNAVAILABLE_RESOURCE_LABEL
        elif kind == "report":
            report = reports.get(resource_id) if resource_id else None
            if report is not None:
                label = f"Report v{report.report_version} · {report.target_domain}"
            else:
                version = _parse_int(scalars.get("report_version"))
                label = f"Report v{version}" if version else UNAVAILABLE_RESOURCE_LABEL
        elif kind == "report_share":
            rid = _parse_uuid(scalars.get("report_id"))
            report = reports.get(rid) if rid else None
            label = (
                f"Share · report v{report.report_version}"
                if report is not None
                else UNAVAILABLE_RESOURCE_LABEL
            )
        elif kind == "candidate":
            ctype = scalars.get("candidate_type")
            label = ctype or UNAVAILABLE_RESOURCE_LABEL
        elif kind == "alert":
            alert = alerts.get(resource_id) if resource_id else None
            label = (
                (scalars.get("alert_type") or None)
                or (alert.alert_type if alert else None)
                or UNAVAILABLE_RESOURCE_LABEL
            )

        resources[row.id] = OrganizationAuditResource(
            kind=kind,
            id=resource_id,
            label=label,
        )
    return resources


def list_organization_audit_events(
    db: Session,
    *,
    organization_id: UUID,
    page_size: int = DEFAULT_PAGE_SIZE,
    cursor: str | None = None,
    action: CustomerAuditAction | None = None,
    resource_type: CustomerAuditResourceKind | None = None,
    actor_user_id: UUID | None = None,
    created_from: datetime | None = None,
    created_to: datetime | None = None,
) -> OrganizationAuditEventsResponse:
    size = page_size
    cursor_position = decode_audit_cursor(cursor) if cursor else None
    page_stmt = build_organization_audit_page_statement(
        organization_id=organization_id,
        size=size,
        cursor_position=cursor_position,
        action=action,
        resource_type=resource_type,
        actor_user_id=actor_user_id,
        created_from=created_from,
        created_to=created_to,
    )
    raw_rows = list(db.execute(page_stmt).all())
    has_more = len(raw_rows) > size
    page_rows = raw_rows[:size]
    if not page_rows:
        return OrganizationAuditEventsResponse(items=[], next_cursor=None)

    event_ids = [row.id for row in page_rows]
    scalar_rows = list(
        db.execute(
            build_organization_audit_scalar_statement(
                organization_id=organization_id,
                event_ids=event_ids,
            )
        ).all()
    )
    scalars_by_id: dict[UUID, dict[str, str | None]] = {}
    for srow in scalar_rows:
        mapping: dict[str, str | None] = {}
        for key in _ALL_SCALAR_KEYS:
            mapping[key] = getattr(srow, key, None)
        scalars_by_id[srow.id] = mapping

    human_ids = {
        row.actor_user_id
        for row in page_rows
        if row.actor_type == "user" and row.actor_user_id is not None
    }
    names: dict[UUID, str | None] = {}
    if human_ids:
        for user in db.scalars(
            select(User).options(load_only(User.id, User.name)).where(User.id.in_(human_ids))
        ).all():
            names[user.id] = user.name

    resources = _enrich_resources(
        db,
        organization_id=organization_id,
        rows=page_rows,
        scalars_by_id=scalars_by_id,
    )

    items: list[OrganizationAuditRow] = []
    for row in page_rows:
        spec = _SPEC_BY_INTERNAL.get(row.action)
        if spec is None:
            # Fail closed — should not appear due to SQL allowlist.
            continue
        scalars = scalars_by_id.get(row.id, {})
        # Only pass keys allowed for this action into detail builder.
        allowed = {k: scalars.get(k) for k in spec.scalar_keys}
        items.append(
            OrganizationAuditRow(
                action=spec.customer_action,
                label=spec.label,
                occurred_at=row.created_at,
                actor=_actor_for_row(
                    actor_type=row.actor_type,
                    actor_user_id=row.actor_user_id,
                    names=names,
                ),
                resource=resources.get(
                    row.id,
                    OrganizationAuditResource(
                        kind=spec.resource_kind,
                        id=row.resource_id,
                        label=UNAVAILABLE_RESOURCE_LABEL,
                    ),
                ),
                detail=_build_detail(spec=spec, scalars=allowed),
            )
        )

    next_cursor = None
    if has_more and page_rows:
        last = page_rows[-1]
        next_cursor = encode_audit_cursor(
            created_at=last.created_at, event_id=last.id
        )

    return OrganizationAuditEventsResponse(items=items, next_cursor=next_cursor)


def compile_organization_audit_page_sql(
    *,
    organization_id: UUID,
    size: int = 20,
    cursor_position: tuple[datetime, UUID] | None = None,
    action: CustomerAuditAction | None = None,
    resource_type: CustomerAuditResourceKind | None = None,
    actor_user_id: UUID | None = None,
    created_from: datetime | None = None,
    created_to: datetime | None = None,
) -> str:
    from sqlalchemy.dialects import postgresql

    statement = build_organization_audit_page_statement(
        organization_id=organization_id,
        size=size,
        cursor_position=cursor_position,
        action=action,
        resource_type=resource_type,
        actor_user_id=actor_user_id,
        created_from=created_from,
        created_to=created_to,
    )
    return str(
        statement.compile(
            dialect=postgresql.dialect(),
            compile_kwargs={"literal_binds": True},
        )
    )
