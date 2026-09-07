"""Customer-facing organization audit trail DTOs (Milestone 37)."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

CustomerAuditAction = Literal[
    "target_created",
    "target_verification_started",
    "target_verified",
    "target_scope_changed",
    "target_revoked",
    "assessment_created",
    "assessment_started",
    "assessment_stopped",
    "assessment_completed",
    "assessment_failed",
    "monitoring_changed",
    "notification_settings_changed",
    "finding_created",
    "remediation_started",
    "ready_for_retest",
    "remediation_recorded",
    "finding_follow_up_changed",
    "finding_resolved",
    "retest_requested",
    "retest_completed",
    "candidate_dismissed",
    "alert_acknowledged",
    "report_generated",
    "report_share_created",
    "report_share_revoked",
    "organization_member_role_changed",
    "organization_member_removed",
]

CustomerAuditResourceKind = Literal[
    "target",
    "assessment",
    "monitoring",
    "notification_settings",
    "finding",
    "retest",
    "report",
    "report_share",
    "candidate",
    "alert",
    "organization_member",
]

ActorKind = Literal["organization_member", "system", "unavailable_user"]


class OrganizationAuditActor(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: ActorKind
    user_id: UUID | None = None
    display_name: str | None = None


class OrganizationAuditResource(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: CustomerAuditResourceKind
    id: UUID | None = None
    label: str | None = None


class TargetAuditDetail(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["target"] = "target"
    domain: str | None = None
    status: str | None = None
    include_subdomains: bool | None = None
    exclusions_count: int | None = None
    scope_root: str | None = None


class AssessmentAuditDetail(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["assessment"] = "assessment"
    domain: str | None = None
    source: str | None = None


class MonitoringAuditDetail(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["monitoring"] = "monitoring"
    enabled: bool | None = None
    frequency: str | None = None
    auto_generate_reports: bool | None = None
    auto_deliver_reports: bool | None = None
    expires_in: str | None = None
    recipient_count: int | None = None


class NotificationSettingsAuditDetail(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["notification_settings"] = "notification_settings"
    email_enabled: bool | None = None
    email_min_priority: str | None = None
    finding_follow_up_reminders_enabled: bool | None = None
    recipient_count: int | None = None


class FindingCreatedAuditDetail(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["finding_created"] = "finding_created"
    severity: str | None = None
    candidate_type: str | None = None


class RemediationWorkflowAuditDetail(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["remediation_workflow"] = "remediation_workflow"
    previous_status: str | None = None
    new_status: str | None = None


class RemediationRecordedAuditDetail(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["remediation_recorded"] = "remediation_recorded"
    revision_number: int | None = None


class FollowUpChangedAuditDetail(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["finding_follow_up_changed"] = "finding_follow_up_changed"
    previous_assigned_to_user_id: UUID | None = None
    new_assigned_to_user_id: UUID | None = None
    previous_due_at: datetime | None = None
    new_due_at: datetime | None = None


class RetestAuditDetail(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["retest"] = "retest"
    retest_id: UUID | None = None
    retest_status: str | None = None


class CandidateDismissedAuditDetail(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["candidate_dismissed"] = "candidate_dismissed"
    candidate_type: str | None = None


class AlertAcknowledgedAuditDetail(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["alert_acknowledged"] = "alert_acknowledged"
    alert_type: str | None = None


class ReportGeneratedAuditDetail(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["report_generated"] = "report_generated"
    report_version: int | None = None
    generation_origin: str | None = None
    findings_total: int | None = None
    findings_open: int | None = None


class ReportShareAuditDetail(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["report_share"] = "report_share"
    report_id: UUID | None = None
    expires_at: datetime | None = None
    creation_origin: str | None = None


class OrganizationMemberRoleChangedAuditDetail(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["organization_member_role_changed"] = "organization_member_role_changed"
    target_user_id: UUID | None = None
    previous_role: str | None = None
    new_role: str | None = None


class OrganizationMemberRemovedAuditDetail(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["organization_member_removed"] = "organization_member_removed"
    target_user_id: UUID | None = None
    previous_role: str | None = None


OrganizationAuditDetail = Annotated[
    TargetAuditDetail
    | AssessmentAuditDetail
    | MonitoringAuditDetail
    | NotificationSettingsAuditDetail
    | FindingCreatedAuditDetail
    | RemediationWorkflowAuditDetail
    | RemediationRecordedAuditDetail
    | FollowUpChangedAuditDetail
    | RetestAuditDetail
    | CandidateDismissedAuditDetail
    | AlertAcknowledgedAuditDetail
    | ReportGeneratedAuditDetail
    | ReportShareAuditDetail
    | OrganizationMemberRoleChangedAuditDetail
    | OrganizationMemberRemovedAuditDetail,
    Field(discriminator="kind"),
]


class OrganizationAuditRow(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: CustomerAuditAction
    label: str
    occurred_at: datetime
    actor: OrganizationAuditActor
    resource: OrganizationAuditResource
    detail: OrganizationAuditDetail | None = None


class OrganizationAuditEventsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[OrganizationAuditRow]
    next_cursor: str | None = None
