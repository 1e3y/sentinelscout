from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

ShareExpiresIn = Literal["24h", "7d", "30d"]
ShareStatus = Literal["active", "expired", "revoked"]


class AssessmentReportSummaryResponse(BaseModel):
    """List projection. Excludes the snapshot payload on purpose."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    organization_id: UUID
    target_id: UUID
    operation_id: UUID
    created_by_user_id: UUID | None = None
    generation_origin: str
    target_domain: str
    report_version: int
    schema_version: int
    snapshot_digest: str
    operation_status_at_generation: str
    assessment_completeness: str
    headline_status: str
    findings_total: int
    findings_open: int
    findings_resolved: int
    regression_count: int
    coverage_limitation_count: int
    severity_counts: dict[str, Any] = Field(default_factory=dict)
    generated_at: datetime
    headline_label: str


class AutomaticDeliveryStatusResponse(BaseModel):
    job_status: str
    last_error_code: str | None = None
    frozen_recipient_count: int = 0
    outbox_count: int = 0
    delivered_count: int = 0
    skipped_count: int = 0
    pending_count: int = 0
    email_delivery_enabled: bool = False


class AssessmentReportResponse(AssessmentReportSummaryResponse):
    snapshot: dict[str, Any] = Field(default_factory=dict)
    automatic_delivery: AutomaticDeliveryStatusResponse | None = None


class CreateReportShareRequest(BaseModel):
    expires_in: ShareExpiresIn


class CreateReportShareResponse(BaseModel):
    id: UUID
    expires_at: datetime
    expires_in: ShareExpiresIn
    share_url: str


class ReportShareListItem(BaseModel):
    id: UUID
    report_id: UUID
    created_by_user_id: UUID | None = None
    creation_origin: str = "manual"
    created_at: datetime
    expires_at: datetime
    revoked_at: datetime | None
    status: ShareStatus


class RevokeReportShareResponse(BaseModel):
    id: UUID
    revoked_at: datetime | None
    status: ShareStatus
