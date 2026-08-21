from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy.orm import Session

from app.api.deps import (
    AuthContext,
    get_auth_context,
    get_db,
    require_active_org_actor,
)
from app.models.report import AssessmentReport
from app.schemas.report import AssessmentReportResponse, AssessmentReportSummaryResponse
from app.services.rate_limit import ACTION_REPORT_GENERATE, enforce_rate_limit
from app.services.reports.generate import (
    generate_assessment_report,
    get_assessment_report_or_404,
    list_assessment_reports,
    list_operation_assessment_reports,
)
from app.services.reports.summary import HEADLINE_LABELS

router = APIRouter(prefix="/v1/reports", tags=["reports"])
operation_router = APIRouter(prefix="/v1/operations", tags=["reports"])


def _summary_response(report: AssessmentReport) -> AssessmentReportSummaryResponse:
    return AssessmentReportSummaryResponse(
        id=report.id,
        organization_id=report.organization_id,
        target_id=report.target_id,
        operation_id=report.operation_id,
        created_by_user_id=report.created_by_user_id,
        target_domain=report.target_domain,
        report_version=report.report_version,
        schema_version=report.schema_version,
        snapshot_digest=report.snapshot_digest,
        operation_status_at_generation=report.operation_status_at_generation,
        assessment_completeness=report.assessment_completeness,
        headline_status=report.headline_status,
        findings_total=report.findings_total,
        findings_open=report.findings_open,
        findings_resolved=report.findings_resolved,
        regression_count=report.regression_count,
        coverage_limitation_count=report.coverage_limitation_count,
        severity_counts=dict(report.severity_counts or {}),
        generated_at=report.generated_at,
        headline_label=HEADLINE_LABELS.get(report.headline_status, report.headline_status),
    )


def _full_response(report: AssessmentReport) -> AssessmentReportResponse:
    base = _summary_response(report)
    return AssessmentReportResponse(
        **base.model_dump(),
        snapshot=dict(report.snapshot_json or {}),
    )


@operation_router.post("/{operation_id}/report", response_model=AssessmentReportResponse)
def generate_report_endpoint(
    operation_id: UUID,
    response: Response,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
) -> AssessmentReportResponse:
    actor = require_active_org_actor(auth)
    enforce_rate_limit(
        db,
        organization_id=actor.organization_id,
        user_id=actor.user_id,
        action=ACTION_REPORT_GENERATE,
    )
    report, created = generate_assessment_report(
        db, operation_id=operation_id, actor=actor
    )
    response.status_code = 201 if created else 200
    return _full_response(report)


@operation_router.get(
    "/{operation_id}/reports", response_model=list[AssessmentReportSummaryResponse]
)
def list_operation_reports_endpoint(
    operation_id: UUID,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
) -> list[AssessmentReportSummaryResponse]:
    rows = list_operation_assessment_reports(
        db, operation_id=operation_id, user_id=auth.user.id
    )
    return [_summary_response(row) for row in rows]


@router.get("", response_model=list[AssessmentReportSummaryResponse])
def list_reports_endpoint(
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
    target_id: UUID | None = None,
    operation_id: UUID | None = None,
    limit: int = Query(default=100, ge=1, le=500),
) -> list[AssessmentReportSummaryResponse]:
    rows = list_assessment_reports(
        db,
        user_id=auth.user.id,
        target_id=target_id,
        operation_id=operation_id,
        limit=limit,
    )
    return [_summary_response(row) for row in rows]


@router.get("/{report_id}", response_model=AssessmentReportResponse)
def get_report_endpoint(
    report_id: UUID,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
) -> AssessmentReportResponse:
    report = get_assessment_report_or_404(db, report_id=report_id, user_id=auth.user.id)
    return _full_response(report)
