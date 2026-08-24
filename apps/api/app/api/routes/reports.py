from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.orm import Session

from app.api.deps import (
    AuthContext,
    get_auth_context,
    get_db,
    require_active_org_actor,
)
from app.models.report import AssessmentReport
from app.models.report_share import AssessmentReportShare
from app.schemas.report import (
    AssessmentReportResponse,
    AssessmentReportSummaryResponse,
    CreateReportShareRequest,
    CreateReportShareResponse,
    ReportShareListItem,
    RevokeReportShareResponse,
)
from app.services.rate_limit import (
    ACTION_REPORT_GENERATE,
    ACTION_REPORT_PDF_EXPORT,
    ACTION_REPORT_SHARE_CREATE,
    enforce_rate_limit,
)
from app.services.authorization import assert_admin_actor
from app.services.reports.generate import (
    REPORT_NOT_FOUND_DETAIL,
    generate_assessment_report,
    get_assessment_report_or_404,
    list_assessment_reports,
    list_operation_assessment_reports,
)
from app.services.reports.pdf import (
    PdfRendererUnavailable,
    PdfSnapshotError,
    export_assessment_report_pdf,
    pdf_http_error,
)
from app.services.reports.share import (
    create_report_share,
    list_report_shares,
    revoke_report_share,
    share_list_item,
    share_url_for,
)
from app.services.reports.summary import HEADLINE_LABELS

router = APIRouter(prefix="/v1/reports", tags=["reports"])
operation_router = APIRouter(prefix="/v1/operations", tags=["reports"])
share_admin_router = APIRouter(prefix="/v1/report-shares", tags=["reports"])


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


@router.get("/{report_id}/pdf")
def export_report_pdf_endpoint(
    report_id: UUID,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
) -> Response:
    """On-demand PDF of an existing immutable snapshot.

    Isolation order: authenticate → membership-scoped get-or-404 → rate limit
    using the authorized organization/user → validate/render. Cross-org IDs
    stay 404 and never increment ``report.pdf_export``.

    Sync ``def`` so FastAPI runs rendering in the threadpool and does not
    block the event loop. The PDF is fully built in memory before this
    response is constructed.
    """
    report = get_assessment_report_or_404(db, report_id=report_id, user_id=auth.user.id)
    enforce_rate_limit(
        db,
        organization_id=report.organization_id,
        user_id=auth.user.id,
        action=ACTION_REPORT_PDF_EXPORT,
    )
    try:
        pdf_bytes, filename = export_assessment_report_pdf(report)
    except PdfRendererUnavailable as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="PDF export is unavailable",
        ) from exc
    except PdfSnapshotError as exc:
        raise pdf_http_error(exc) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred",
        ) from exc
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/{report_id}/shares", response_model=CreateReportShareResponse, status_code=201)
def create_report_share_endpoint(
    report_id: UUID,
    body: CreateReportShareRequest,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
) -> CreateReportShareResponse:
    report = get_assessment_report_or_404(db, report_id=report_id, user_id=auth.user.id)
    actor = require_active_org_actor(auth)
    assert_admin_actor(actor, report.organization_id, not_found=REPORT_NOT_FOUND_DETAIL)
    enforce_rate_limit(
        db,
        organization_id=report.organization_id,
        user_id=auth.user.id,
        action=ACTION_REPORT_SHARE_CREATE,
    )
    share, secret = create_report_share(
        db, report_id=report.id, actor=actor, expires_in=body.expires_in
    )
    return CreateReportShareResponse(
        id=share.id,
        expires_at=share.expires_at,
        expires_in=body.expires_in,
        share_url=share_url_for(share, secret),
    )


@router.get("/{report_id}/shares", response_model=list[ReportShareListItem])
def list_report_shares_endpoint(
    report_id: UUID,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
) -> list[ReportShareListItem]:
    get_assessment_report_or_404(db, report_id=report_id, user_id=auth.user.id)
    actor = require_active_org_actor(auth)
    rows = list_report_shares(db, report_id=report_id, actor=actor)
    return [ReportShareListItem.model_validate(share_list_item(row)) for row in rows]


@share_admin_router.post("/{share_id}/revoke", response_model=RevokeReportShareResponse)
def revoke_report_share_endpoint(
    share_id: UUID,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
) -> RevokeReportShareResponse:
    preview = db.get(AssessmentReportShare, share_id)
    if preview is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=REPORT_NOT_FOUND_DETAIL
        )
    report = get_assessment_report_or_404(
        db, report_id=preview.report_id, user_id=auth.user.id
    )
    if preview.organization_id != report.organization_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=REPORT_NOT_FOUND_DETAIL
        )
    actor = require_active_org_actor(auth)
    share = revoke_report_share(db, share_id=share_id, actor=actor)
    return RevokeReportShareResponse(
        id=share.id,
        revoked_at=share.revoked_at,
        status=share_list_item(share)["status"],
    )
