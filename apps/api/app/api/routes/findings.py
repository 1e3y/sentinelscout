from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import AuthContext, get_auth_context, get_db
from app.models.asset import Asset
from app.schemas.audit import FindingProvenanceResponse
from app.schemas.finding import FindingResponse
from app.schemas.retest import RetestAttemptResponse
from app.services.findings import (
    get_finding_or_404,
    list_findings_for_user,
    mark_ready_for_retest,
    start_remediation,
)
from app.services.provenance import build_finding_provenance
from app.services.rate_limit import ACTION_RETEST, enforce_rate_limit
from app.services.retest_runtime import list_finding_retests, queue_finding_retest

router = APIRouter(prefix="/v1/findings", tags=["findings"])


def _to_finding_response(
    db: Session, finding, asset: Asset | None = None
) -> FindingResponse:
    provenance = FindingProvenanceResponse.model_validate(
        build_finding_provenance(db, finding)
    )
    return FindingResponse(
        id=finding.id,
        organization_id=finding.organization_id,
        operation_id=finding.operation_id,
        candidate_id=finding.candidate_id,
        asset_id=finding.asset_id,
        asset_hostname=asset.hostname if asset else None,
        asset_url=asset.url if asset else None,
        title=finding.title,
        summary=finding.summary,
        severity=finding.severity,
        status=finding.status,
        business_impact=finding.business_impact,
        remediation_guidance=finding.remediation_guidance,
        evidence=dict(finding.evidence or {}),
        provenance=provenance,
        created_at=finding.created_at,
        updated_at=finding.updated_at,
        resolved_at=finding.resolved_at,
    )


def _assets_by_id(db: Session, findings) -> dict[UUID, Asset]:
    asset_ids = {row.asset_id for row in findings}
    if not asset_ids:
        return {}
    return {
        asset.id: asset
        for asset in db.scalars(select(Asset).where(Asset.id.in_(asset_ids))).all()
    }


@router.get("", response_model=list[FindingResponse])
def list_findings_endpoint(
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
) -> list[FindingResponse]:
    findings = list_findings_for_user(db, user_id=auth.user.id)
    assets = _assets_by_id(db, findings)
    return [
        _to_finding_response(db, finding, assets.get(finding.asset_id))
        for finding in findings
    ]


@router.get("/{finding_id}", response_model=FindingResponse)
def get_finding_endpoint(
    finding_id: UUID,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
) -> FindingResponse:
    finding = get_finding_or_404(db, finding_id=finding_id, user_id=auth.user.id)
    asset = db.get(Asset, finding.asset_id)
    return _to_finding_response(db, finding, asset)


@router.post("/{finding_id}/start-remediation", response_model=FindingResponse)
def start_remediation_endpoint(
    finding_id: UUID,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
) -> FindingResponse:
    finding = start_remediation(db, finding_id=finding_id, user_id=auth.user.id)
    asset = db.get(Asset, finding.asset_id)
    return _to_finding_response(db, finding, asset)


@router.post("/{finding_id}/ready-for-retest", response_model=FindingResponse)
def ready_for_retest_endpoint(
    finding_id: UUID,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
) -> FindingResponse:
    finding = mark_ready_for_retest(db, finding_id=finding_id, user_id=auth.user.id)
    asset = db.get(Asset, finding.asset_id)
    return _to_finding_response(db, finding, asset)


def _to_retest_response(attempt) -> RetestAttemptResponse:
    return RetestAttemptResponse(
        id=attempt.id,
        organization_id=attempt.organization_id,
        finding_id=attempt.finding_id,
        candidate_id=attempt.candidate_id,
        asset_id=attempt.asset_id,
        original_validation_attempt_id=attempt.original_validation_attempt_id,
        status=attempt.status,
        method=attempt.method,
        summary=attempt.summary,
        evidence=dict(attempt.evidence or {}),
        created_at=attempt.created_at,
        completed_at=attempt.completed_at,
    )


@router.post(
    "/{finding_id}/retest",
    response_model=RetestAttemptResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def queue_retest_endpoint(
    finding_id: UUID,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
) -> RetestAttemptResponse:
    finding = get_finding_or_404(db, finding_id=finding_id, user_id=auth.user.id)
    enforce_rate_limit(
        db,
        organization_id=finding.organization_id,
        user_id=auth.user.id,
        action=ACTION_RETEST,
    )
    attempt = queue_finding_retest(db, finding_id=finding_id, user_id=auth.user.id)
    return _to_retest_response(attempt)


@router.get("/{finding_id}/retests", response_model=list[RetestAttemptResponse])
def list_retests_endpoint(
    finding_id: UUID,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
) -> list[RetestAttemptResponse]:
    attempts = list_finding_retests(db, finding_id=finding_id, user_id=auth.user.id)
    return [_to_retest_response(item) for item in attempts]
