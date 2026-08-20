from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.api.deps import AuthContext, get_auth_context, get_db, require_active_org_actor
from app.models.asset import Asset
from app.schemas.candidate import SecurityCandidateResponse
from app.schemas.audit import FindingProvenanceResponse
from app.schemas.finding import FindingResponse
from app.schemas.validation import ValidationAttemptResponse
from app.services.authorization import assert_actor_org
from app.services.findings import promote_candidate_to_finding
from app.services.operations import (
    dismiss_candidate,
    get_candidate_or_404,
    list_candidate_validation_attempts,
    queue_candidate_validation,
)
from app.services.provenance import build_finding_provenance
from app.services.rate_limit import ACTION_VALIDATION, enforce_rate_limit

router = APIRouter(prefix="/v1/candidates", tags=["candidates"])


def _to_candidate_response(candidate, asset: Asset | None = None) -> SecurityCandidateResponse:
    return SecurityCandidateResponse(
        id=candidate.id,
        organization_id=candidate.organization_id,
        operation_id=candidate.operation_id,
        asset_id=candidate.asset_id,
        asset_hostname=asset.hostname if asset else None,
        asset_url=asset.url if asset else None,
        candidate_type=candidate.candidate_type,
        title=candidate.title,
        summary=candidate.summary,
        status=candidate.status,
        source=candidate.source,
        evidence=dict(candidate.evidence or {}),
        created_at=candidate.created_at,
        updated_at=candidate.updated_at,
    )


def _to_attempt_response(attempt) -> ValidationAttemptResponse:
    return ValidationAttemptResponse(
        id=attempt.id,
        organization_id=attempt.organization_id,
        operation_id=attempt.operation_id,
        candidate_id=attempt.candidate_id,
        asset_id=attempt.asset_id,
        status=attempt.status,
        validation_method=attempt.validation_method,
        summary=attempt.summary,
        evidence=dict(attempt.evidence or {}),
        created_at=attempt.created_at,
        completed_at=attempt.completed_at,
    )


@router.get("/{candidate_id}", response_model=SecurityCandidateResponse)
def get_candidate_endpoint(
    candidate_id: UUID,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
) -> SecurityCandidateResponse:
    candidate = get_candidate_or_404(db, candidate_id=candidate_id, user_id=auth.user.id)
    asset = db.get(Asset, candidate.asset_id)
    return _to_candidate_response(candidate, asset)


@router.post("/{candidate_id}/dismiss", response_model=SecurityCandidateResponse)
def dismiss_candidate_endpoint(
    candidate_id: UUID,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
) -> SecurityCandidateResponse:
    actor = require_active_org_actor(auth)
    candidate = dismiss_candidate(db, candidate_id=candidate_id, actor=actor)
    asset = db.get(Asset, candidate.asset_id)
    return _to_candidate_response(candidate, asset)


@router.post(
    "/{candidate_id}/validate",
    response_model=ValidationAttemptResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def validate_candidate_endpoint(
    candidate_id: UUID,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
) -> ValidationAttemptResponse:
    actor = require_active_org_actor(auth)
    candidate = get_candidate_or_404(db, candidate_id=candidate_id, user_id=actor.user_id)
    assert_actor_org(actor, candidate.organization_id, not_found="Candidate not found")
    enforce_rate_limit(
        db,
        organization_id=candidate.organization_id,
        user_id=actor.user_id,
        action=ACTION_VALIDATION,
    )
    attempt = queue_candidate_validation(
        db, candidate_id=candidate_id, actor=actor
    )
    return _to_attempt_response(attempt)


@router.get(
    "/{candidate_id}/validation-attempts",
    response_model=list[ValidationAttemptResponse],
)
def list_validation_attempts_endpoint(
    candidate_id: UUID,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
) -> list[ValidationAttemptResponse]:
    attempts = list_candidate_validation_attempts(
        db, candidate_id=candidate_id, user_id=auth.user.id
    )
    return [_to_attempt_response(item) for item in attempts]


@router.post(
    "/{candidate_id}/promote",
    response_model=FindingResponse,
)
def promote_candidate_endpoint(
    candidate_id: UUID,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
) -> FindingResponse:
    actor = require_active_org_actor(auth)
    finding = promote_candidate_to_finding(
        db, candidate_id=candidate_id, actor=actor
    )
    asset = db.get(Asset, finding.asset_id)
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
