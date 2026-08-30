from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import AuthContext, get_auth_context, get_db, require_active_org_actor
from app.models.asset import Asset
from app.schemas.audit import FindingProvenanceResponse
from app.schemas.finding import FindingResponse
from app.schemas.finding_remediation import (
    CreateFindingRemediationRevisionRequest,
    FindingRemediationHistoryResponse,
    FindingRemediationRevisionResponse,
)
from app.schemas.finding_timeline import FindingTimelineResponse
from app.schemas.findings_inbox import (
    CurrentRetestState,
    FindingInboxResponse,
    FindingInboxSeverity,
    FindingInboxStatus,
)
from app.schemas.retest import RetestAttemptResponse
from app.services.authorization import assert_actor_org
from app.services.findings import (
    get_finding_or_404,
    list_finding_timeline,
    list_findings_for_user,
    list_remediation_revisions,
    mark_ready_for_retest,
    record_remediation_revision,
    start_remediation,
)
from app.services.findings.remediation_record import (
    DEFAULT_REMEDIATION_PAGE_SIZE,
    MAX_REMEDIATION_PAGE_SIZE,
)
from app.services.findings.timeline import (
    DEFAULT_TIMELINE_PAGE_SIZE,
    MAX_TIMELINE_PAGE_SIZE,
)
from app.services.findings_inbox import (
    DEFAULT_PAGE_SIZE,
    MAX_PAGE_SIZE,
    list_findings_inbox,
)
from app.services.provenance import build_finding_provenance
from app.services.rate_limit import (
    ACTION_REMEDIATION_RECORD,
    ACTION_RETEST,
    enforce_rate_limit,
)
from app.services.retest_runtime import list_finding_retests, queue_finding_retest
from app.services.targets import require_active_organization

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


# Must stay above "/{finding_id}": that path converts to UUID, so a later
# declaration order would turn /v1/findings/inbox into a 422.
@router.get("/inbox", response_model=FindingInboxResponse)
def findings_inbox_endpoint(
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
    page_size: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = DEFAULT_PAGE_SIZE,
    cursor: str | None = None,
    status: FindingInboxStatus | None = None,
    severity: FindingInboxSeverity | None = None,
    target_id: UUID | None = None,
    retest_state: CurrentRetestState | None = None,
) -> FindingInboxResponse:
    """Current findings for the caller's active organization. Members and admins alike."""
    require_active_organization(auth)
    assert auth.active_organization is not None
    return list_findings_inbox(
        db,
        organization=auth.active_organization,
        page_size=page_size,
        cursor=cursor,
        finding_status=status,
        severity=severity,
        target_id=target_id,
        retest_state=retest_state,
    )


@router.get("/{finding_id}", response_model=FindingResponse)
def get_finding_endpoint(
    finding_id: UUID,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
) -> FindingResponse:
    finding = get_finding_or_404(db, finding_id=finding_id, user_id=auth.user.id)
    asset = db.get(Asset, finding.asset_id)
    return _to_finding_response(db, finding, asset)


@router.get("/{finding_id}/timeline", response_model=FindingTimelineResponse)
def finding_timeline_endpoint(
    finding_id: UUID,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
    page_size: Annotated[
        int, Query(ge=1, le=MAX_TIMELINE_PAGE_SIZE)
    ] = DEFAULT_TIMELINE_PAGE_SIZE,
    cursor: str | None = None,
) -> FindingTimelineResponse:
    """Durable history for one Finding in the verified active organization."""
    require_active_organization(auth)
    assert auth.active_organization is not None
    return list_finding_timeline(
        db,
        finding_id=finding_id,
        organization_id=auth.active_organization.id,
        page_size=page_size,
        cursor=cursor,
    )


@router.get(
    "/{finding_id}/remediation",
    response_model=FindingRemediationHistoryResponse,
)
def list_finding_remediation_endpoint(
    finding_id: UUID,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
    page_size: Annotated[
        int, Query(ge=1, le=MAX_REMEDIATION_PAGE_SIZE)
    ] = DEFAULT_REMEDIATION_PAGE_SIZE,
    cursor: str | None = None,
) -> FindingRemediationHistoryResponse:
    return list_remediation_revisions(
        db,
        finding_id=finding_id,
        user_id=auth.user.id,
        page_size=page_size,
        cursor=cursor,
    )


@router.post(
    "/{finding_id}/remediation",
    response_model=FindingRemediationRevisionResponse,
    status_code=status.HTTP_201_CREATED,
)
def record_finding_remediation_endpoint(
    finding_id: UUID,
    body: CreateFindingRemediationRevisionRequest,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
) -> FindingRemediationRevisionResponse:
    actor = require_active_org_actor(auth)
    finding = get_finding_or_404(db, finding_id=finding_id, user_id=actor.user_id)
    assert_actor_org(actor, finding.organization_id, not_found="Finding not found")
    enforce_rate_limit(
        db,
        organization_id=finding.organization_id,
        user_id=actor.user_id,
        action=ACTION_REMEDIATION_RECORD,
    )
    created = record_remediation_revision(
        db,
        finding=finding,
        summary=body.summary,
        actor=actor,
    )
    return FindingRemediationRevisionResponse(
        id=created.revision.id,
        revision_number=created.revision.revision_number,
        summary=created.revision.summary,
        created_at=created.revision.created_at,
        created_by_user_id=created.revision.created_by_user_id,
        created_by_name=created.created_by_name,
    )


@router.post("/{finding_id}/start-remediation", response_model=FindingResponse)
def start_remediation_endpoint(
    finding_id: UUID,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
) -> FindingResponse:
    actor = require_active_org_actor(auth)
    finding = start_remediation(db, finding_id=finding_id, actor=actor)
    asset = db.get(Asset, finding.asset_id)
    return _to_finding_response(db, finding, asset)


@router.post("/{finding_id}/ready-for-retest", response_model=FindingResponse)
def ready_for_retest_endpoint(
    finding_id: UUID,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
) -> FindingResponse:
    actor = require_active_org_actor(auth)
    finding = mark_ready_for_retest(db, finding_id=finding_id, actor=actor)
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
    actor = require_active_org_actor(auth)
    finding = get_finding_or_404(db, finding_id=finding_id, user_id=actor.user_id)
    assert_actor_org(actor, finding.organization_id, not_found="Finding not found")
    enforce_rate_limit(
        db,
        organization_id=finding.organization_id,
        user_id=actor.user_id,
        action=ACTION_RETEST,
    )
    attempt = queue_finding_retest(db, finding_id=finding_id, actor=actor)
    return _to_retest_response(attempt)


@router.get("/{finding_id}/retests", response_model=list[RetestAttemptResponse])
def list_retests_endpoint(
    finding_id: UUID,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
) -> list[RetestAttemptResponse]:
    attempts = list_finding_retests(db, finding_id=finding_id, user_id=auth.user.id)
    return [_to_retest_response(item) for item in attempts]
