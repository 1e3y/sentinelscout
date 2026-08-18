from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import AuthContext, get_auth_context, get_db
from app.models.asset import Asset
from app.schemas.candidate import SecurityCandidateResponse
from app.schemas.discovery import AssetResponse, DiscoveryObservationResponse
from app.schemas.audit import OperationControlSnapshotResponse
from app.schemas.coverage import OperationCoverageResponse
from app.schemas.diff import OperationDiffResponse
from app.schemas.operation import (
    CreateOperationRequest,
    OperationEventResponse,
    OperationResponse,
)
from app.services.operations import (
    create_operation,
    get_operation_coverage,
    get_operation_diff,
    get_operation_or_404,
    list_operation_assets,
    list_operation_candidates,
    list_operation_events,
    list_operation_observations,
    list_operations,
    stop_operation,
)
from app.services.rate_limit import ACTION_OPERATION_CREATE, enforce_rate_limit

router = APIRouter(prefix="/v1/operations", tags=["operations"])


def _to_control_snapshot_response(snapshot) -> OperationControlSnapshotResponse | None:
    if snapshot is None:
        return None
    return OperationControlSnapshotResponse(
        id=snapshot.id,
        operation_id=snapshot.operation_id,
        organization_id=snapshot.organization_id,
        target_id=snapshot.target_id,
        target_domain=snapshot.target_domain,
        authorization_status=snapshot.authorization_status,
        target_authorization_id=snapshot.target_authorization_id,
        scope_root=snapshot.scope_root,
        include_subdomains=bool(snapshot.include_subdomains),
        exclusions=[str(item) for item in (snapshot.exclusions or [])],
        operation_source=snapshot.operation_source,
        testing_profile=snapshot.testing_profile,
        created_by_user_id=snapshot.created_by_user_id,
        created_at=snapshot.created_at,
        notes=snapshot.notes,
    )


def _to_operation_response(operation) -> OperationResponse:
    return OperationResponse(
        id=operation.id,
        organization_id=operation.organization_id,
        target_id=operation.target_id,
        target_domain=operation.target.domain,
        created_by_user_id=operation.created_by_user_id,
        status=operation.status,
        source=getattr(operation, "source", None) or "manual",
        testing_profile=getattr(operation, "testing_profile", None) or "safe_production",
        stop_requested=bool(operation.stop_requested),
        created_at=operation.created_at,
        started_at=operation.started_at,
        completed_at=operation.completed_at,
        failed_at=operation.failed_at,
        stopped_at=operation.stopped_at,
        error_code=operation.error_code,
        error_message=operation.error_message,
        control_snapshot=_to_control_snapshot_response(
            getattr(operation, "control_snapshot", None)
        ),
    )


def _to_event_response(event) -> OperationEventResponse:
    return OperationEventResponse(
        id=event.id,
        operation_id=event.operation_id,
        sequence=event.sequence,
        event_type=event.event_type,
        summary=event.summary,
        metadata=dict(event.event_metadata or {}),
        created_at=event.created_at,
    )


@router.post("", response_model=OperationResponse, status_code=201)
def create_operation_endpoint(
    body: CreateOperationRequest,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
) -> OperationResponse:
    if auth.active_organization is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Active organization required",
        )
    enforce_rate_limit(
        db,
        organization_id=auth.active_organization.id,
        user_id=auth.user.id,
        action=ACTION_OPERATION_CREATE,
    )
    operation = create_operation(db, user=auth.user, target_id=body.target_id)
    return _to_operation_response(operation)


@router.get("", response_model=list[OperationResponse])
def list_operations_endpoint(
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
) -> list[OperationResponse]:
    operations = list_operations(db, user_id=auth.user.id)
    return [_to_operation_response(op) for op in operations]


@router.get("/{operation_id}", response_model=OperationResponse)
def get_operation_endpoint(
    operation_id: UUID,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
) -> OperationResponse:
    operation = get_operation_or_404(db, operation_id=operation_id, user_id=auth.user.id)
    return _to_operation_response(operation)


@router.get("/{operation_id}/events", response_model=list[OperationEventResponse])
def list_events_endpoint(
    operation_id: UUID,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
) -> list[OperationEventResponse]:
    events = list_operation_events(db, operation_id=operation_id, user_id=auth.user.id)
    return [_to_event_response(event) for event in events]


@router.get("/{operation_id}/assets", response_model=list[AssetResponse])
def list_assets_endpoint(
    operation_id: UUID,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
) -> list[AssetResponse]:
    assets = list_operation_assets(db, operation_id=operation_id, user_id=auth.user.id)
    return [AssetResponse.model_validate(asset) for asset in assets]


@router.get("/{operation_id}/observations", response_model=list[DiscoveryObservationResponse])
def list_observations_endpoint(
    operation_id: UUID,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
) -> list[DiscoveryObservationResponse]:
    rows = list_operation_observations(
        db, operation_id=operation_id, user_id=auth.user.id
    )
    return [
        DiscoveryObservationResponse(
            id=row.id,
            organization_id=row.organization_id,
            operation_id=row.operation_id,
            asset_id=row.asset_id,
            observation_type=row.observation_type,
            summary=row.summary,
            metadata=dict(row.observation_metadata or {}),
            source=row.source,
            created_at=row.created_at,
        )
        for row in rows
    ]


@router.get("/{operation_id}/coverage", response_model=OperationCoverageResponse)
def get_coverage_endpoint(
    operation_id: UUID,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
) -> OperationCoverageResponse:
    payload = get_operation_coverage(
        db, operation_id=operation_id, user_id=auth.user.id
    )
    return OperationCoverageResponse.model_validate(payload)


@router.get("/{operation_id}/diff", response_model=OperationDiffResponse)
def get_diff_endpoint(
    operation_id: UUID,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
) -> OperationDiffResponse:
    payload = get_operation_diff(
        db, operation_id=operation_id, user_id=auth.user.id
    )
    return OperationDiffResponse.model_validate(payload)


@router.get("/{operation_id}/candidates", response_model=list[SecurityCandidateResponse])
def list_candidates_endpoint(
    operation_id: UUID,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
) -> list[SecurityCandidateResponse]:
    rows = list_operation_candidates(
        db, operation_id=operation_id, user_id=auth.user.id
    )
    asset_ids = {row.asset_id for row in rows}
    assets_by_id: dict[UUID, Asset] = {}
    if asset_ids:
        assets_by_id = {
            asset.id: asset
            for asset in db.scalars(select(Asset).where(Asset.id.in_(asset_ids))).all()
        }
    return [
        SecurityCandidateResponse(
            id=row.id,
            organization_id=row.organization_id,
            operation_id=row.operation_id,
            asset_id=row.asset_id,
            asset_hostname=(
                assets_by_id[row.asset_id].hostname if row.asset_id in assets_by_id else None
            ),
            asset_url=(
                assets_by_id[row.asset_id].url if row.asset_id in assets_by_id else None
            ),
            candidate_type=row.candidate_type,
            title=row.title,
            summary=row.summary,
            status=row.status,
            source=row.source,
            evidence=dict(row.evidence or {}),
            created_at=row.created_at,
            updated_at=row.updated_at,
        )
        for row in rows
    ]


@router.post("/{operation_id}/stop", response_model=OperationResponse)
def stop_operation_endpoint(
    operation_id: UUID,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[Session, Depends(get_db)],
) -> OperationResponse:
    operation = stop_operation(db, operation_id=operation_id, user_id=auth.user.id)
    return _to_operation_response(operation)
