from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session, joinedload

from app.models import OrganizationMembership
from app.models.asset import Asset, DiscoveryObservation
from app.models.candidate import SecurityCandidate
from app.models.coverage import OperationCoverageSummary
from app.models.operation import Operation, OperationEvent
from app.models.operation_controls import TESTING_PROFILE_SAFE_PRODUCTION
from app.models.target import AuthorizedTarget
from app.models.user import User
from app.models.validation import ACTIVE_VALIDATION_STATUSES, ValidationAttempt
from app.services.audit import record_audit
from app.services.coverage import (
    assemble_live_coverage,
    coverage_payload_from_snapshot,
    freeze_operation_coverage,
)
from app.services.operation_controls import create_control_snapshot
from app.services.validation_engine.types import method_for_candidate_type

# Only non-sensitive keys allowed in event metadata.
_ALLOWED_METADATA_KEYS = frozenset(
    {
        "target_id",
        "domain",
        "status",
        "stage",
        "hostname",
        "url",
        "status_code",
        "asset_id",
        "count",
        "observation_type",
        "candidate_type",
        "candidate_id",
        "validation_method",
        "finding_id",
        "severity",
        "retest_id",
        "source",
        "previous_status_code",
        "title",
    }
)

TERMINAL_STATUSES = frozenset({"completed", "failed", "stopped"})


def _user_org_ids(db: Session, user_id: UUID) -> set[UUID]:
    rows = db.scalars(
        select(OrganizationMembership.organization_id).where(
            OrganizationMembership.user_id == user_id
        )
    ).all()
    return set(rows)


def _require_org_membership(db: Session, *, user_id: UUID, organization_id: UUID) -> None:
    membership = db.scalar(
        select(OrganizationMembership).where(
            OrganizationMembership.user_id == user_id,
            OrganizationMembership.organization_id == organization_id,
        )
    )
    if membership is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Operation not found")


def sanitize_event_metadata(metadata: dict | None) -> dict:
    if not metadata:
        return {}
    clean: dict = {}
    for key, value in metadata.items():
        if key not in _ALLOWED_METADATA_KEYS:
            continue
        if isinstance(value, (str, int, float, bool)) or value is None:
            clean[key] = value
        else:
            clean[key] = str(value)
    return clean


def append_event(
    db: Session,
    operation: Operation,
    *,
    event_type: str,
    summary: str,
    metadata: dict | None = None,
) -> OperationEvent:
    next_seq = db.scalar(
        select(func.coalesce(func.max(OperationEvent.sequence), 0)).where(
            OperationEvent.operation_id == operation.id
        )
    )
    event = OperationEvent(
        operation_id=operation.id,
        sequence=int(next_seq or 0) + 1,
        event_type=event_type,
        summary=summary,
        event_metadata=sanitize_event_metadata(metadata),
    )
    db.add(event)
    db.flush()
    return event


def create_operation(
    db: Session,
    *,
    user: User,
    target_id: UUID,
    source: str = "manual",
) -> Operation:
    if source not in {"manual", "scheduled"}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid operation source",
        )
    target = db.scalar(
        select(AuthorizedTarget)
        .options(
            joinedload(AuthorizedTarget.scope),
            joinedload(AuthorizedTarget.authorization),
        )
        .where(AuthorizedTarget.id == target_id)
    )
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found")

    membership = db.scalar(
        select(OrganizationMembership).where(
            OrganizationMembership.user_id == user.id,
            OrganizationMembership.organization_id == target.organization_id,
        )
    )
    if membership is None:
        # Do not leak target existence across orgs.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found")

    if target.status == "revoked":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot create operation for a revoked target",
        )
    if target.status != "verified":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target must be verified before creating an operation",
        )
    if target.scope is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target scope is required before creating an operation",
        )

    operation = Operation(
        organization_id=target.organization_id,
        target_id=target.id,
        created_by_user_id=user.id,
        status="queued",
        source=source,
        testing_profile=TESTING_PROFILE_SAFE_PRODUCTION,
    )
    db.add(operation)
    db.flush()
    create_control_snapshot(db, operation=operation, target=target)

    append_event(
        db,
        operation,
        event_type="operation.created",
        summary="Scout operation queued.",
        metadata={
            "target_id": str(target.id),
            "domain": target.domain,
            "status": "queued",
            "source": source,
        },
    )
    record_audit(
        db,
        organization_id=operation.organization_id,
        actor_type="user",
        actor_user_id=user.id,
        action="operation.created",
        resource_type="operation",
        resource_id=operation.id,
        summary=f"Operation created for {target.domain} ({source}).",
        metadata={
            "target_id": str(target.id),
            "domain": target.domain,
            "source": source,
            "status": "queued",
            "testing_profile": TESTING_PROFILE_SAFE_PRODUCTION,
            "authorization_status": target.status,
            "scope_root": target.scope.root_domain,
            "include_subdomains": bool(target.scope.include_subdomains),
            "exclusions_count": len(list(target.scope.exclusions or [])),
        },
    )
    db.commit()
    return get_operation_or_404(db, operation_id=operation.id, user_id=user.id)


def list_operations(db: Session, *, user_id: UUID) -> list[Operation]:
    org_ids = _user_org_ids(db, user_id)
    if not org_ids:
        return []
    return list(
        db.scalars(
            select(Operation)
            .options(
                joinedload(Operation.target),
                joinedload(Operation.control_snapshot),
            )
            .where(Operation.organization_id.in_(org_ids))
            .order_by(Operation.created_at.desc())
        )
        .unique()
        .all()
    )


def get_operation_or_404(
    db: Session,
    *,
    operation_id: UUID,
    user_id: UUID,
) -> Operation:
    operation = db.scalar(
        select(Operation)
        .options(
            joinedload(Operation.target),
            joinedload(Operation.events),
            joinedload(Operation.control_snapshot),
        )
        .where(Operation.id == operation_id)
    )
    if operation is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Operation not found")

    _require_org_membership(
        db, user_id=user_id, organization_id=operation.organization_id
    )
    return operation


def list_operation_events(
    db: Session,
    *,
    operation_id: UUID,
    user_id: UUID,
) -> list[OperationEvent]:
    operation = get_operation_or_404(db, operation_id=operation_id, user_id=user_id)
    return list(
        db.scalars(
            select(OperationEvent)
            .where(OperationEvent.operation_id == operation.id)
            .order_by(OperationEvent.sequence.asc())
        ).all()
    )


def list_operation_assets(
    db: Session,
    *,
    operation_id: UUID,
    user_id: UUID,
) -> list[Asset]:
    operation = get_operation_or_404(db, operation_id=operation_id, user_id=user_id)
    asset_ids = db.scalars(
        select(DiscoveryObservation.asset_id).where(
            DiscoveryObservation.operation_id == operation.id,
            DiscoveryObservation.asset_id.is_not(None),
        )
    ).all()
    ids = {asset_id for asset_id in asset_ids if asset_id is not None}
    if not ids:
        return []
    return list(
        db.scalars(
            select(Asset)
            .where(Asset.id.in_(ids))
            .order_by(Asset.hostname.asc(), Asset.url.asc())
        ).all()
    )


def list_operation_observations(
    db: Session,
    *,
    operation_id: UUID,
    user_id: UUID,
) -> list[DiscoveryObservation]:
    operation = get_operation_or_404(db, operation_id=operation_id, user_id=user_id)
    return list(
        db.scalars(
            select(DiscoveryObservation)
            .where(DiscoveryObservation.operation_id == operation.id)
            .order_by(DiscoveryObservation.created_at.asc())
        ).all()
    )


def list_operation_candidates(
    db: Session,
    *,
    operation_id: UUID,
    user_id: UUID,
) -> list[SecurityCandidate]:
    operation = get_operation_or_404(db, operation_id=operation_id, user_id=user_id)
    return list(
        db.scalars(
            select(SecurityCandidate)
            .where(SecurityCandidate.operation_id == operation.id)
            .order_by(SecurityCandidate.created_at.asc())
        ).all()
    )


def get_candidate_or_404(
    db: Session,
    *,
    candidate_id: UUID,
    user_id: UUID,
) -> SecurityCandidate:
    candidate = db.get(SecurityCandidate, candidate_id)
    if candidate is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Candidate not found")
    _require_org_membership(
        db, user_id=user_id, organization_id=candidate.organization_id
    )
    return candidate


def dismiss_candidate(
    db: Session,
    *,
    candidate_id: UUID,
    user_id: UUID,
) -> SecurityCandidate:
    candidate = get_candidate_or_404(db, candidate_id=candidate_id, user_id=user_id)
    if candidate.status == "dismissed":
        return candidate
    candidate.status = "dismissed"
    operation = db.get(Operation, candidate.operation_id)
    if operation is not None:
        append_event(
            db,
            operation,
            event_type="candidate.dismissed",
            summary=f"Security candidate dismissed: {candidate.title}",
            metadata={
                "candidate_id": str(candidate.id),
                "asset_id": str(candidate.asset_id),
                "candidate_type": candidate.candidate_type,
                "status": "dismissed",
            },
        )
    record_audit(
        db,
        organization_id=candidate.organization_id,
        actor_type="user",
        actor_user_id=user_id,
        action="candidate.dismissed",
        resource_type="candidate",
        resource_id=candidate.id,
        summary=f"Security candidate dismissed: {candidate.title}",
        metadata={
            "candidate_id": str(candidate.id),
            "candidate_type": candidate.candidate_type,
            "asset_id": str(candidate.asset_id),
            "operation_id": str(candidate.operation_id),
            "status": "dismissed",
        },
    )
    db.commit()
    db.refresh(candidate)
    return candidate


def queue_candidate_validation(
    db: Session,
    *,
    candidate_id: UUID,
    user_id: UUID,
) -> ValidationAttempt:
    candidate = get_candidate_or_404(db, candidate_id=candidate_id, user_id=user_id)
    if candidate.status == "dismissed":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot validate a dismissed candidate",
        )

    active = db.scalar(
        select(ValidationAttempt).where(
            ValidationAttempt.candidate_id == candidate.id,
            ValidationAttempt.status.in_(tuple(ACTIVE_VALIDATION_STATUSES)),
        )
    )
    if active is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A validation attempt is already pending or running for this candidate",
        )

    method = method_for_candidate_type(candidate.candidate_type) or "none"
    attempt = ValidationAttempt(
        organization_id=candidate.organization_id,
        operation_id=candidate.operation_id,
        candidate_id=candidate.id,
        asset_id=candidate.asset_id,
        status="pending",
        validation_method=method,
        summary="Safe validation queued.",
        evidence={},
    )
    db.add(attempt)
    db.flush()
    record_audit(
        db,
        organization_id=candidate.organization_id,
        actor_type="user",
        actor_user_id=user_id,
        action="validation.requested",
        resource_type="validation_attempt",
        resource_id=attempt.id,
        summary=f"Safe validation requested for candidate: {candidate.title}",
        metadata={
            "candidate_id": str(candidate.id),
            "candidate_type": candidate.candidate_type,
            "operation_id": str(candidate.operation_id),
            "asset_id": str(candidate.asset_id),
            "validation_method": method,
            "status": "pending",
            "validation_attempt_id": str(attempt.id),
        },
    )
    db.commit()
    db.refresh(attempt)
    return attempt


def list_candidate_validation_attempts(
    db: Session,
    *,
    candidate_id: UUID,
    user_id: UUID,
) -> list[ValidationAttempt]:
    candidate = get_candidate_or_404(db, candidate_id=candidate_id, user_id=user_id)
    return list(
        db.scalars(
            select(ValidationAttempt)
            .where(ValidationAttempt.candidate_id == candidate.id)
            .order_by(ValidationAttempt.created_at.asc())
        ).all()
    )


def stop_operation(
    db: Session,
    *,
    operation_id: UUID,
    user_id: UUID,
) -> Operation:
    operation = get_operation_or_404(db, operation_id=operation_id, user_id=user_id)

    if operation.status in TERMINAL_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot stop an operation in status '{operation.status}'",
        )

    if operation.status == "queued":
        operation.status = "stopped"
        operation.stopped_at = datetime.now(timezone.utc)
        operation.stop_requested = True
        append_event(
            db,
            operation,
            event_type="operation.stopped",
            summary="Scout operation stopped.",
            metadata={"status": "stopped"},
        )
        record_audit(
            db,
            organization_id=operation.organization_id,
            actor_type="user",
            actor_user_id=user_id,
            action="operation.stopped",
            resource_type="operation",
            resource_id=operation.id,
            summary="Scout operation stopped before start.",
            metadata={
                "operation_id": str(operation.id),
                "target_id": str(operation.target_id),
                "status": "stopped",
                "source": operation.source,
                "testing_profile": operation.testing_profile,
            },
        )
        freeze_operation_coverage(
            db, operation, source="frozen", actor_type="user"
        )
        db.commit()
        return get_operation_or_404(db, operation_id=operation.id, user_id=user_id)

    if operation.status == "running":
        # Cooperative cancellation: worker notices between stages.
        operation.stop_requested = True
        record_audit(
            db,
            organization_id=operation.organization_id,
            actor_type="user",
            actor_user_id=user_id,
            action="operation.stopped",
            resource_type="operation",
            resource_id=operation.id,
            summary="Stop requested for running Scout operation.",
            metadata={
                "operation_id": str(operation.id),
                "target_id": str(operation.target_id),
                "status": "running",
                "source": operation.source,
                "reason": "stop_requested",
            },
        )
        db.commit()
        return get_operation_or_404(db, operation_id=operation.id, user_id=user_id)

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=f"Cannot stop an operation in status '{operation.status}'",
    )


def get_operation_coverage(
    db: Session,
    *,
    operation_id: UUID,
    user_id: UUID,
) -> dict:
    operation = get_operation_or_404(db, operation_id=operation_id, user_id=user_id)
    if operation.status in TERMINAL_STATUSES:
        existing = db.scalar(
            select(OperationCoverageSummary).where(
                OperationCoverageSummary.operation_id == operation.id
            )
        )
        row = freeze_operation_coverage(
            db,
            operation,
            source="recovered",
            actor_type="system",
        )
        if existing is None and row is not None:
            db.commit()
            db.refresh(row)
        if row is not None:
            return coverage_payload_from_snapshot(db, operation, row)
    return assemble_live_coverage(db, operation)

