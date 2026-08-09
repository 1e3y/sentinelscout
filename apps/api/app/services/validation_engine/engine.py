"""Orchestrate safe, allowlisted candidate validation with authz/scope checks."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.asset import Asset, DiscoveryObservation
from app.models.candidate import SecurityCandidate
from app.models.operation import Operation
from app.models.validation import ValidationAttempt
from app.services.discovery.execute import AuthorizationExecutionError, load_authorized_scope
from app.services.discovery.scope import host_in_scope
from app.services.audit import record_audit
from app.services.operations import append_event
from app.services.validation_engine.http import HttpxSafeHttpClient, SafeHttpClient
from app.services.validation_engine.methods import (
    inconclusive_unknown_type,
    resolve_method_for_candidate,
    run_allowlisted_method,
)
from app.services.validation_engine.types import ValidationResult

_EVENT_BY_STATUS = {
    "supported": "validation.supported",
    "unsupported": "validation.unsupported",
    "inconclusive": "validation.inconclusive",
    "failed": "validation.failed",
}


class ValidationAuthzError(Exception):
    """Authorization or scope prevents validation."""


def _load_observations(
    db: Session, *, candidate: SecurityCandidate
) -> list[DiscoveryObservation]:
    evidence_ids = (candidate.evidence or {}).get("observation_ids") or []
    ids: list[UUID] = []
    for raw in evidence_ids:
        try:
            ids.append(UUID(str(raw)))
        except ValueError:
            continue
    if ids:
        rows = list(
            db.scalars(
                select(DiscoveryObservation).where(DiscoveryObservation.id.in_(ids))
            ).all()
        )
        if rows:
            return rows
    return list(
        db.scalars(
            select(DiscoveryObservation).where(
                DiscoveryObservation.asset_id == candidate.asset_id,
                DiscoveryObservation.operation_id == candidate.operation_id,
            )
        ).all()
    )


def assert_validation_authorized(
    db: Session,
    *,
    operation: Operation,
    asset: Asset,
) -> None:
    target, scope = load_authorized_scope(db, operation)
    if asset.organization_id != operation.organization_id:
        raise ValidationAuthzError("Asset organization mismatch")
    if asset.target_id != target.id:
        raise ValidationAuthzError("Asset does not belong to the operation target")
    exclusions = list(scope.exclusions or [])
    if not host_in_scope(
        asset.hostname,
        scope.root_domain,
        include_subdomains=bool(scope.include_subdomains),
        exclusions=exclusions,
    ):
        raise ValidationAuthzError("Asset is outside authorized scope or excluded")


def evaluate_candidate(
    db: Session,
    *,
    candidate: SecurityCandidate,
    asset: Asset,
    operation: Operation,
    client: SafeHttpClient | None = None,
) -> ValidationResult:
    """Pure evaluation path used by the worker after authz checks."""
    method = resolve_method_for_candidate(candidate)
    if method is None:
        return inconclusive_unknown_type(candidate.id, candidate.candidate_type)

    http_client = client or HttpxSafeHttpClient()
    observations = _load_observations(db, candidate=candidate)
    return run_allowlisted_method(
        http_client,
        method=method,
        candidate=candidate,
        asset=asset,
        observations=observations,
    )


def apply_validation_result(
    db: Session,
    attempt: ValidationAttempt,
    *,
    candidate: SecurityCandidate,
    operation: Operation,
    result: ValidationResult,
) -> ValidationAttempt:
    now = datetime.now(timezone.utc)
    attempt.status = result.status
    attempt.validation_method = result.validation_method
    attempt.summary = result.summary
    attempt.evidence = dict(result.evidence or {})
    attempt.completed_at = now

    if result.status == "supported":
        candidate.status = "supported"
        candidate.updated_at = now
    elif result.status in {"unsupported", "inconclusive"} and candidate.status == "candidate":
        candidate.status = "needs_review"
        candidate.updated_at = now

    event_type = _EVENT_BY_STATUS.get(result.status, "validation.failed")
    append_event(
        db,
        operation,
        event_type=event_type,
        summary=result.summary,
        metadata={
            "candidate_id": str(candidate.id),
            "asset_id": str(attempt.asset_id),
            "candidate_type": candidate.candidate_type,
            "status": result.status,
            "validation_method": result.validation_method,
        },
    )
    record_audit(
        db,
        organization_id=operation.organization_id,
        actor_type="worker",
        actor_user_id=operation.created_by_user_id,
        action="validation.completed",
        resource_type="validation_attempt",
        resource_id=attempt.id,
        summary=result.summary,
        metadata={
            "candidate_id": str(candidate.id),
            "asset_id": str(attempt.asset_id),
            "operation_id": str(operation.id),
            "validation_attempt_id": str(attempt.id),
            "validation_method": result.validation_method,
            "validation_status": result.status,
            "status": result.status,
            "candidate_type": candidate.candidate_type,
        },
    )
    db.commit()
    db.refresh(attempt)
    return attempt


def mark_validation_failed(
    db: Session,
    attempt: ValidationAttempt,
    *,
    candidate: SecurityCandidate,
    operation: Operation,
    summary: str,
    evidence: dict | None = None,
) -> ValidationAttempt:
    result = ValidationResult(
        status="failed",
        validation_method=attempt.validation_method or "none",
        summary=summary,
        evidence=evidence
        or {
            "method": attempt.validation_method,
            "candidate_id": str(candidate.id),
            "asset_id": str(attempt.asset_id),
        },
    )
    return apply_validation_result(
        db, attempt, candidate=candidate, operation=operation, result=result
    )
