"""Queue, claim, and execute safe RetestAttempt jobs via the validation engine."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.models.asset import Asset, DiscoveryObservation
from app.models.candidate import SecurityCandidate
from app.models.finding import Finding
from app.models.operation import Operation
from app.models.organization import OrganizationMembership
from app.models.retest import ACTIVE_RETEST_STATUSES, RetestAttempt
from app.models.validation import ValidationAttempt
from app.services.audit import record_audit
from app.services.authorization import AuthorizedOrgActor, assert_actor_org, merge_auth_audit
from app.services.discovery.execute import AuthorizationExecutionError
from app.services.operations import append_event
from app.services.validation_engine.engine import (
    ValidationAuthzError,
    assert_validation_authorized,
)
from app.services.validation_engine.http import HttpxSafeHttpClient, SafeHttpClient
from app.services.validation_engine.methods import run_allowlisted_method
from app.services.validation_engine.types import ALLOWLISTED_VALIDATION_METHODS, ValidationResult

logger = logging.getLogger(__name__)

_EVENT_BY_RETEST_STATUS = {
    "passed": "retest.passed",
    "failed": "retest.failed",
    "inconclusive": "retest.inconclusive",
    "error": "retest.error",
}


def _require_org_membership(db: Session, *, user_id: UUID, organization_id: UUID) -> None:
    membership = db.scalar(
        select(OrganizationMembership).where(
            OrganizationMembership.user_id == user_id,
            OrganizationMembership.organization_id == organization_id,
        )
    )
    if membership is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")


def _original_supported_validation(
    db: Session, *, finding: Finding
) -> ValidationAttempt | None:
    evidence = finding.evidence or {}
    provenance = evidence.get("provenance") or {}
    raw_id = provenance.get("validation_attempt_id")
    if raw_id:
        try:
            attempt = db.get(ValidationAttempt, UUID(str(raw_id)))
            if attempt is not None and attempt.status == "supported":
                return attempt
        except ValueError:
            pass
    return db.scalar(
        select(ValidationAttempt)
        .where(
            ValidationAttempt.candidate_id == finding.candidate_id,
            ValidationAttempt.status == "supported",
        )
        .order_by(ValidationAttempt.completed_at.desc().nullslast())
        .limit(1)
    )


def _load_observations(
    db: Session, *, candidate: SecurityCandidate, original: ValidationAttempt
) -> list[DiscoveryObservation]:
    ids: list[UUID] = []
    for source in (
        (original.evidence or {}).get("observation_ids") or [],
        (candidate.evidence or {}).get("observation_ids") or [],
    ):
        for raw in source:
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
                DiscoveryObservation.asset_id == candidate.asset_id
            )
        ).all()
    )


def map_validation_to_retest(result: ValidationResult) -> tuple[str, str]:
    """Map validation outcome to retest meaning.

    Retest asks whether the previously supported condition is still present.
    """
    if result.status == "unsupported":
        return (
            "passed",
            "Previously observed condition is no longer present.",
        )
    if result.status == "supported":
        return (
            "failed",
            "Previously observed condition remains present.",
        )
    if result.status == "inconclusive":
        return (
            "inconclusive",
            "Scout could not determine whether the remediation was effective.",
        )
    return (
        "error",
        "Safe retest could not complete reliably.",
    )


def queue_finding_retest(
    db: Session,
    *,
    finding_id: UUID,
    actor: AuthorizedOrgActor,
) -> RetestAttempt:
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    _require_org_membership(
        db, user_id=actor.user_id, organization_id=finding.organization_id
    )
    assert_actor_org(actor, finding.organization_id, not_found="Finding not found")

    if finding.status != "ready_for_retest":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only findings in ready_for_retest status can be retested",
        )

    active = db.scalar(
        select(RetestAttempt).where(
            RetestAttempt.finding_id == finding.id,
            RetestAttempt.status.in_(tuple(ACTIVE_RETEST_STATUSES)),
        )
    )
    if active is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A retest is already pending or running for this finding",
        )

    original = _original_supported_validation(db, finding=finding)
    if original is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A supported original validation attempt is required for retest",
        )
    method = original.validation_method
    if method not in ALLOWLISTED_VALIDATION_METHODS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Original validation method is not on the safe allowlist",
        )

    attempt = RetestAttempt(
        organization_id=finding.organization_id,
        finding_id=finding.id,
        candidate_id=finding.candidate_id,
        asset_id=finding.asset_id,
        original_validation_attempt_id=original.id,
        status="pending",
        method=method,
        summary="Safe retest queued.",
        evidence={},
    )
    db.add(attempt)
    db.flush()
    record_audit(
        db,
        organization_id=finding.organization_id,
        actor_type="user",
        actor_user_id=actor.user_id,
        action="retest.requested",
        resource_type="retest_attempt",
        resource_id=attempt.id,
        summary=f"Safe retest requested for finding: {finding.title}",
        metadata=merge_auth_audit(
            actor,
            {
                "finding_id": str(finding.id),
                "candidate_id": str(finding.candidate_id),
                "asset_id": str(finding.asset_id),
                "operation_id": str(finding.operation_id),
                "retest_id": str(attempt.id),
                "validation_attempt_id": str(original.id),
                "validation_method": method,
                "status": "pending",
            },
        ),
    )
    db.commit()
    db.refresh(attempt)
    return attempt


def list_finding_retests(
    db: Session,
    *,
    finding_id: UUID,
    user_id: UUID,
) -> list[RetestAttempt]:
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    _require_org_membership(
        db, user_id=user_id, organization_id=finding.organization_id
    )
    return list(
        db.scalars(
            select(RetestAttempt)
            .where(RetestAttempt.finding_id == finding.id)
            .order_by(RetestAttempt.created_at.asc())
        ).all()
    )


def claim_next_retest_attempt(db: Session) -> RetestAttempt | None:
    attempt = db.scalar(
        select(RetestAttempt)
        .where(RetestAttempt.status == "pending")
        .order_by(RetestAttempt.created_at.asc())
        .with_for_update(skip_locked=True)
        .limit(1)
    )
    if attempt is None:
        return None

    attempt.status = "running"
    finding = db.get(Finding, attempt.finding_id)
    operation = db.get(Operation, finding.operation_id) if finding else None
    if operation is not None and finding is not None:
        append_event(
            db,
            operation,
            event_type="retest.started",
            summary=f"Safe retest started for finding: {finding.title}",
            metadata={
                "finding_id": str(finding.id),
                "candidate_id": str(finding.candidate_id),
                "asset_id": str(attempt.asset_id),
                "status": "running",
                "validation_method": attempt.method,
                "retest_id": str(attempt.id),
            },
        )
    db.commit()
    db.refresh(attempt)
    return attempt


def _finish_retest(
    db: Session,
    attempt: RetestAttempt,
    *,
    finding: Finding,
    operation: Operation,
    status_value: str,
    summary: str,
    evidence: dict[str, Any],
) -> RetestAttempt:
    now = datetime.now(timezone.utc)
    attempt.status = status_value
    attempt.summary = summary
    attempt.evidence = evidence
    attempt.completed_at = now

    event_type = _EVENT_BY_RETEST_STATUS.get(status_value, "retest.error")
    append_event(
        db,
        operation,
        event_type=event_type,
        summary=summary,
        metadata={
            "finding_id": str(finding.id),
            "candidate_id": str(finding.candidate_id),
            "asset_id": str(attempt.asset_id),
            "status": status_value,
            "validation_method": attempt.method,
            "retest_id": str(attempt.id),
        },
    )
    record_audit(
        db,
        organization_id=finding.organization_id,
        actor_type="worker",
        actor_user_id=operation.created_by_user_id,
        action="retest.completed",
        resource_type="retest_attempt",
        resource_id=attempt.id,
        summary=summary,
        metadata={
            "finding_id": str(finding.id),
            "candidate_id": str(finding.candidate_id),
            "asset_id": str(attempt.asset_id),
            "operation_id": str(operation.id),
            "retest_id": str(attempt.id),
            "retest_status": status_value,
            "validation_method": attempt.method,
            "status": status_value,
        },
    )

    if status_value == "passed" and finding.status == "ready_for_retest":
        finding.status = "resolved"
        finding.resolved_at = now
        finding.updated_at = now
        evidence_blob = dict(finding.evidence or {})
        evidence_blob["resolving_retest_id"] = str(attempt.id)
        evidence_blob["resolved_via"] = "retest_passed"
        finding.evidence = evidence_blob
        append_event(
            db,
            operation,
            event_type="finding.resolved",
            summary=(
                f"Finding resolved after passing retest: {finding.title}. "
                "Previously observed condition is no longer present."
            ),
            metadata={
                "finding_id": str(finding.id),
                "candidate_id": str(finding.candidate_id),
                "asset_id": str(finding.asset_id),
                "status": "resolved",
                "retest_id": str(attempt.id),
                "validation_method": attempt.method,
            },
        )
        record_audit(
            db,
            organization_id=finding.organization_id,
            actor_type="worker",
            actor_user_id=operation.created_by_user_id,
            action="finding.resolved",
            resource_type="finding",
            resource_id=finding.id,
            summary=(
                f"Finding resolved after passing retest: {finding.title}."
            ),
            metadata={
                "finding_id": str(finding.id),
                "candidate_id": str(finding.candidate_id),
                "asset_id": str(finding.asset_id),
                "operation_id": str(operation.id),
                "retest_id": str(attempt.id),
                "status": "resolved",
                "validation_method": attempt.method,
            },
        )
    # failed / inconclusive / error: finding remains ready_for_retest

    db.commit()
    db.refresh(attempt)
    return attempt


def execute_retest_job(
    db: Session,
    attempt_id: UUID,
    *,
    http_client: SafeHttpClient | None = None,
) -> RetestAttempt:
    attempt = db.get(RetestAttempt, attempt_id)
    if attempt is None:
        raise RuntimeError("retest attempt disappeared")
    if attempt.status not in {"running", "pending"}:
        return attempt
    if attempt.status == "pending":
        attempt.status = "running"
        db.flush()

    finding = db.get(Finding, attempt.finding_id)
    candidate = db.get(SecurityCandidate, attempt.candidate_id)
    asset = db.get(Asset, attempt.asset_id)
    original = db.get(ValidationAttempt, attempt.original_validation_attempt_id)
    operation = db.get(Operation, finding.operation_id) if finding else None

    if (
        finding is None
        or candidate is None
        or asset is None
        or original is None
        or operation is None
    ):
        attempt.status = "error"
        attempt.summary = "Retest error: missing finding, candidate, asset, or validation."
        attempt.completed_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(attempt)
        return attempt

    if finding.status != "ready_for_retest":
        return _finish_retest(
            db,
            attempt,
            finding=finding,
            operation=operation,
            status_value="error",
            summary="Retest error: finding is no longer ready for retest.",
            evidence={
                "method": attempt.method,
                "finding_id": str(finding.id),
                "finding_status": finding.status,
            },
        )

    client = http_client or HttpxSafeHttpClient()
    try:
        assert_validation_authorized(db, operation=operation, asset=asset)
        observations = _load_observations(db, candidate=candidate, original=original)
        validation_result = run_allowlisted_method(
            client,
            method=attempt.method,
            candidate=candidate,
            asset=asset,
            observations=observations,
        )
        retest_status, summary = map_validation_to_retest(validation_result)
        evidence = {
            "method": attempt.method,
            "original_validation_attempt_id": str(original.id),
            "original_validation_method": original.validation_method,
            "validation_status": validation_result.status,
            "finding_id": str(finding.id),
            "candidate_id": str(candidate.id),
            "asset_id": str(asset.id),
            "observation_ids": list(
                (validation_result.evidence or {}).get("observation_ids") or []
            )[:50],
            "recheck": {
                k: v
                for k, v in (validation_result.evidence or {}).items()
                if k
                in {
                    "reachable",
                    "status_code",
                    "final_url",
                    "hostname",
                    "staging_markers",
                    "admin_signals",
                    "auth_signals",
                    "sensitive_markers",
                    "still_missing",
                    "observed_header",
                }
            },
        }
        return _finish_retest(
            db,
            attempt,
            finding=finding,
            operation=operation,
            status_value=retest_status,
            summary=summary,
            evidence=evidence,
        )
    except (ValidationAuthzError, AuthorizationExecutionError) as exc:
        logger.warning("retest authz failure for attempt %s: %s", attempt_id, exc)
        return _finish_retest(
            db,
            attempt,
            finding=finding,
            operation=operation,
            status_value="error",
            summary=(
                "Retest stopped because the target is not authorized "
                "or the asset is out of scope."
            ),
            evidence={
                "method": attempt.method,
                "finding_id": str(finding.id),
                "asset_id": str(asset.id),
                "reason": str(exc),
                "probed": False,
            },
        )
    except Exception:
        logger.exception("unexpected retest failure for attempt %s", attempt_id)
        return _finish_retest(
            db,
            attempt,
            finding=finding,
            operation=operation,
            status_value="error",
            summary="Safe retest failed unexpectedly.",
            evidence={
                "method": attempt.method,
                "finding_id": str(finding.id),
                "asset_id": str(asset.id),
            },
        )


def process_one_retest(
    session_factory: sessionmaker[Session],
    *,
    http_client: SafeHttpClient | None = None,
) -> RetestAttempt | None:
    db = session_factory()
    try:
        claimed = claim_next_retest_attempt(db)
        if claimed is None:
            return None
        attempt_id = claimed.id
    finally:
        db.close()

    db = session_factory()
    try:
        return execute_retest_job(db, attempt_id, http_client=http_client)
    finally:
        db.close()
