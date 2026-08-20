"""Promote evidence-supported SecurityCandidates into Findings."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.candidate import SecurityCandidate
from app.models.finding import Finding
from app.models.operation import Operation
from app.models.organization import OrganizationMembership
from app.models.validation import ValidationAttempt
from app.services.audit import record_audit
from app.services.authorization import AuthorizedOrgActor, assert_actor_org, merge_auth_audit
from app.services.findings.catalog import (
    business_impact_for_candidate_type,
    remediation_guidance_for_candidate_type,
    severity_for_candidate_type,
)
from app.services.operations import append_event


def _require_org_membership(db: Session, *, user_id: UUID, organization_id: UUID) -> None:
    membership = db.scalar(
        select(OrganizationMembership).where(
            OrganizationMembership.user_id == user_id,
            OrganizationMembership.organization_id == organization_id,
        )
    )
    if membership is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")


def _has_concrete_evidence(candidate: SecurityCandidate, attempt: ValidationAttempt) -> bool:
    cand_ev = candidate.evidence or {}
    att_ev = attempt.evidence or {}
    if not att_ev:
        return False
    # Require at least one concrete observable anchor.
    if att_ev.get("reachable") is True:
        return True
    if att_ev.get("status_code") is not None:
        return True
    if att_ev.get("still_missing") or att_ev.get("observed_header"):
        return True
    if cand_ev.get("observation_ids") or att_ev.get("observation_ids"):
        return bool(att_ev.get("method"))
    return False


def _build_finding_evidence(
    *,
    candidate: SecurityCandidate,
    asset: Asset,
    attempt: ValidationAttempt,
) -> dict[str, Any]:
    cand_ev = dict(candidate.evidence or {})
    att_ev = dict(attempt.evidence or {})
    return {
        "provenance": {
            "operation_id": str(candidate.operation_id),
            "asset_id": str(asset.id),
            "observation_ids": list(
                att_ev.get("observation_ids") or cand_ev.get("observation_ids") or []
            )[:50],
            "candidate_id": str(candidate.id),
            "validation_attempt_id": str(attempt.id),
        },
        "candidate_type": candidate.candidate_type,
        "candidate_evidence": {
            "reasons": list(cand_ev.get("reasons") or [])[:20],
            "signals": list(cand_ev.get("signals") or [])[:20],
            "why": cand_ev.get("why"),
        },
        "validation": {
            "method": attempt.validation_method,
            "status": attempt.status,
            "summary": attempt.summary,
            "evidence": {
                k: v
                for k, v in att_ev.items()
                if k
                in {
                    "method",
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
                    "observation_ids",
                }
            },
        },
        "asset": {
            "hostname": asset.hostname,
            "url": asset.url,
        },
        "evidence_supported": True,
    }


def promote_candidate_to_finding(
    db: Session,
    *,
    candidate_id: UUID,
    actor: AuthorizedOrgActor,
) -> Finding:
    candidate = db.get(SecurityCandidate, candidate_id)
    if candidate is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Candidate not found")
    _require_org_membership(
        db, user_id=actor.user_id, organization_id=candidate.organization_id
    )
    assert_actor_org(actor, candidate.organization_id, not_found="Candidate not found")

    existing = db.scalar(
        select(Finding).where(Finding.candidate_id == candidate.id)
    )
    if existing is not None:
        return existing

    if candidate.status != "supported":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only supported candidates can be promoted to findings",
        )

    attempt = db.scalar(
        select(ValidationAttempt)
        .where(
            ValidationAttempt.candidate_id == candidate.id,
            ValidationAttempt.status == "supported",
        )
        .order_by(ValidationAttempt.completed_at.desc().nullslast())
        .limit(1)
    )
    if attempt is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A supported validation attempt is required before promotion",
        )
    if not _has_concrete_evidence(candidate, attempt):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Concrete persisted evidence is required before promotion",
        )

    severity = severity_for_candidate_type(candidate.candidate_type)
    if severity is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No deterministic severity mapping exists for this candidate type",
        )

    asset = db.get(Asset, candidate.asset_id)
    if asset is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Asset missing")

    finding = Finding(
        organization_id=candidate.organization_id,
        operation_id=candidate.operation_id,
        candidate_id=candidate.id,
        asset_id=candidate.asset_id,
        title=candidate.title,
        summary=candidate.summary,
        severity=severity,
        status="open",
        business_impact=business_impact_for_candidate_type(candidate.candidate_type),
        remediation_guidance=remediation_guidance_for_candidate_type(
            candidate.candidate_type
        ),
        evidence=_build_finding_evidence(
            candidate=candidate, asset=asset, attempt=attempt
        ),
    )
    db.add(finding)
    db.flush()

    operation = db.get(Operation, candidate.operation_id)
    if operation is not None:
        append_event(
            db,
            operation,
            event_type="finding.created",
            summary=f"Finding created from supported candidate: {finding.title}",
            metadata={
                "finding_id": str(finding.id),
                "candidate_id": str(candidate.id),
                "asset_id": str(candidate.asset_id),
                "candidate_type": candidate.candidate_type,
                "severity": finding.severity,
                "status": finding.status,
            },
        )
    record_audit(
        db,
        organization_id=finding.organization_id,
        actor_type="user",
        actor_user_id=actor.user_id,
        action="finding.created",
        resource_type="finding",
        resource_id=finding.id,
        summary=f"Finding created from supported candidate: {finding.title}",
        metadata=merge_auth_audit(
            actor,
            {
                "finding_id": str(finding.id),
                "candidate_id": str(candidate.id),
                "asset_id": str(candidate.asset_id),
                "operation_id": str(candidate.operation_id),
                "candidate_type": candidate.candidate_type,
                "severity": finding.severity,
                "status": finding.status,
                "validation_attempt_id": str(attempt.id),
            },
        ),
    )
    db.commit()
    db.refresh(finding)
    return finding
