"""Build evidence provenance chains for findings without duplicating raw bodies."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.candidate import SecurityCandidate
from app.models.finding import Finding
from app.models.operation import Operation
from app.models.retest import RetestAttempt
from app.models.validation import ValidationAttempt
from app.services.operation_controls import get_control_snapshot


def build_finding_provenance(db: Session, finding: Finding) -> dict[str, Any]:
    evidence = finding.evidence or {}
    provenance = dict(evidence.get("provenance") or {})

    candidate = db.get(SecurityCandidate, finding.candidate_id)
    operation = db.get(Operation, finding.operation_id)
    snapshot = get_control_snapshot(db, operation_id=finding.operation_id)

    validation_id = provenance.get("validation_attempt_id")
    validation = None
    if validation_id:
        try:
            validation = db.get(ValidationAttempt, UUID(str(validation_id)))
        except ValueError:
            validation = None
    if validation is None:
        validation = db.scalar(
            select(ValidationAttempt)
            .where(
                ValidationAttempt.candidate_id == finding.candidate_id,
                ValidationAttempt.status == "supported",
            )
            .order_by(ValidationAttempt.completed_at.desc().nullslast())
            .limit(1)
        )

    observation_ids = list(
        provenance.get("observation_ids")
        or (validation.evidence or {}).get("observation_ids")
        or (candidate.evidence or {}).get("observation_ids")
        or []
    )[:50]

    resolving_retest_id = evidence.get("resolving_retest_id")
    retest = None
    if resolving_retest_id:
        try:
            retest = db.get(RetestAttempt, UUID(str(resolving_retest_id)))
        except ValueError:
            retest = None
    if retest is None and finding.status == "resolved":
        retest = db.scalar(
            select(RetestAttempt)
            .where(
                RetestAttempt.finding_id == finding.id,
                RetestAttempt.status == "passed",
            )
            .order_by(RetestAttempt.completed_at.desc().nullslast())
            .limit(1)
        )

    chain = [
        "observation",
        "candidate",
        "safe_validation",
        "finding",
    ]
    if retest is not None:
        chain.append("retest")
        if finding.status == "resolved":
            chain.append("resolved")

    return {
        "chain": chain,
        "finding_id": str(finding.id),
        "candidate_id": str(finding.candidate_id),
        "asset_id": str(finding.asset_id),
        "operation_id": str(finding.operation_id),
        "target_id": str(operation.target_id) if operation else None,
        "observation_ids": [str(i) for i in observation_ids],
        "validation_attempt_id": str(validation.id) if validation else None,
        "validation_method": validation.validation_method if validation else None,
        "retest_attempt_id": str(retest.id) if retest else None,
        "control_snapshot": {
            "target_domain": snapshot.target_domain,
            "authorization_status": snapshot.authorization_status,
            "scope_root": snapshot.scope_root,
            "include_subdomains": snapshot.include_subdomains,
            "exclusions": list(snapshot.exclusions or []),
            "testing_profile": snapshot.testing_profile,
            "operation_source": snapshot.operation_source,
        }
        if snapshot
        else None,
    }
