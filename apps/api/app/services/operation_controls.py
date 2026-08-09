"""Immutable operation control snapshots at creation time."""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.operation import Operation
from app.models.operation_controls import (
    TESTING_PROFILE_SAFE_PRODUCTION,
    OperationControlSnapshot,
)
from app.models.target import AuthorizedTarget


def create_control_snapshot(
    db: Session,
    *,
    operation: Operation,
    target: AuthorizedTarget,
) -> OperationControlSnapshot:
    scope = target.scope
    if scope is None:
        raise ValueError("Cannot snapshot operation controls without target scope")

    authz_id = target.authorization.id if target.authorization is not None else None
    snapshot = OperationControlSnapshot(
        operation_id=operation.id,
        organization_id=operation.organization_id,
        target_id=target.id,
        target_domain=target.domain,
        authorization_status=target.status,
        target_authorization_id=authz_id,
        scope_root=scope.root_domain,
        include_subdomains=bool(scope.include_subdomains),
        exclusions=list(scope.exclusions or []),
        operation_source=operation.source,
        testing_profile=operation.testing_profile or TESTING_PROFILE_SAFE_PRODUCTION,
        created_by_user_id=operation.created_by_user_id,
        notes=(
            "safe_production: discovery within authorized scope; conservative HTTP probing; "
            "GET/HEAD validation only; no credential or destructive actions."
        ),
    )
    db.add(snapshot)
    db.flush()
    return snapshot


def get_control_snapshot(
    db: Session, *, operation_id: UUID
) -> OperationControlSnapshot | None:
    return db.scalar(
        select(OperationControlSnapshot).where(
            OperationControlSnapshot.operation_id == operation_id
        )
    )

