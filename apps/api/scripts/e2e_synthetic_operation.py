"""Local end-to-end check: queue → claim → synthetic complete.

Run from apps/api after migrations:

    uv run python scripts/e2e_synthetic_operation.py
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from app.core.db import SessionLocal, engine
from app.models import (
    AuthorizedTarget,
    Organization,
    OrganizationMembership,
    TargetScope,
    User,
)
from app.models.operation import Operation, OperationEvent
from app.services.operations import append_event
from app.services.worker_runtime import process_one_operation


def _ensure_schema() -> None:
    from sqlalchemy import inspect

    from app.core.db import Base
    import app.models  # noqa: F401

    if "operations" not in inspect(engine).get_table_names():
        Base.metadata.create_all(bind=engine)


def main() -> None:
    _ensure_schema()
    db = SessionLocal()
    try:
        suffix = uuid.uuid4().hex[:8]
        org = Organization(clerk_org_id=f"org_e2e_{suffix}", name=f"E2E Org {suffix}")
        user = User(
            clerk_user_id=f"user_e2e_{suffix}",
            email=f"e2e-{suffix}@example.com",
            name="E2E User",
        )
        db.add_all([org, user])
        db.flush()
        db.add(
            OrganizationMembership(
                organization_id=org.id,
                user_id=user.id,
                role="org:admin",
            )
        )
        target = AuthorizedTarget(
            organization_id=org.id,
            created_by_user_id=user.id,
            domain=f"e2e-{suffix}.example",
            status="verified",
        )
        db.add(target)
        db.flush()
        db.add(
            TargetScope(
                target_id=target.id,
                root_domain=target.domain,
                include_subdomains=False,
                exclusions=[],
            )
        )
        operation = Operation(
            organization_id=org.id,
            target_id=target.id,
            created_by_user_id=user.id,
            status="queued",
        )
        db.add(operation)
        db.flush()
        append_event(
            db,
            operation,
            event_type="operation.created",
            summary="Scout operation queued.",
            metadata={"status": "queued", "domain": target.domain},
        )
        db.commit()
        operation_id = operation.id
        print(f"created queued operation {operation_id}")
    finally:
        db.close()

    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    result = process_one_operation(factory, stage_delay_seconds=0.05)
    if result is None:
        raise SystemExit("worker did not claim the operation")
    print(f"worker finished operation {result.id} status={result.status}")

    db = SessionLocal()
    try:
        events = db.scalars(
            select(OperationEvent)
            .where(OperationEvent.operation_id == operation_id)
            .order_by(OperationEvent.sequence.asc())
        ).all()
        for event in events:
            print(f"#{event.sequence} {event.event_type}: {event.summary}")
        op = db.get(Operation, operation_id)
        assert op is not None
        if op.status != "completed":
            raise SystemExit(f"expected completed, got {op.status}")
        print("e2e synthetic operation: PASS")
    finally:
        db.close()


if __name__ == "__main__":
    main()
