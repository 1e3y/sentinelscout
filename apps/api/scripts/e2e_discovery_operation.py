"""Local end-to-end discovery check with mocked tools (no public domains).

Run from apps/api after migrations:

    PYTHONPATH=. uv run python scripts/e2e_discovery_operation.py

For a real tool run against a domain you control, use the worker with
subfinder/httpx installed and a verified target in the app UI.
"""

from __future__ import annotations

import uuid

from sqlalchemy import inspect, select
from sqlalchemy.orm import sessionmaker

from app.core.db import Base, SessionLocal, engine
import app.models  # noqa: F401
from app.models import (
    AuthorizedTarget,
    Organization,
    OrganizationMembership,
    TargetScope,
    User,
)
from app.models.asset import Asset, DiscoveryObservation
from app.models.operation import Operation, OperationEvent
from app.services.discovery.runner import FakeDiscoveryTools, ProbeResult
from app.services.operations import append_event
from app.services.worker_runtime import process_one_operation


def _ensure_schema() -> None:
    if "operations" not in inspect(engine).get_table_names():
        Base.metadata.create_all(bind=engine)


def main() -> None:
    _ensure_schema()
    suffix = uuid.uuid4().hex[:8]
    domain = f"local-{suffix}.test"

    db = SessionLocal()
    try:
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
                organization_id=org.id, user_id=user.id, role="org:admin"
            )
        )
        target = AuthorizedTarget(
            organization_id=org.id,
            created_by_user_id=user.id,
            domain=domain,
            status="verified",
        )
        db.add(target)
        db.flush()
        db.add(
            TargetScope(
                target_id=target.id,
                root_domain=domain,
                include_subdomains=True,
                exclusions=[f"dev.{domain}"],
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
            metadata={"status": "queued", "domain": domain},
        )
        db.commit()
        operation_id = operation.id
        print(f"created queued operation {operation_id} for {domain}")
    finally:
        db.close()

    tools = FakeDiscoveryTools(
        hosts_by_domain={
            domain: [domain, f"www.{domain}", f"dev.{domain}", "evil.other.test"]
        },
        probes_by_host={
            domain: ProbeResult(url=f"https://{domain}", status_code=200, title="Root"),
            f"www.{domain}": ProbeResult(
                url=f"https://www.{domain}", status_code=200, title="WWW"
            ),
            f"dev.{domain}": ProbeResult(
                url=f"https://dev.{domain}", status_code=200, title="Dev"
            ),
        },
    )
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    result = process_one_operation(factory, tools=tools)
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

        assets = db.scalars(select(Asset).where(Asset.target_id == result.target_id)).all()
        print(f"assets={len(assets)}")
        for asset in assets:
            print(f"  - {asset.hostname} {asset.url or '(hostname)'} {asset.status_code}")

        observations = db.scalars(
            select(DiscoveryObservation).where(
                DiscoveryObservation.operation_id == operation_id
            )
        ).all()
        print(f"observations={len(observations)}")

        assert result.status == "completed"
        assert any(a.hostname == domain for a in assets)
        assert all(a.hostname != f"dev.{domain}" for a in assets)
        assert all(a.hostname != "evil.other.test" for a in assets)
        print("e2e discovery operation: PASS")
    finally:
        db.close()


if __name__ == "__main__":
    main()
