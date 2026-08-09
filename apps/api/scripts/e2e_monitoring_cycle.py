"""Synthetic monitoring cycle (no public domains).

monitoring due → scheduler creates operation → worker processes → next_run_at updates
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

# Ensure apps/api is on path when run as script.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.db import engine
from app.models.monitoring import MonitoringConfiguration
from app.models.operation import Operation
from app.models.organization import Organization, OrganizationMembership
from app.models.target import AuthorizedTarget, TargetScope
from app.models.user import User
from app.services.discovery.runner import FakeDiscoveryTools, ProbeResult
from app.services.scheduler_runtime import process_one_scheduled_monitoring
from app.services.worker_runtime import process_one_operation


def main() -> None:
    SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    db: Session = SessionLocal()
    domain = f"e2e-mon-{uuid4().hex[:8]}.example"
    try:
        org = Organization(clerk_org_id=f"org_{uuid4().hex}", name="E2E Monitoring Org")
        user = User(
            clerk_user_id=f"user_{uuid4().hex}",
            email=f"{uuid4().hex[:8]}@example.test",
            name="E2E",
        )
        db.add_all([org, user])
        db.flush()
        db.add(
            OrganizationMembership(
                user_id=user.id,
                organization_id=org.id,
                role="org:admin",
            )
        )
        target = AuthorizedTarget(
            organization_id=org.id,
            created_by_user_id=user.id,
            domain=domain,
            status="verified",
            verified_at=datetime.now(timezone.utc),
        )
        db.add(target)
        db.flush()
        db.add(
            TargetScope(
                target_id=target.id,
                root_domain=domain,
                include_subdomains=True,
                exclusions=[],
            )
        )
        now = datetime.now(timezone.utc)
        config = MonitoringConfiguration(
            organization_id=org.id,
            target_id=target.id,
            enabled=True,
            frequency="daily",
            next_run_at=now - timedelta(seconds=1),
            updated_by_user_id=user.id,
        )
        db.add(config)
        db.commit()
        target_id = target.id
        config_id = config.id
        next_before = config.next_run_at
    finally:
        db.close()

    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    scheduled = process_one_scheduled_monitoring(factory)
    assert scheduled is not None, "scheduler did not create operation"
    assert scheduled.source == "scheduled"
    assert scheduled.status == "queued"
    print(f"scheduled operation={scheduled.id} source={scheduled.source}")

    tools = FakeDiscoveryTools(
        hosts_by_domain={domain: [domain]},
        probes_by_host={
            domain: ProbeResult(url=f"https://{domain}", status_code=200, title="E2E")
        },
    )
    result = process_one_operation(factory, tools=tools)
    assert result is not None
    assert result.status == "completed"
    assert result.id == scheduled.id
    print(f"worker completed operation={result.id}")

    db = factory()
    try:
        config = db.get(MonitoringConfiguration, config_id)
        assert config is not None
        assert config.last_run_at is not None
        assert config.next_run_at is not None
        assert config.next_run_at > next_before
        op = db.get(Operation, scheduled.id)
        assert op is not None and op.source == "scheduled"
        print(
            f"monitoring last_run_at={config.last_run_at.isoformat()} "
            f"next_run_at={config.next_run_at.isoformat()}"
        )
        print("PASS e2e monitoring cycle")
    finally:
        db.close()


if __name__ == "__main__":
    main()
