"""Create an isolated authorized org/target for a benchmark run."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy.orm import Session

from app.models.organization import Organization, OrganizationMembership
from app.models.target import AuthorizedTarget, TargetAuthorization, TargetScope
from app.models.user import User
from app.services.authorization import explicit_org_actor
from app.services.operations import create_operation


def seed_world(
    db: Session,
    *,
    root: str,
    include_subdomains: bool,
    exclusions: list[str],
):
    now = datetime.now(timezone.utc)
    suffix = uuid4().hex[:12]
    user = User(
        clerk_user_id=f"bench_user_{suffix}",
        email=f"bench-{suffix}@example.test",
        name="Benchmark",
    )
    org = Organization(
        clerk_org_id=f"org_bench_{suffix}",
        name=f"Benchmark {suffix}",
    )
    db.add_all([user, org])
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
        domain=root,
        status="verified",
        verified_at=now,
    )
    db.add(target)
    db.flush()
    db.add(
        TargetAuthorization(
            target_id=target.id,
            method="dns_txt",
            token=f"bench-{suffix}",
            txt_name=f"_scout-verify.{root}",
            txt_value=f"scout-verify=bench-{suffix}",
            verified_at=now,
        )
    )
    db.add(
        TargetScope(
            target_id=target.id,
            root_domain=root,
            include_subdomains=include_subdomains,
            exclusions=list(exclusions),
        )
    )
    db.commit()
    db.refresh(user)
    db.refresh(target)
    actor = explicit_org_actor(
        user_id=user.id, organization_id=org.id, normalized_role="admin"
    )
    operation = create_operation(db, actor=actor, target_id=target.id)
    return user, org, target, operation
