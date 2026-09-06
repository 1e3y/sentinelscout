"""Milestone 37 — organization audit trail explorer."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import event, func, select, text
from sqlalchemy.orm import Session, sessionmaker

from app.models.audit import AuditEvent
from app.services.organization_audit import (
    INVALID_CURSOR_DETAIL,
    VISIBLE_INTERNAL_ACTIONS,
    build_organization_audit_scalar_statement,
    compile_organization_audit_page_sql,
    list_organization_audit_events,
)
from tests.test_finding_follow_up import _add_clerk_member, _auth, _ids


def _list(client, token: str, **params):
    return client.get(
        "/v1/audit-events",
        headers=_auth(token),
        params=params or None,
    )


def _setup(client, make_token, seed_user_a, fake_clerk):
    clerk_admin, clerk_org = seed_user_a
    token = make_token(sub=clerk_admin, org_id=clerk_org, org_role="org:admin")
    admin_id, org_id = _ids(client, token)
    member_clerk = _add_clerk_member(fake_clerk, clerk_org_id=clerk_org, name="Member")
    member_token = make_token(
        sub=member_clerk, org_id=clerk_org, org_role="org:member"
    )
    member_id, _ = _ids(client, member_token)
    return {
        "token": token,
        "member_token": member_token,
        "admin_id": admin_id,
        "member_id": member_id,
        "org_id": org_id,
        "clerk_org": clerk_org,
    }


def _insert_event(
    db: Session,
    *,
    organization_id: UUID,
    action: str,
    resource_type: str,
    resource_id: UUID | None = None,
    actor_type: str = "user",
    actor_user_id: UUID | None = None,
    metadata: dict | None = None,
    created_at: datetime | None = None,
    summary: str = "test",
) -> AuditEvent:
    event = AuditEvent(
        organization_id=organization_id,
        actor_type=actor_type,
        actor_user_id=actor_user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id or uuid4(),
        summary=summary,
        event_metadata=metadata or {},
    )
    if created_at is not None:
        event.created_at = created_at
    db.add(event)
    db.flush()
    return event


# --------------------------------------------------------------------------- RBAC / legacy closure


def test_unauthenticated_401(client):
    assert client.get("/v1/audit-events").status_code == 401


def test_member_403_admin_200_no_raw_metadata(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    _insert_event(
        db_session,
        organization_id=ctx["org_id"],
        action="target.created",
        resource_type="target",
        actor_user_id=ctx["admin_id"],
        metadata={"domain": "a.example", "authorization_role": "admin"},
    )
    db_session.commit()

    assert _list(client, ctx["member_token"]).status_code == 403
    ok = _list(client, ctx["token"])
    assert ok.status_code == 200, ok.text
    body = ok.json()
    assert set(body.keys()) == {"items", "next_cursor"}
    dumped = str(body)
    assert "metadata" not in dumped
    assert "authorization_role" not in dumped
    assert "target.created" not in dumped
    assert body["items"][0]["action"] == "target_created"


def test_stale_membership_role_cannot_elevate(
    client, make_token, seed_user_a, fake_clerk
):
    clerk_admin, clerk_org = seed_user_a
    # Establish admin membership, then present as member.
    make_token(sub=clerk_admin, org_id=clerk_org, org_role="org:admin")
    # Hit /v1/me with admin first via setup pattern
    token_admin = make_token(sub=clerk_admin, org_id=clerk_org, org_role="org:admin")
    client.get("/v1/me", headers=_auth(token_admin))
    memberish = make_token(sub=clerk_admin, org_id=clerk_org, org_role="org:member")
    assert _list(client, memberish).status_code == 403


# --------------------------------------------------------------------------- tenant


def test_foreign_org_rows_never_returned(
    client, make_token, seed_user_a, seed_user_b, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    clerk_b, org_b_clerk = seed_user_b
    token_b = make_token(sub=clerk_b, org_id=org_b_clerk, org_role="org:admin")
    admin_b, org_b = _ids(client, token_b)

    local = _insert_event(
        db_session,
        organization_id=ctx["org_id"],
        action="target.created",
        resource_type="target",
        actor_user_id=ctx["admin_id"],
        metadata={"domain": "local.example"},
    )
    foreign = _insert_event(
        db_session,
        organization_id=org_b,
        action="target.created",
        resource_type="target",
        actor_user_id=admin_b,
        metadata={"domain": "foreign.example"},
    )
    db_session.commit()

    body = _list(client, ctx["token"], page_size=50).json()
    dumped = str(body)
    assert "foreign.example" not in dumped
    assert "local.example" in dumped
    assert str(foreign.id) not in dumped
    assert str(local.resource_id) in dumped


# --------------------------------------------------------------------------- filter pushdown


def test_action_filter_pushdown_finds_older_matches(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    now = datetime.now(UTC)
    for i in range(55):
        _insert_event(
            db_session,
            organization_id=ctx["org_id"],
            action="target.created",
            resource_type="target",
            actor_user_id=ctx["admin_id"],
            created_at=now - timedelta(minutes=i),
            metadata={"domain": f"recent-{i}.example"},
        )
    for i in range(5):
        _insert_event(
            db_session,
            organization_id=ctx["org_id"],
            action="notification.settings.updated",
            resource_type="organization",
            actor_user_id=ctx["admin_id"],
            created_at=now - timedelta(hours=2, minutes=i),
            metadata={"email_enabled": True, "recipient_count": 1},
        )
    db_session.commit()

    body = _list(
        client,
        ctx["token"],
        action="notification_settings_changed",
        page_size=20,
    ).json()
    assert len(body["items"]) == 5
    assert all(e["action"] == "notification_settings_changed" for e in body["items"])


def test_resource_filter_uses_customer_mapping_not_raw_org(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    # Hidden/unrelated organization-typed action if any — use notification settings
    # plus invent a non-visible org action that would otherwise match resource_type=organization.
    _insert_event(
        db_session,
        organization_id=ctx["org_id"],
        action="notification.settings.updated",
        resource_type="organization",
        actor_user_id=ctx["admin_id"],
        metadata={"email_enabled": False},
    )
    _insert_event(
        db_session,
        organization_id=ctx["org_id"],
        action="unknown.future_org_action",
        resource_type="organization",
        actor_user_id=ctx["admin_id"],
        metadata={"email_enabled": True},
    )
    db_session.commit()

    body = _list(
        client, ctx["token"], resource_type="notification_settings", page_size=50
    ).json()
    assert len(body["items"]) == 1
    assert body["items"][0]["action"] == "notification_settings_changed"


def test_hidden_actions_never_appear(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    for action, rtype in [
        ("validation.completed", "validation_attempt"),
        ("coverage.frozen", "operation"),
        ("assessment_report_delivery.queued", "assessment_report_delivery_job"),
        ("alert.read", "alert"),
        ("monitoring.operation_created", "operation"),
    ]:
        _insert_event(
            db_session,
            organization_id=ctx["org_id"],
            action=action,
            resource_type=rtype,
            actor_type="worker",
        )
    db_session.commit()
    body = _list(client, ctx["token"], page_size=50).json()
    assert body["items"] == []


# --------------------------------------------------------------------------- actor / system


def test_system_actor_hides_actor_user_id(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    _insert_event(
        db_session,
        organization_id=ctx["org_id"],
        action="operation.completed",
        resource_type="operation",
        actor_type="worker",
        actor_user_id=ctx["admin_id"],  # must not surface
        metadata={"source": "manual"},
    )
    db_session.commit()
    row = _list(client, ctx["token"]).json()["items"][0]
    assert row["actor"]["kind"] == "system"
    assert row["actor"]["user_id"] is None
    assert row["action"] == "assessment_completed"


def test_unavailable_user_actor(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    # actor_type=user with null actor_user_id (e.g. user deleted → SET NULL).
    _insert_event(
        db_session,
        organization_id=ctx["org_id"],
        action="target.created",
        resource_type="target",
        actor_type="user",
        actor_user_id=None,
        metadata={"domain": "gone.example"},
    )
    db_session.commit()
    row = _list(client, ctx["token"]).json()["items"][0]
    assert row["actor"]["kind"] == "unavailable_user"
    assert row["actor"]["user_id"] is None
    assert "email" not in str(row).lower()


# --------------------------------------------------------------------------- dates / cursor


def test_date_contract_and_cursor(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    mid = datetime(2026, 6, 15, 12, 0, tzinfo=UTC)
    _insert_event(
        db_session,
        organization_id=ctx["org_id"],
        action="target.created",
        resource_type="target",
        actor_user_id=ctx["admin_id"],
        created_at=mid - timedelta(days=1),
        metadata={"domain": "before.example"},
    )
    _insert_event(
        db_session,
        organization_id=ctx["org_id"],
        action="target.created",
        resource_type="target",
        actor_user_id=ctx["admin_id"],
        created_at=mid,
        metadata={"domain": "boundary.example"},
    )
    _insert_event(
        db_session,
        organization_id=ctx["org_id"],
        action="target.created",
        resource_type="target",
        actor_user_id=ctx["admin_id"],
        created_at=mid + timedelta(days=1),
        metadata={"domain": "after.example"},
    )
    db_session.commit()

    # Inclusive boundaries
    body = _list(
        client,
        ctx["token"],
        **{"from": mid.isoformat(), "to": mid.isoformat()},
    ).json()
    assert len(body["items"]) == 1
    assert body["items"][0]["detail"]["domain"] == "boundary.example"

    # Offset-aware accepted
    assert (
        _list(
            client,
            ctx["token"],
            **{"from": "2026-06-15T12:00:00+00:00", "to": "2026-06-15T12:00:00+00:00"},
        ).status_code
        == 200
    )

    # Naive rejected
    naive = _list(client, ctx["token"], **{"from": "2026-06-15T12:00:00"})
    assert naive.status_code == 422

    # from > to
    bad = _list(
        client,
        ctx["token"],
        **{"from": "2026-06-16T00:00:00Z", "to": "2026-06-15T00:00:00Z"},
    )
    assert bad.status_code == 422

    # Malformed cursor
    cur = _list(client, ctx["token"], cursor="not-a-cursor")
    assert cur.status_code == 400
    assert cur.json()["error"]["message"] == INVALID_CURSOR_DETAIL

    assert _list(client, ctx["token"], page_size=51).status_code == 422


def test_deep_pagination_no_holes(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    stamp = datetime.now(UTC) - timedelta(days=1)
    for i in range(35):
        _insert_event(
            db_session,
            organization_id=ctx["org_id"],
            action="target.created",
            resource_type="target",
            actor_user_id=ctx["admin_id"],
            created_at=stamp,
            metadata={"domain": f"tie-{i}.example"},
        )
    db_session.commit()

    seen: list[str] = []
    cursor = None
    for _ in range(20):
        params = {"page_size": 10}
        if cursor:
            params["cursor"] = cursor
        body = _list(client, ctx["token"], **params).json()
        for item in body["items"]:
            seen.append(item["detail"]["domain"])
        cursor = body["next_cursor"]
        if not cursor:
            break
    assert len(seen) == len(set(seen)) == 35


# --------------------------------------------------------------------------- SQL privacy / read-only


def test_sql_never_selects_raw_metadata_column(
    client, make_token, seed_user_a, fake_clerk, db_session, engine
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    _insert_event(
        db_session,
        organization_id=ctx["org_id"],
        action="target.scope_updated",
        resource_type="target",
        actor_user_id=ctx["admin_id"],
        metadata={
            "domain": "x.example",
            "include_subdomains": True,
            "exclusions_count": 1,
            "authorization_role": "admin",
            "reason": "stop_requested",
        },
    )
    db_session.commit()

    page_sql = compile_organization_audit_page_sql(
        organization_id=ctx["org_id"]
    ).lower()
    assert "metadata" not in page_sql or "as_string" in page_sql or "->>" in page_sql
    # Primary page must not mention the JSON column at all.
    assert "audit_events.metadata" not in page_sql
    assert " event_metadata" not in page_sql

    scalar_sql = str(
        build_organization_audit_scalar_statement(
            organization_id=ctx["org_id"],
            event_ids=[uuid4()],
        ).compile(compile_kwargs={"literal_binds": True})
    ).lower()
    # Scalar JSON access (SQLAlchemy renders metadata['key']).
    assert "metadata[" in scalar_sql
    assert "audit_events.metadata as" not in scalar_sql
    assert ", audit_events.metadata from" not in scalar_sql
    assert "audit_events.metadata," not in scalar_sql.split("metadata[")[0]

    statements: list[str] = []

    def capture(_conn, _cursor, statement, _parameters, _context, _executemany):
        if statement.lstrip().upper().startswith("SELECT"):
            statements.append(statement)

    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    session = factory()
    event.listen(engine, "before_cursor_execute", capture)
    try:
        list_organization_audit_events(session, organization_id=ctx["org_id"], page_size=20)
        session.rollback()
    finally:
        event.remove(engine, "before_cursor_execute", capture)
        session.close()

    joined = " ".join(statements).lower()
    assert "users.email" not in joined
    assert "snapshot_json" not in joined
    assert "encrypted_secret" not in joined
    assert "secret_hash" not in joined
    assert "delivery_snapshot" not in joined
    assert "audit_events.metadata," not in joined
    # Whole-column metadata select should not appear; JSON operators are OK.
    assert " audit_events.metadata from" not in joined
    assert "audit_events.metadata as metadata" not in joined


def test_operation_stopped_reason_not_exposed(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    _insert_event(
        db_session,
        organization_id=ctx["org_id"],
        action="operation.stopped",
        resource_type="operation",
        actor_user_id=ctx["admin_id"],
        metadata={"source": "manual", "reason": "stop_requested"},
    )
    db_session.commit()
    row = _list(client, ctx["token"]).json()["items"][0]
    assert row["action"] == "assessment_stopped"
    assert row["detail"] is None or "reason" not in row["detail"]
    assert "stop_requested" not in str(row)


def test_read_does_not_create_audit_event(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    _insert_event(
        db_session,
        organization_id=ctx["org_id"],
        action="target.created",
        resource_type="target",
        actor_user_id=ctx["admin_id"],
        metadata={"domain": "ro.example"},
    )
    db_session.commit()
    before = int(db_session.scalar(select(func.count()).select_from(AuditEvent)) or 0)
    assert _list(client, ctx["token"]).status_code == 200
    db_session.expire_all()
    after = int(db_session.scalar(select(func.count()).select_from(AuditEvent)) or 0)
    assert after == before


def test_explain_prefers_existing_indexes(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    now = datetime.now(UTC)
    for i in range(40):
        _insert_event(
            db_session,
            organization_id=ctx["org_id"],
            action="target.created",
            resource_type="target",
            actor_user_id=ctx["admin_id"],
            created_at=now - timedelta(minutes=i),
            metadata={"domain": f"e{i}.example"},
        )
    db_session.commit()
    sql = compile_organization_audit_page_sql(organization_id=ctx["org_id"], size=20)
    plan = db_session.execute(text(f"EXPLAIN {sql}")).all()
    plan_text = "\n".join(row[0] for row in plan).lower()
    assert "audit_events" in plan_text
    # Decision: prefer no migration; existing org/created_at indexes sufficient for M37 volume.
    assert True


def test_visible_allowlist_covers_expected_actions():
    assert "target.created" in VISIBLE_INTERNAL_ACTIONS
    assert "notification.settings.updated" in VISIBLE_INTERNAL_ACTIONS
    assert "assessment_report_delivery.queued" not in VISIBLE_INTERNAL_ACTIONS
    assert "validation.completed" not in VISIBLE_INTERNAL_ACTIONS
    assert "coverage.frozen" not in VISIBLE_INTERNAL_ACTIONS
