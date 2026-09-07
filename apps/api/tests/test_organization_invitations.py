"""Milestone 40 — organization member invitations."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID, uuid4

from sqlalchemy import func, select

from app.core.config import get_settings, reset_settings_cache
from app.models.audit import AuditEvent
from app.models.organization import OrganizationMembership
from app.models.user import User
from app.services.clerk import ClerkOrganizationInvitationRaw
from app.services.organization_invitations import (
    ALREADY_MEMBER_DETAIL,
    CREATE_UNAVAILABLE_DETAIL,
    DUPLICATE_PENDING_DETAIL,
    LIST_UNAVAILABLE_DETAIL,
    canonicalize_invitation_email,
    recipient_hint,
)
from tests.test_finding_follow_up import _auth, _ids
from tests.test_organization_access import _assert_no_secrets, _setup


def _invite(client, token: str, email: str):
    return client.post(
        "/v1/organization-invitations",
        headers=_auth(token),
        json={"email": email},
    )


def _list(client, token: str, **params):
    return client.get(
        "/v1/organization-invitations",
        headers=_auth(token),
        params=params or None,
    )


def _plant_pending(
    fake_clerk,
    *,
    clerk_org: str,
    email: str,
    role: str = "org:member",
    inviter: str = "user_planter",
    status: str = "pending",
    created_at_ms: int | None = None,
):
    now_ms = created_at_ms
    if now_ms is None:
        now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
    fake_clerk.invitations.setdefault(clerk_org, []).append(
        ClerkOrganizationInvitationRaw(
            provider_invitation_id=f"inv_plant_{uuid4().hex[:8]}",
            email_address=email,
            external_role=role,
            status=status,
            inviter_user_id=inviter,
            created_at_ms=now_ms,
            expires_at_ms=now_ms + 86_400_000,
        )
    )


# ---------------------------------------------------------------- canonicalization


def test_email_canonicalization_preserves_local_part_case():
    assert canonicalize_invitation_email("  Jane.Doe@Example.COM ") == "Jane.Doe@example.com"
    assert recipient_hint("Jane.Doe@example.com") == "J***@example.com"


def test_create_rate_limit_default_vs_window():
    settings = get_settings()
    assert settings.rate_limit_window_seconds == 3600
    assert settings.rate_limit_organization_invitation_create == 10
    # 10 / hour is below Clerk's documented 250 / hour instance quota.


# ---------------------------------------------------------------- RBAC / auth order


def test_unauthenticated_zero_provider(client, fake_clerk):
    before_list = fake_clerk.list_invitations_calls
    before_create = fake_clerk.create_invitation_calls
    assert client.get("/v1/organization-invitations").status_code == 401
    assert (
        client.post(
            "/v1/organization-invitations", json={"email": "a@example.com"}
        ).status_code
        == 401
    )
    assert fake_clerk.list_invitations_calls == before_list
    assert fake_clerk.create_invitation_calls == before_create


def test_member_403_zero_provider(client, make_token, seed_user_a, fake_clerk):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    before_list = fake_clerk.list_invitations_calls
    before_create = fake_clerk.create_invitation_calls
    assert _list(client, ctx["member_token"]).status_code == 403
    assert _invite(client, ctx["member_token"], "x@example.com").status_code == 403
    assert fake_clerk.list_invitations_calls == before_list
    assert fake_clerk.create_invitation_calls == before_create


# ---------------------------------------------------------------- create happy path


def test_admin_invites_member_only(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    users_before = db_session.scalar(select(func.count()).select_from(User))
    memberships_before = db_session.scalar(
        select(func.count()).select_from(OrganizationMembership)
    )
    creates_before = fake_clerk.create_invitation_calls
    lists_before = fake_clerk.list_invitations_calls

    response = _invite(client, ctx["token"], "  New.Person@Example.COM ")
    assert response.status_code == 201, response.text
    body = response.json()
    _assert_no_secrets(body)
    assert body["status"] == "pending"
    assert body["role"] == "member"
    assert body["role_state"] == "recognized"
    assert body["recipient_hint"] == "N***@example.com"
    assert "email" not in body
    assert body["local_recording_state"] == "complete"
    assert "@" in body["recipient_hint"]
    assert "New.Person@Example.COM" not in response.text
    assert isinstance(body["invitation_ref"], str) and body["invitation_ref"].startswith(
        "v1."
    )

    # preflight list + create
    assert fake_clerk.list_invitations_calls == lists_before + 1
    assert fake_clerk.create_invitation_calls == creates_before + 1
    stored = fake_clerk.invitations[ctx["clerk_org"]][-1]
    assert stored.email_address == "New.Person@example.com"
    assert stored.external_role == "org:member"
    assert stored.inviter_user_id == ctx["clerk_admin"]
    assert stored.provider_invitation_id not in body["invitation_ref"]
    assert str(ctx["org_id"]) not in body["invitation_ref"]
    assert stored.provider_invitation_id not in response.text

    assert db_session.scalar(select(func.count()).select_from(User)) == users_before
    assert (
        db_session.scalar(select(func.count()).select_from(OrganizationMembership))
        == memberships_before
    )

    events = db_session.scalars(
        select(AuditEvent).where(
            AuditEvent.organization_id == ctx["org_id"],
            AuditEvent.action == "organization.invitation_created",
        )
    ).all()
    assert len(events) == 1
    assert events[0].event_metadata == {"role": "member"}
    assert "email" not in str(events[0].event_metadata).lower()
    assert "hint" not in str(events[0].event_metadata).lower()


def test_client_role_field_rejected(client, make_token, seed_user_a, fake_clerk):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    response = client.post(
        "/v1/organization-invitations",
        headers=_auth(ctx["token"]),
        json={"email": "a@example.com", "role": "admin"},
    )
    assert response.status_code == 422
    assert fake_clerk.create_invitation_calls == 0


def test_invalid_emails_422(client, make_token, seed_user_a, fake_clerk):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    for bad in ("not-an-email", "a,b@example.com", "a\n@example.com", "a\r@example.com"):
        response = _invite(client, ctx["token"], bad)
        assert response.status_code == 422, bad
    assert fake_clerk.create_invitation_calls == 0


# ---------------------------------------------------------------- conflicts


def test_preflight_duplicate_pending_409_zero_create(
    client, make_token, seed_user_a, fake_clerk
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    email = "pending@example.com"
    _plant_pending(fake_clerk, clerk_org=ctx["clerk_org"], email=email)
    before = fake_clerk.create_invitation_calls
    response = _invite(client, ctx["token"], email)
    assert response.status_code == 409
    assert response.json()["error"]["message"] == DUPLICATE_PENDING_DETAIL
    assert fake_clerk.create_invitation_calls == before


def test_provider_duplicate_race_409(client, make_token, seed_user_a, fake_clerk):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    fake_clerk.create_invitation_mode = "duplicate"
    response = _invite(client, ctx["token"], "race@example.com")
    assert response.status_code == 409
    assert response.json()["error"]["message"] == DUPLICATE_PENDING_DETAIL
    assert fake_clerk.create_invitation_calls == 1


def test_already_member_409(client, make_token, seed_user_a, fake_clerk):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    # Member email from _setup helpers is "{clerk_id}@example.com"
    member_email = fake_clerk.users[ctx["member_clerk"]].email
    response = _invite(client, ctx["token"], member_email)
    assert response.status_code == 409
    assert response.json()["error"]["message"] == ALREADY_MEMBER_DETAIL


def test_unexpected_provider_error_503(client, make_token, seed_user_a, fake_clerk):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    fake_clerk.create_invitation_mode = "unavailable"
    response = _invite(client, ctx["token"], "x@example.com")
    assert response.status_code == 503
    assert response.json()["error"]["message"] == CREATE_UNAVAILABLE_DETAIL


# ---------------------------------------------------------------- ambiguous causality


def test_ambiguous_correlated_success(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    fake_clerk.create_invitation_mode = "ambiguous_applied"
    response = _invite(client, ctx["token"], "ok@example.com")
    assert response.status_code == 201, response.text
    assert fake_clerk.create_invitation_calls == 1
    # preflight + reconcile
    assert fake_clerk.list_invitations_calls >= 2
    assert (
        db_session.scalar(
            select(func.count())
            .select_from(AuditEvent)
            .where(AuditEvent.action == "organization.invitation_created")
        )
        == 1
    )


def test_ambiguous_other_inviter_not_attributed(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    fake_clerk.create_invitation_mode = "ambiguous_applied_other_inviter"
    response = _invite(client, ctx["token"], "other@example.com")
    assert response.status_code == 503
    assert response.json()["error"]["message"] == CREATE_UNAVAILABLE_DETAIL
    assert fake_clerk.create_invitation_calls == 1
    assert (
        db_session.scalar(
            select(func.count())
            .select_from(AuditEvent)
            .where(AuditEvent.action == "organization.invitation_created")
        )
        == 0
    )


def test_ambiguous_stale_pending_not_attributed(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    fake_clerk.create_invitation_mode = "ambiguous_applied_stale"
    response = _invite(client, ctx["token"], "stale@example.com")
    assert response.status_code == 503
    assert fake_clerk.create_invitation_calls == 1
    assert (
        db_session.scalar(
            select(func.count())
            .select_from(AuditEvent)
            .where(AuditEvent.action == "organization.invitation_created")
        )
        == 0
    )


def test_ambiguous_absent_503(client, make_token, seed_user_a, fake_clerk, db_session):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    fake_clerk.create_invitation_mode = "ambiguous"
    response = _invite(client, ctx["token"], "gone@example.com")
    assert response.status_code == 503
    assert fake_clerk.create_invitation_calls == 1
    assert (
        db_session.scalar(
            select(func.count())
            .select_from(AuditEvent)
            .where(AuditEvent.action == "organization.invitation_created")
        )
        == 0
    )


def test_audit_degraded_no_second_create(
    client, make_token, seed_user_a, fake_clerk, monkeypatch
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)

    def boom(*_a, **_k):
        raise RuntimeError("audit down")

    monkeypatch.setattr(
        "app.services.organization_invitations.record_audit",
        boom,
    )
    before = fake_clerk.create_invitation_calls
    response = _invite(client, ctx["token"], "degraded@example.com")
    assert response.status_code == 201
    assert response.json()["local_recording_state"] == "audit_degraded"
    assert fake_clerk.create_invitation_calls == before + 1


# ---------------------------------------------------------------- list role truth / integrity


def test_list_role_truth_and_unknown(
    client, make_token, seed_user_a, fake_clerk
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    _plant_pending(
        fake_clerk,
        clerk_org=ctx["clerk_org"],
        email="member-role@example.com",
        role="org:member",
    )
    _plant_pending(
        fake_clerk,
        clerk_org=ctx["clerk_org"],
        email="admin-role@example.com",
        role="org:admin",
    )
    _plant_pending(
        fake_clerk,
        clerk_org=ctx["clerk_org"],
        email="billing-role@example.com",
        role="org:billing",
    )
    _plant_pending(
        fake_clerk,
        clerk_org=ctx["clerk_org"],
        email="accepted@example.com",
        role="org:member",
        status="accepted",
    )

    response = _list(client, ctx["token"])
    assert response.status_code == 200, response.text
    body = response.json()
    _assert_no_secrets(body)
    by_hint = {item["recipient_hint"]: item for item in body["items"]}
    assert by_hint["m***@example.com"]["role"] == "member"
    assert by_hint["m***@example.com"]["role_state"] == "recognized"
    assert by_hint["a***@example.com"]["role"] == "admin"
    assert by_hint["a***@example.com"]["role_state"] == "recognized"
    assert by_hint["b***@example.com"]["role"] is None
    assert by_hint["b***@example.com"]["role_state"] == "unrecognized"
    assert "accepted@example.com" not in response.text
    assert all(item["status"] == "pending" for item in body["items"])
    assert all(
        isinstance(item["invitation_ref"], str) and item["invitation_ref"].startswith("v1.")
        for item in body["items"]
    )
    # accepted filtered by provider status=pending
    assert len(body["items"]) == 3


def test_create_missing_ref_key_503_zero_provider(
    client, make_token, seed_user_a, fake_clerk, monkeypatch
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    monkeypatch.setenv("ORGANIZATION_INVITATION_REF_SECRET_KEY", "")
    reset_settings_cache()
    before_list = fake_clerk.list_invitations_calls
    before_create = fake_clerk.create_invitation_calls
    response = _invite(client, ctx["token"], "missing-key@example.com")
    assert response.status_code == 503
    assert response.json()["error"]["message"] == CREATE_UNAVAILABLE_DETAIL
    assert fake_clerk.list_invitations_calls == before_list
    assert fake_clerk.create_invitation_calls == before_create
    reset_settings_cache()


def test_create_malformed_ref_key_503_zero_provider(
    client, make_token, seed_user_a, fake_clerk, monkeypatch
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    monkeypatch.setenv("ORGANIZATION_INVITATION_REF_SECRET_KEY", "not-hex-key")
    reset_settings_cache()
    before_list = fake_clerk.list_invitations_calls
    before_create = fake_clerk.create_invitation_calls
    response = _invite(client, ctx["token"], "bad-key@example.com")
    assert response.status_code == 503
    assert response.json()["error"]["message"] == CREATE_UNAVAILABLE_DETAIL
    assert fake_clerk.list_invitations_calls == before_list
    assert fake_clerk.create_invitation_calls == before_create
    reset_settings_cache()


def test_list_missing_ref_key_503_zero_provider(
    client, make_token, seed_user_a, fake_clerk, monkeypatch
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    _plant_pending(
        fake_clerk, clerk_org=ctx["clerk_org"], email="listed@example.com", role="org:member"
    )
    monkeypatch.setenv("ORGANIZATION_INVITATION_REF_SECRET_KEY", "")
    reset_settings_cache()
    before_list = fake_clerk.list_invitations_calls
    response = _list(client, ctx["token"])
    assert response.status_code == 503
    assert response.json()["error"]["message"] == LIST_UNAVAILABLE_DETAIL
    assert fake_clerk.list_invitations_calls == before_list
    reset_settings_cache()


def test_list_contradictory_status_503(client, make_token, seed_user_a, fake_clerk):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    _plant_pending(
        fake_clerk, clerk_org=ctx["clerk_org"], email="bad@example.com", role="org:member"
    )
    fake_clerk.list_invitations_corrupt = "non_pending"
    response = _list(client, ctx["token"])
    assert response.status_code == 503
    assert response.json()["error"]["message"] == LIST_UNAVAILABLE_DETAIL


def test_list_malformed_row_503(client, make_token, seed_user_a, fake_clerk):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    _plant_pending(
        fake_clerk, clerk_org=ctx["clerk_org"], email="bad2@example.com", role="org:member"
    )
    fake_clerk.list_invitations_corrupt = "missing_created_at"
    response = _list(client, ctx["token"])
    assert response.status_code == 503
    assert response.json()["error"]["message"] == LIST_UNAVAILABLE_DETAIL


def test_list_read_only_no_audit(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    before = db_session.scalar(select(func.count()).select_from(AuditEvent))
    users_before = db_session.scalar(select(func.count()).select_from(User))
    assert _list(client, ctx["token"]).status_code == 200
    assert db_session.scalar(select(func.count()).select_from(AuditEvent)) == before
    assert db_session.scalar(select(func.count()).select_from(User)) == users_before
    assert fake_clerk.create_invitation_calls == 0


def test_list_malformed_cursor_and_page_size(
    client, make_token, seed_user_a, fake_clerk
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    assert _list(client, ctx["token"], cursor="%%%").status_code == 400
    assert _list(client, ctx["token"], page_size=101).status_code == 422


def test_create_rate_limit_blocks_provider(
    client, make_token, seed_user_a, fake_clerk, monkeypatch
):
    monkeypatch.setenv("RATE_LIMIT_ORGANIZATION_INVITATION_CREATE", "1")
    reset_settings_cache()
    try:
        ctx = _setup(client, make_token, seed_user_a, fake_clerk)
        assert _invite(client, ctx["token"], "one@example.com").status_code == 201
        creates = fake_clerk.create_invitation_calls
        lists = fake_clerk.list_invitations_calls
        second = _invite(client, ctx["token"], "two@example.com")
        assert second.status_code == 429
        assert fake_clerk.create_invitation_calls == creates
        assert fake_clerk.list_invitations_calls == lists
    finally:
        monkeypatch.setenv("RATE_LIMIT_ORGANIZATION_INVITATION_CREATE", "10")
        reset_settings_cache()


def test_m37_projects_invitation_created(client, make_token, seed_user_a, fake_clerk):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    assert _invite(client, ctx["token"], "audit@example.com").status_code == 201
    audit = client.get("/v1/audit-events", headers=_auth(ctx["token"]))
    assert audit.status_code == 200
    actions = {row["action"] for row in audit.json()["items"]}
    assert "organization_invitation_created" in actions
    for row in audit.json()["items"]:
        if row["action"] == "organization_invitation_created":
            assert row["resource"]["kind"] == "organization"
            assert row["detail"]["role"] == "member"
            _assert_no_secrets(row)
            assert "email" not in str(row).lower() or "email_enabled" in str(row).lower()


def test_acceptance_moves_to_membership_view(
    client, make_token, seed_user_a, fake_clerk
):
    """Pending drops when invitation is no longer pending; no local conversion."""
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    assert _invite(client, ctx["token"], "join@example.com").status_code == 201
    listed = _list(client, ctx["token"]).json()
    assert any(item["recipient_hint"] == "j***@example.com" for item in listed["items"])

    # Simulate acceptance: invitation gone; membership appears via Clerk membership map.
    fake_clerk.invitations[ctx["clerk_org"]] = [
        row
        for row in fake_clerk.invitations.get(ctx["clerk_org"], [])
        if row.email_address != "join@example.com"
    ]
    after = _list(client, ctx["token"]).json()
    assert all(item["recipient_hint"] != "j***@example.com" for item in after["items"])
