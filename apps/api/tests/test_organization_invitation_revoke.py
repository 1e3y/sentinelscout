"""Milestone 41 — pending organization invitation revocation."""

from __future__ import annotations

from base64 import urlsafe_b64decode, urlsafe_b64encode
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

from sqlalchemy import func, select

from app.core.config import get_settings, reset_settings_cache
from app.models.audit import AuditEvent
from app.models.organization import OrganizationMembership
from app.models.user import User
from app.services.clerk import ClerkInvitationMutationView
from app.services.organization_invitation_refs import (
    TOKEN_FORMAT_VERSION,
    InvitationRefCodecError,
    mint_invitation_ref,
    open_invitation_ref,
)
from app.services.organization_invitations import (
    PENDING_NOT_FOUND_DETAIL,
    REVOKE_UNAVAILABLE_DETAIL,
)
from tests.test_finding_follow_up import _auth
from tests.test_organization_access import _assert_no_secrets, _setup
from tests.test_organization_invitations import _invite, _list, _plant_pending


def _revoke(client, token: str, invitation_ref: str, **extra):
    body = {"invitation_ref": invitation_ref, **extra}
    return client.post(
        "/v1/organization-invitations/revoke",
        headers=_auth(token),
        json=body,
    )


def _ref_for_planted(org_id: UUID, fake_clerk, clerk_org: str, email: str) -> str:
    row = next(
        r for r in fake_clerk.invitations[clerk_org] if r.email_address == email
    )
    return mint_invitation_ref(
        organization_id=org_id,
        provider_invitation_id=row.provider_invitation_id,
    )


# ---------------------------------------------------------------- codec confidentiality


def test_invitation_ref_is_confidential_encrypted():
    org_id = uuid4()
    provider_id = "inv_secret_provider_abc"
    token = mint_invitation_ref(
        organization_id=org_id,
        provider_invitation_id=provider_id,
    )
    assert token.startswith(f"{TOKEN_FORMAT_VERSION}.")
    assert str(org_id) not in token
    assert provider_id not in token
    # Base64 blob must not decode to plaintext fields.
    blob = token.split(".", 1)[1]
    padded = blob + ("=" * (-len(blob) % 4))
    packed = urlsafe_b64decode(padded.encode("ascii"))
    assert str(org_id).encode() not in packed
    assert provider_id.encode() not in packed


def test_token_format_v1_no_key_version_config():
    settings = get_settings()
    assert not hasattr(settings, "organization_invitation_ref_secret_key_version")
    token = mint_invitation_ref(
        organization_id=uuid4(),
        provider_invitation_id="inv_x",
    )
    assert token.startswith("v1.")


def test_key_rotation_invalidates_old_refs(monkeypatch):
    org_id = uuid4()
    token = mint_invitation_ref(
        organization_id=org_id,
        provider_invitation_id="inv_rotate",
    )
    monkeypatch.setenv("ORGANIZATION_INVITATION_REF_SECRET_KEY", "cc" * 32)
    reset_settings_cache()
    try:
        open_invitation_ref(token, expected_organization_id=org_id)
        raised = False
    except InvitationRefCodecError:
        raised = True
    assert raised
    fresh = mint_invitation_ref(
        organization_id=org_id,
        provider_invitation_id="inv_rotate",
    )
    payload = open_invitation_ref(fresh, expected_organization_id=org_id)
    assert payload.provider_invitation_id == "inv_rotate"
    monkeypatch.setenv("ORGANIZATION_INVITATION_REF_SECRET_KEY", "bb" * 32)
    reset_settings_cache()


# ---------------------------------------------------------------- route privacy / auth


def test_revoke_route_has_no_ref_in_url(client, make_token, seed_user_a, fake_clerk):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    _plant_pending(
        fake_clerk, clerk_org=ctx["clerk_org"], email="url@example.com", role="org:member"
    )
    ref = _ref_for_planted(ctx["org_id"], fake_clerk, ctx["clerk_org"], "url@example.com")
    response = _revoke(client, ctx["token"], ref)
    assert response.status_code == 200, response.text
    assert response.request.url.path == "/v1/organization-invitations/revoke"
    assert ref not in str(response.request.url)
    assert "invitation_ref" not in str(response.request.url)


def test_revoke_extra_fields_rejected(client, make_token, seed_user_a, fake_clerk):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    before = fake_clerk.get_invitation_calls
    response = _revoke(
        client,
        ctx["token"],
        "v1.abc",
        organization_id=str(ctx["org_id"]),
    )
    assert response.status_code == 422
    assert fake_clerk.get_invitation_calls == before


def test_unauthenticated_revoke_zero_provider(client, fake_clerk):
    before_get = fake_clerk.get_invitation_calls
    before_revoke = fake_clerk.revoke_invitation_calls
    assert (
        client.post(
            "/v1/organization-invitations/revoke",
            json={"invitation_ref": "v1.abc"},
        ).status_code
        == 401
    )
    assert fake_clerk.get_invitation_calls == before_get
    assert fake_clerk.revoke_invitation_calls == before_revoke


def test_member_403_revoke_zero_provider(client, make_token, seed_user_a, fake_clerk):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    before_get = fake_clerk.get_invitation_calls
    before_revoke = fake_clerk.revoke_invitation_calls
    assert _revoke(client, ctx["member_token"], "v1.abc").status_code == 403
    assert fake_clerk.get_invitation_calls == before_get
    assert fake_clerk.revoke_invitation_calls == before_revoke


# ---------------------------------------------------------------- happy path


def test_admin_revokes_pending_invitation(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    users_before = db_session.scalar(select(func.count()).select_from(User))
    memberships_before = db_session.scalar(
        select(func.count()).select_from(OrganizationMembership)
    )
    created = _invite(client, ctx["token"], "revoke-me@example.com")
    assert created.status_code == 201, created.text
    ref = created.json()["invitation_ref"]
    provider_id = fake_clerk.invitations[ctx["clerk_org"]][-1].provider_invitation_id

    gets_before = fake_clerk.get_invitation_calls
    revokes_before = fake_clerk.revoke_invitation_calls
    response = _revoke(client, ctx["token"], ref)
    assert response.status_code == 200, response.text
    body = response.json()
    _assert_no_secrets(body)
    assert body == {"revoked": True, "local_recording_state": "complete"}
    assert "invitation_ref" not in body
    assert "recipient_hint" not in body
    assert provider_id not in response.text
    assert ref not in response.text
    assert "revoke-me@example.com" not in response.text

    assert fake_clerk.get_invitation_calls == gets_before + 1
    assert fake_clerk.revoke_invitation_calls == revokes_before + 1
    stored = fake_clerk.invitations[ctx["clerk_org"]][-1]
    assert stored.status == "revoked"
    assert isinstance(
        fake_clerk.get_organization_invitation(ctx["clerk_org"], provider_id),
        ClerkInvitationMutationView,
    )
    view = fake_clerk.get_organization_invitation(ctx["clerk_org"], provider_id)
    assert not hasattr(view, "email_address")
    assert view.status == "revoked"

    assert db_session.scalar(select(func.count()).select_from(User)) == users_before
    assert (
        db_session.scalar(select(func.count()).select_from(OrganizationMembership))
        == memberships_before
    )

    events = db_session.scalars(
        select(AuditEvent).where(
            AuditEvent.organization_id == ctx["org_id"],
            AuditEvent.action == "organization.invitation_revoked",
        )
    ).all()
    assert len(events) == 1
    assert events[0].event_metadata == {"role": "member"}
    meta = str(events[0].event_metadata).lower()
    assert "email" not in meta
    assert "hint" not in meta
    assert "invitation_ref" not in meta
    assert provider_id not in meta


def test_revoke_unrecognized_role_allowed_no_role_in_audit(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    _plant_pending(
        fake_clerk,
        clerk_org=ctx["clerk_org"],
        email="billing@example.com",
        role="org:billing",
    )
    ref = _ref_for_planted(
        ctx["org_id"], fake_clerk, ctx["clerk_org"], "billing@example.com"
    )
    response = _revoke(client, ctx["token"], ref)
    assert response.status_code == 200
    events = db_session.scalars(
        select(AuditEvent).where(
            AuditEvent.organization_id == ctx["org_id"],
            AuditEvent.action == "organization.invitation_revoked",
        )
    ).all()
    assert len(events) == 1
    assert events[0].event_metadata in (None, {})


def test_revoke_admin_role_pending_allowed(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    _plant_pending(
        fake_clerk,
        clerk_org=ctx["clerk_org"],
        email="admin-invite@example.com",
        role="org:admin",
    )
    ref = _ref_for_planted(
        ctx["org_id"], fake_clerk, ctx["clerk_org"], "admin-invite@example.com"
    )
    assert _revoke(client, ctx["token"], ref).status_code == 200
    events = db_session.scalars(
        select(AuditEvent).where(
            AuditEvent.organization_id == ctx["org_id"],
            AuditEvent.action == "organization.invitation_revoked",
        )
    ).all()
    assert events[-1].event_metadata == {"role": "admin"}


# ---------------------------------------------------------------- invalid refs → 404 zero provider


def test_invalid_refs_404_zero_provider(client, make_token, seed_user_a, fake_clerk):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    org_id = ctx["org_id"]
    good = mint_invitation_ref(
        organization_id=org_id,
        provider_invitation_id="inv_good",
    )

    # Bit-flip ciphertext
    prefix, blob = good.split(".", 1)
    padded = blob + ("=" * (-len(blob) % 4))
    packed = bytearray(urlsafe_b64decode(padded.encode("ascii")))
    packed[-1] ^= 0x01
    flipped = (
        f"{prefix}."
        + urlsafe_b64encode(bytes(packed)).decode("ascii").rstrip("=")
    )

    expired = mint_invitation_ref(
        organization_id=org_id,
        provider_invitation_id="inv_expired",
        now=datetime.now(timezone.utc) - timedelta(hours=25),
        provider_expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
    )

    foreign = mint_invitation_ref(
        organization_id=uuid4(),
        provider_invitation_id="inv_foreign",
    )

    cases = [
        "not-a-token",
        "v2.abc",
        "v1.",
        "orginv_raw_provider_id",
        flipped,
        expired,
        foreign,
        good[:-1] + ("A" if good[-1] != "A" else "B"),
    ]
    for raw in cases:
        before_get = fake_clerk.get_invitation_calls
        before_revoke = fake_clerk.revoke_invitation_calls
        before_audit = fake_clerk.create_invitation_calls
        response = _revoke(client, ctx["token"], raw)
        assert response.status_code == 404, raw
        assert response.json()["error"]["message"] == PENDING_NOT_FOUND_DETAIL
        assert fake_clerk.get_invitation_calls == before_get
        assert fake_clerk.revoke_invitation_calls == before_revoke
        _ = before_audit


def test_wrong_key_404(client, make_token, seed_user_a, fake_clerk, monkeypatch):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    token = mint_invitation_ref(
        organization_id=ctx["org_id"],
        provider_invitation_id="inv_wrong_key",
    )
    monkeypatch.setenv("ORGANIZATION_INVITATION_REF_SECRET_KEY", "dd" * 32)
    reset_settings_cache()
    before_get = fake_clerk.get_invitation_calls
    response = _revoke(client, ctx["token"], token)
    assert response.status_code == 404
    assert fake_clerk.get_invitation_calls == before_get
    monkeypatch.setenv("ORGANIZATION_INVITATION_REF_SECRET_KEY", "bb" * 32)
    reset_settings_cache()


# ---------------------------------------------------------------- provider semantics


def test_repeat_revoke_404(client, make_token, seed_user_a, fake_clerk, db_session):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    created = _invite(client, ctx["token"], "once@example.com")
    ref = created.json()["invitation_ref"]
    assert _revoke(client, ctx["token"], ref).status_code == 200
    audits_before = db_session.scalar(
        select(func.count())
        .select_from(AuditEvent)
        .where(AuditEvent.action == "organization.invitation_revoked")
    )
    revokes_before = fake_clerk.revoke_invitation_calls
    second = _revoke(client, ctx["token"], ref)
    assert second.status_code == 404
    assert second.json()["error"]["message"] == PENDING_NOT_FOUND_DETAIL
    # precheck GET sees revoked → 404, zero revoke write
    assert fake_clerk.revoke_invitation_calls == revokes_before
    assert (
        db_session.scalar(
            select(func.count())
            .select_from(AuditEvent)
            .where(AuditEvent.action == "organization.invitation_revoked")
        )
        == audits_before
    )


def test_accepted_precheck_404(client, make_token, seed_user_a, fake_clerk):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    _plant_pending(
        fake_clerk,
        clerk_org=ctx["clerk_org"],
        email="accepted@example.com",
        role="org:member",
        status="accepted",
    )
    row = fake_clerk.invitations[ctx["clerk_org"]][-1]
    ref = mint_invitation_ref(
        organization_id=ctx["org_id"],
        provider_invitation_id=row.provider_invitation_id,
    )
    before_revoke = fake_clerk.revoke_invitation_calls
    response = _revoke(client, ctx["token"], ref)
    assert response.status_code == 404
    assert fake_clerk.revoke_invitation_calls == before_revoke


def test_provider_missing_404(client, make_token, seed_user_a, fake_clerk):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    ref = mint_invitation_ref(
        organization_id=ctx["org_id"],
        provider_invitation_id="inv_missing_nowhere",
    )
    before_revoke = fake_clerk.revoke_invitation_calls
    response = _revoke(client, ctx["token"], ref)
    assert response.status_code == 404
    assert response.json()["error"]["message"] == PENDING_NOT_FOUND_DETAIL
    assert fake_clerk.revoke_invitation_calls == before_revoke


def test_ambiguous_revoke_reconciles_success(
    client, make_token, seed_user_a, fake_clerk
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    _plant_pending(
        fake_clerk, clerk_org=ctx["clerk_org"], email="amb@example.com", role="org:member"
    )
    ref = _ref_for_planted(ctx["org_id"], fake_clerk, ctx["clerk_org"], "amb@example.com")
    fake_clerk.revoke_invitation_mode = "ambiguous_applied"
    revokes_before = fake_clerk.revoke_invitation_calls
    gets_before = fake_clerk.get_invitation_calls
    response = _revoke(client, ctx["token"], ref)
    assert response.status_code == 200
    assert fake_clerk.revoke_invitation_calls == revokes_before + 1
    # precheck GET + reconcile GET
    assert fake_clerk.get_invitation_calls == gets_before + 2


def test_ambiguous_still_pending_503(client, make_token, seed_user_a, fake_clerk):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    _plant_pending(
        fake_clerk,
        clerk_org=ctx["clerk_org"],
        email="still@example.com",
        role="org:member",
    )
    ref = _ref_for_planted(
        ctx["org_id"], fake_clerk, ctx["clerk_org"], "still@example.com"
    )
    fake_clerk.revoke_invitation_mode = "ambiguous_applied_pending"
    response = _revoke(client, ctx["token"], ref)
    assert response.status_code == 503
    assert response.json()["error"]["message"] == REVOKE_UNAVAILABLE_DETAIL
    assert fake_clerk.revoke_invitation_calls == 1


def test_ambiguous_accepted_404(client, make_token, seed_user_a, fake_clerk):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    _plant_pending(
        fake_clerk,
        clerk_org=ctx["clerk_org"],
        email="race@example.com",
        role="org:member",
    )
    ref = _ref_for_planted(
        ctx["org_id"], fake_clerk, ctx["clerk_org"], "race@example.com"
    )
    fake_clerk.revoke_invitation_mode = "ambiguous_applied_accepted"
    response = _revoke(client, ctx["token"], ref)
    assert response.status_code == 404
    assert fake_clerk.revoke_invitation_calls == 1


def test_ambiguous_absent_503(client, make_token, seed_user_a, fake_clerk):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    _plant_pending(
        fake_clerk,
        clerk_org=ctx["clerk_org"],
        email="gone@example.com",
        role="org:member",
    )
    ref = _ref_for_planted(
        ctx["org_id"], fake_clerk, ctx["clerk_org"], "gone@example.com"
    )
    fake_clerk.revoke_invitation_mode = "ambiguous_applied_absent"
    response = _revoke(client, ctx["token"], ref)
    assert response.status_code == 503
    assert response.json()["error"]["message"] == REVOKE_UNAVAILABLE_DETAIL


def test_provider_unavailable_503(client, make_token, seed_user_a, fake_clerk):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    _plant_pending(
        fake_clerk,
        clerk_org=ctx["clerk_org"],
        email="down@example.com",
        role="org:member",
    )
    ref = _ref_for_planted(
        ctx["org_id"], fake_clerk, ctx["clerk_org"], "down@example.com"
    )
    fake_clerk.revoke_invitation_mode = "unavailable"
    response = _revoke(client, ctx["token"], ref)
    assert response.status_code == 503
    assert response.json()["error"]["message"] == REVOKE_UNAVAILABLE_DETAIL


def test_get_unavailable_503_zero_revoke(client, make_token, seed_user_a, fake_clerk):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    _plant_pending(
        fake_clerk,
        clerk_org=ctx["clerk_org"],
        email="getfail@example.com",
        role="org:member",
    )
    ref = _ref_for_planted(
        ctx["org_id"], fake_clerk, ctx["clerk_org"], "getfail@example.com"
    )
    fake_clerk.fail_get_invitation = True
    before_revoke = fake_clerk.revoke_invitation_calls
    response = _revoke(client, ctx["token"], ref)
    assert response.status_code == 503
    assert fake_clerk.revoke_invitation_calls == before_revoke


# ---------------------------------------------------------------- rate limit / audit degraded / m37


def test_revoke_rate_limit_after_valid_ref(
    client, make_token, seed_user_a, fake_clerk, monkeypatch
):
    monkeypatch.setenv("RATE_LIMIT_ORGANIZATION_INVITATION_REVOKE", "1")
    reset_settings_cache()
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    _plant_pending(
        fake_clerk, clerk_org=ctx["clerk_org"], email="r1@example.com", role="org:member"
    )
    _plant_pending(
        fake_clerk, clerk_org=ctx["clerk_org"], email="r2@example.com", role="org:member"
    )
    ref1 = _ref_for_planted(ctx["org_id"], fake_clerk, ctx["clerk_org"], "r1@example.com")
    ref2 = _ref_for_planted(ctx["org_id"], fake_clerk, ctx["clerk_org"], "r2@example.com")
    assert _revoke(client, ctx["token"], ref1).status_code == 200
    revokes_before = fake_clerk.revoke_invitation_calls
    gets_before = fake_clerk.get_invitation_calls
    second = _revoke(client, ctx["token"], ref2)
    assert second.status_code == 429
    assert fake_clerk.revoke_invitation_calls == revokes_before
    assert fake_clerk.get_invitation_calls == gets_before
    # invalid ref still 404 without consuming further provider I/O
    assert _revoke(client, ctx["token"], "v1.notvalid").status_code == 404
    reset_settings_cache()


def test_audit_degraded_still_success(
    client, make_token, seed_user_a, fake_clerk, monkeypatch
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    _plant_pending(
        fake_clerk,
        clerk_org=ctx["clerk_org"],
        email="degraded@example.com",
        role="org:member",
    )
    ref = _ref_for_planted(
        ctx["org_id"], fake_clerk, ctx["clerk_org"], "degraded@example.com"
    )
    monkeypatch.setattr(
        "app.services.organization_invitations.record_audit",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("audit down")),
    )
    revokes_before = fake_clerk.revoke_invitation_calls
    response = _revoke(client, ctx["token"], ref)
    assert response.status_code == 200
    assert response.json()["local_recording_state"] == "audit_degraded"
    assert fake_clerk.revoke_invitation_calls == revokes_before + 1


def test_m37_projects_invitation_revoked(client, make_token, seed_user_a, fake_clerk):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    created = _invite(client, ctx["token"], "m37@example.com")
    ref = created.json()["invitation_ref"]
    assert _revoke(client, ctx["token"], ref).status_code == 200
    audit = client.get("/v1/audit-events", headers=_auth(ctx["token"]))
    assert audit.status_code == 200
    actions = {row["action"] for row in audit.json()["items"]}
    assert "organization_invitation_revoked" in actions
    for row in audit.json()["items"]:
        if row["action"] == "organization_invitation_revoked":
            assert row["label"] == "Organization invitation revoked"
            detail = row.get("detail") or {}
            assert detail.get("kind") == "organization_invitation_revoked"
            assert "invitation_ref" not in str(row).lower()
            assert "email" not in str(detail).lower()


def test_list_refresh_after_key_rotation(
    client, make_token, seed_user_a, fake_clerk, monkeypatch
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    _plant_pending(
        fake_clerk,
        clerk_org=ctx["clerk_org"],
        email="rotate-ui@example.com",
        role="org:member",
    )
    old_ref = _ref_for_planted(
        ctx["org_id"], fake_clerk, ctx["clerk_org"], "rotate-ui@example.com"
    )
    monkeypatch.setenv("ORGANIZATION_INVITATION_REF_SECRET_KEY", "ee" * 32)
    reset_settings_cache()
    assert _revoke(client, ctx["token"], old_ref).status_code == 404
    listed = _list(client, ctx["token"])
    assert listed.status_code == 200
    fresh_ref = listed.json()["items"][0]["invitation_ref"]
    assert _revoke(client, ctx["token"], fresh_ref).status_code == 200
    monkeypatch.setenv("ORGANIZATION_INVITATION_REF_SECRET_KEY", "bb" * 32)
    reset_settings_cache()


def test_revoke_default_rate_limit_config():
    settings = get_settings()
    assert settings.rate_limit_organization_invitation_revoke == 20
    assert settings.rate_limit_window_seconds == 3600
