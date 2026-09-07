"""Milestone 39 — organization access management mutations."""

from __future__ import annotations

from uuid import UUID, uuid4

import pytest
from sqlalchemy import func, select

from app.core.config import reset_settings_cache
from app.models.audit import AuditEvent
from app.models.organization import OrganizationMembership
from app.models.user import User
from app.services.clerk import ClerkOrgMembership, ClerkUserInfo
from app.services.organization_access_mutations import (
    ADMIN_MUTATION_FORBIDDEN_DETAIL,
    LAST_ADMIN_PROVIDER_ATOMIC_GUARANTEE,
    MEMBER_NOT_FOUND_DETAIL,
    UNRECOGNIZED_ROLE_DETAIL,
    UPDATE_UNAVAILABLE_DETAIL,
)
from tests.test_finding_follow_up import _add_clerk_member, _auth, _ids
from tests.test_organization_access import _access, _assert_no_secrets, _setup


def _put_role(client, token: str, user_id: UUID, role: str):
    return client.put(
        f"/v1/organization-access/members/{user_id}/role",
        headers=_auth(token),
        json={"role": role},
    )


def _delete_member(client, token: str, user_id: UUID):
    return client.delete(
        f"/v1/organization-access/members/{user_id}",
        headers=_auth(token),
    )


def test_last_admin_provider_guarantee_is_unconfirmed():
    assert LAST_ADMIN_PROVIDER_ATOMIC_GUARANTEE is False


# ------------------------------------------------------------------- RBAC / privacy


def test_member_cannot_mutate(client, make_token, seed_user_a, fake_clerk):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    assert _put_role(client, ctx["member_token"], ctx["member_id"], "admin").status_code == 403
    assert _delete_member(client, ctx["member_token"], ctx["member_id"]).status_code == 403
    assert fake_clerk.update_role_calls == 0
    assert fake_clerk.delete_membership_calls == 0


def test_uniform_404_missing_and_foreign_user(
    client, make_token, seed_user_a, seed_user_b, fake_clerk
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    clerk_b, org_b = seed_user_b
    foreign_token = make_token(sub=clerk_b, org_id=org_b, org_role="org:admin")
    foreign_id, _ = _ids(client, foreign_token)

    missing = _put_role(client, ctx["token"], uuid4(), "admin")
    foreign = _put_role(client, ctx["token"], foreign_id, "admin")
    assert missing.status_code == 404
    assert foreign.status_code == 404
    assert missing.json()["error"]["message"] == MEMBER_NOT_FOUND_DETAIL
    assert foreign.json()["error"]["message"] == MEMBER_NOT_FOUND_DETAIL
    assert missing.json()["error"]["code"] == foreign.json()["error"]["code"]
    _assert_no_secrets(missing.json())
    assert fake_clerk.update_role_calls == 0

    missing_del = _delete_member(client, ctx["token"], uuid4())
    foreign_del = _delete_member(client, ctx["token"], foreign_id)
    assert missing_del.status_code == 404
    assert foreign_del.status_code == 404
    assert missing_del.json()["error"]["message"] == MEMBER_NOT_FOUND_DETAIL
    assert foreign_del.json()["error"]["message"] == MEMBER_NOT_FOUND_DETAIL
    assert foreign_del.json()["error"]["code"] == missing_del.json()["error"]["code"]
    assert fake_clerk.delete_membership_calls == 0


def test_linked_but_authoritative_membership_absent_404(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    # Drop Clerk membership while local User remains.
    fake_clerk.memberships[ctx["member_clerk"]] = []
    response = _put_role(client, ctx["token"], ctx["member_id"], "admin")
    assert response.status_code == 404
    assert response.json()["error"]["message"] == MEMBER_NOT_FOUND_DETAIL
    assert fake_clerk.update_role_calls == 0


# --------------------------------------------------------------- unrecognized role


def test_unrecognized_role_mutations_409_no_provider_write(
    client, make_token, seed_user_a, fake_clerk
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    unknown_clerk = _add_clerk_member(
        fake_clerk, clerk_org_id=ctx["clerk_org"], role="org:billing", name="Billing"
    )
    unknown_token = make_token(
        sub=unknown_clerk, org_id=ctx["clerk_org"], org_role="org:billing"
    )
    # Sync creates User; JWT unknown role still links account.
    unknown_id, _ = _ids(client, unknown_token)

    listed = _access(client, ctx["token"])
    assert listed.status_code == 200
    match = next(
        item
        for item in listed.json()["items"]
        if item["user_id"] == str(unknown_id)
    )
    assert match["role_state"] == "unrecognized"
    assert match["role"] is None

    put = _put_role(client, ctx["token"], unknown_id, "member")
    delete = _delete_member(client, ctx["token"], unknown_id)
    assert put.status_code == 409
    assert delete.status_code == 409
    assert put.json()["error"]["message"] == UNRECOGNIZED_ROLE_DETAIL
    assert delete.json()["error"]["message"] == UNRECOGNIZED_ROLE_DETAIL
    assert fake_clerk.update_role_calls == 0
    assert fake_clerk.delete_membership_calls == 0


# --------------------------------------------------------------- admin policy


def test_recognized_admin_demotion_and_removal_rejected(
    client, make_token, seed_user_a, fake_clerk
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    second_admin_clerk = _add_clerk_member(
        fake_clerk, clerk_org_id=ctx["clerk_org"], role="org:admin", name="Admin Two"
    )
    second_token = make_token(
        sub=second_admin_clerk, org_id=ctx["clerk_org"], org_role="org:admin"
    )
    second_id, _ = _ids(client, second_token)

    demote = _put_role(client, ctx["token"], second_id, "member")
    remove = _delete_member(client, ctx["token"], second_id)
    self_demote = _put_role(client, ctx["token"], ctx["admin_id"], "member")
    self_remove = _delete_member(client, ctx["token"], ctx["admin_id"])

    for response in (demote, remove, self_demote, self_remove):
        assert response.status_code == 409, response.text
        assert response.json()["error"]["message"] == ADMIN_MUTATION_FORBIDDEN_DETAIL

    assert fake_clerk.update_role_calls == 0
    assert fake_clerk.delete_membership_calls == 0


# --------------------------------------------------------------- role / remove happy path


def test_promote_member_to_admin_and_noop(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    before_updates = fake_clerk.update_role_calls

    promoted = _put_role(client, ctx["token"], ctx["member_id"], "admin")
    assert promoted.status_code == 200, promoted.text
    body = promoted.json()
    _assert_no_secrets(body)
    assert body["local_recording_state"] == "complete"
    assert body["member"]["user_id"] == str(ctx["member_id"])
    assert body["member"]["role"] == "admin"
    assert body["member"]["role_state"] == "recognized"
    assert fake_clerk.update_role_calls == before_updates + 1

    events = db_session.scalars(
        select(AuditEvent).where(
            AuditEvent.organization_id == ctx["org_id"],
            AuditEvent.action == "organization.member_role_changed",
        )
    ).all()
    assert len(events) == 1
    assert events[0].resource_type == "organization_member"
    assert events[0].resource_id == ctx["member_id"]
    assert events[0].event_metadata["previous_role"] == "member"
    assert events[0].event_metadata["new_role"] == "admin"
    assert events[0].event_metadata["target_user_id"] == str(ctx["member_id"])

    local = db_session.scalar(
        select(OrganizationMembership).where(
            OrganizationMembership.organization_id == ctx["org_id"],
            OrganizationMembership.user_id == ctx["member_id"],
        )
    )
    assert local is not None
    assert local.role == "org:admin"

    # No-op same role
    noop = _put_role(client, ctx["token"], ctx["member_id"], "admin")
    assert noop.status_code == 200
    assert fake_clerk.update_role_calls == before_updates + 1
    assert (
        db_session.scalar(
            select(func.count())
            .select_from(AuditEvent)
            .where(
                AuditEvent.organization_id == ctx["org_id"],
                AuditEvent.action == "organization.member_role_changed",
            )
        )
        == 1
    )


def test_remove_recognized_member(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    removed = _delete_member(client, ctx["token"], ctx["member_id"])
    assert removed.status_code == 200, removed.text
    body = removed.json()
    assert body["removed_user_id"] == str(ctx["member_id"])
    assert body["local_recording_state"] == "complete"
    _assert_no_secrets(body)
    assert fake_clerk.delete_membership_calls == 1

    events = db_session.scalars(
        select(AuditEvent).where(
            AuditEvent.organization_id == ctx["org_id"],
            AuditEvent.action == "organization.member_removed",
        )
    ).all()
    assert len(events) == 1
    assert events[0].resource_id == ctx["member_id"]
    assert events[0].event_metadata["previous_role"] == "member"

    local = db_session.scalar(
        select(OrganizationMembership).where(
            OrganizationMembership.organization_id == ctx["org_id"],
            OrganizationMembership.user_id == ctx["member_id"],
        )
    )
    assert local is None

    # Repeat ordinary removal → 404
    again = _delete_member(client, ctx["token"], ctx["member_id"])
    assert again.status_code == 404
    assert again.json()["error"]["message"] == MEMBER_NOT_FOUND_DETAIL
    assert fake_clerk.delete_membership_calls == 1

    # User row preserved
    assert db_session.get(User, ctx["member_id"]) is not None

    # M38 no longer lists removed member
    listed = _access(client, ctx["token"]).json()
    assert all(item.get("user_id") != str(ctx["member_id"]) for item in listed["items"])


def test_invalid_role_422(client, make_token, seed_user_a, fake_clerk):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    response = _put_role(client, ctx["token"], ctx["member_id"], "billing")
    assert response.status_code == 422
    assert fake_clerk.update_role_calls == 0


# --------------------------------------------------------------- ambiguous writes


def test_ambiguous_role_patch_applied_then_success(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    fake_clerk.update_role_mode = "ambiguous_applied"
    response = _put_role(client, ctx["token"], ctx["member_id"], "admin")
    assert response.status_code == 200, response.text
    assert response.json()["member"]["role"] == "admin"
    assert fake_clerk.update_role_calls == 1
    assert (
        db_session.scalar(
            select(func.count())
            .select_from(AuditEvent)
            .where(AuditEvent.action == "organization.member_role_changed")
        )
        == 1
    )


def test_ambiguous_role_patch_without_apply_503(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    fake_clerk.update_role_mode = "ambiguous"
    response = _put_role(client, ctx["token"], ctx["member_id"], "admin")
    assert response.status_code == 503
    assert response.json()["error"]["message"] == UPDATE_UNAVAILABLE_DETAIL
    assert fake_clerk.update_role_calls == 1
    assert (
        db_session.scalar(
            select(func.count())
            .select_from(AuditEvent)
            .where(AuditEvent.action == "organization.member_role_changed")
        )
        == 0
    )


def test_ambiguous_role_patch_reconcile_unavailable_503(
    client, make_token, seed_user_a, fake_clerk
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    fake_clerk.update_role_mode = "ambiguous"
    fake_clerk.fail_get_membership = True
    # Pre-check also uses get_membership — fail after first successful resolve.
    # Force: succeed pre-check by temporarily clearing fail, then fail reconcile.
    fake_clerk.fail_get_membership = False
    original_get = fake_clerk.get_organization_membership
    calls = {"n": 0}

    def flaky_get(clerk_org_id: str, clerk_user_id: str):
        calls["n"] += 1
        if calls["n"] == 1:
            return original_get(clerk_org_id, clerk_user_id)
        from app.services.clerk import OrganizationAccessWriteUnavailable

        raise OrganizationAccessWriteUnavailable()

    fake_clerk.get_organization_membership = flaky_get  # type: ignore[method-assign]
    response = _put_role(client, ctx["token"], ctx["member_id"], "admin")
    assert response.status_code == 503
    assert fake_clerk.update_role_calls == 1


def test_ambiguous_delete_applied_then_success(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    fake_clerk.delete_membership_mode = "ambiguous_applied"
    response = _delete_member(client, ctx["token"], ctx["member_id"])
    assert response.status_code == 200, response.text
    assert fake_clerk.delete_membership_calls == 1
    assert (
        db_session.scalar(
            select(func.count())
            .select_from(AuditEvent)
            .where(AuditEvent.action == "organization.member_removed")
        )
        == 1
    )


def test_ambiguous_delete_without_apply_503(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    fake_clerk.delete_membership_mode = "ambiguous"
    response = _delete_member(client, ctx["token"], ctx["member_id"])
    assert response.status_code == 503
    assert response.json()["error"]["message"] == UPDATE_UNAVAILABLE_DETAIL
    assert fake_clerk.delete_membership_calls == 1
    assert (
        db_session.scalar(
            select(func.count())
            .select_from(AuditEvent)
            .where(AuditEvent.action == "organization.member_removed")
        )
        == 0
    )


def test_ambiguous_delete_reconcile_unavailable_503(
    client, make_token, seed_user_a, fake_clerk
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    fake_clerk.delete_membership_mode = "ambiguous"
    original_get = fake_clerk.get_organization_membership
    calls = {"n": 0}

    def flaky_get(clerk_org_id: str, clerk_user_id: str):
        calls["n"] += 1
        if calls["n"] == 1:
            return original_get(clerk_org_id, clerk_user_id)
        from app.services.clerk import OrganizationAccessWriteUnavailable

        raise OrganizationAccessWriteUnavailable()

    fake_clerk.get_organization_membership = flaky_get  # type: ignore[method-assign]
    response = _delete_member(client, ctx["token"], ctx["member_id"])
    assert response.status_code == 503
    assert fake_clerk.delete_membership_calls == 1


# --------------------------------------------------------------- audit degraded


def test_audit_transient_retry_succeeds_exactly_once(
    client, make_token, seed_user_a, fake_clerk, monkeypatch, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    calls = {"n": 0}
    from app.services.audit import record_audit as real_record_audit

    def flaky(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] < 2:
            raise RuntimeError("transient")
        return real_record_audit(*args, **kwargs)

    monkeypatch.setattr(
        "app.services.organization_access_mutations.record_audit",
        flaky,
    )
    response = _put_role(client, ctx["token"], ctx["member_id"], "admin")
    assert response.status_code == 200
    assert response.json()["local_recording_state"] == "complete"
    assert calls["n"] == 2
    assert (
        db_session.scalar(
            select(func.count())
            .select_from(AuditEvent)
            .where(AuditEvent.action == "organization.member_role_changed")
        )
        == 1
    )


def test_provider_success_audit_degraded_no_second_write(
    client, make_token, seed_user_a, fake_clerk, monkeypatch, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)

    def always_fail(*_args, **_kwargs):
        raise RuntimeError("audit unavailable")

    monkeypatch.setattr(
        "app.services.organization_access_mutations.record_audit",
        always_fail,
    )
    before = fake_clerk.update_role_calls
    response = _put_role(client, ctx["token"], ctx["member_id"], "admin")
    assert response.status_code == 200, response.text
    assert response.json()["local_recording_state"] == "audit_degraded"
    assert response.json()["member"]["role"] == "admin"
    assert fake_clerk.update_role_calls == before + 1
    assert (
        db_session.scalar(
            select(func.count())
            .select_from(AuditEvent)
            .where(AuditEvent.action == "organization.member_role_changed")
        )
        == 0
    )


def test_failed_provider_mutation_no_success_audit(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    fake_clerk.update_role_mode = "unavailable"
    response = _put_role(client, ctx["token"], ctx["member_id"], "admin")
    assert response.status_code == 503
    assert (
        db_session.scalar(
            select(func.count())
            .select_from(AuditEvent)
            .where(AuditEvent.action == "organization.member_role_changed")
        )
        == 0
    )


def test_cache_failure_after_audit_still_success(
    client, make_token, seed_user_a, fake_clerk, monkeypatch, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)

    def boom(*_a, **_k):
        raise RuntimeError("cache boom")

    monkeypatch.setattr(
        "app.services.organization_access_mutations._update_local_role_cache_if_present",
        boom,
    )
    response = _put_role(client, ctx["token"], ctx["member_id"], "admin")
    assert response.status_code == 200
    assert response.json()["local_recording_state"] == "complete"
    assert (
        db_session.scalar(
            select(func.count())
            .select_from(AuditEvent)
            .where(AuditEvent.action == "organization.member_role_changed")
        )
        == 1
    )


# --------------------------------------------------------------- rate limit / stale JWT


def test_mutate_rate_limit_blocks_before_provider(
    client, make_token, seed_user_a, fake_clerk, monkeypatch
):
    monkeypatch.setenv("RATE_LIMIT_ORGANIZATION_ACCESS_MUTATE", "1")
    reset_settings_cache()
    try:
        ctx = _setup(client, make_token, seed_user_a, fake_clerk)
        first = _put_role(client, ctx["token"], ctx["member_id"], "admin")
        assert first.status_code == 200, first.text
        calls = fake_clerk.update_role_calls
        second = _delete_member(client, ctx["token"], ctx["admin_id"])
        # Rate limit hits before any provider verification for second call.
        assert second.status_code == 429
        assert fake_clerk.update_role_calls == calls
        # get_membership for second must not run either — but first call already used get.
        # Ensure delete was not attempted.
        assert fake_clerk.delete_membership_calls == 0
    finally:
        monkeypatch.setenv("RATE_LIMIT_ORGANIZATION_ACCESS_MUTATE", "30")
        reset_settings_cache()


def test_stale_jwt_admin_vetoed_after_provider_role_change(
    client, make_token, seed_user_a, fake_clerk
):
    """M21 fresh membership veto: JWT admin + Clerk member cannot mutate."""
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    # Simulate demotion at provider while JWT still claims admin.
    fake_clerk.memberships[ctx["clerk_admin"]] = [
        ClerkOrgMembership(
            clerk_org_id=ctx["clerk_org"], org_name="Org A", role="org:member"
        )
    ]
    response = _put_role(client, ctx["token"], ctx["member_id"], "admin")
    assert response.status_code == 403
    assert fake_clerk.update_role_calls == 0


def test_m37_projects_member_access_events(
    client, make_token, seed_user_a, fake_clerk
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    assert _put_role(client, ctx["token"], ctx["member_id"], "admin").status_code == 200

    # Add another ordinary member to remove.
    other_clerk = _add_clerk_member(
        fake_clerk, clerk_org_id=ctx["clerk_org"], name="Removable"
    )
    other_token = make_token(
        sub=other_clerk, org_id=ctx["clerk_org"], org_role="org:member"
    )
    other_id, _ = _ids(client, other_token)
    assert _delete_member(client, ctx["token"], other_id).status_code == 200

    audit = client.get("/v1/audit-events", headers=_auth(ctx["token"]))
    assert audit.status_code == 200, audit.text
    actions = {row["action"] for row in audit.json()["items"]}
    assert "organization_member_role_changed" in actions
    assert "organization_member_removed" in actions
    for row in audit.json()["items"]:
        if row["action"] in {
            "organization_member_role_changed",
            "organization_member_removed",
        }:
            assert row["resource"]["kind"] == "organization_member"
            _assert_no_secrets(row)


def test_unlinked_member_visible_but_not_mutable_via_user_id(
    client, make_token, seed_user_a, fake_clerk
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    unlinked = f"user_{uuid4().hex}"
    fake_clerk.users[unlinked] = ClerkUserInfo(
        clerk_user_id=unlinked,
        email=f"{unlinked}@example.com",
        name="Unlinked Person",
        email_verified=True,
    )
    fake_clerk.memberships[unlinked] = [
        ClerkOrgMembership(
            clerk_org_id=ctx["clerk_org"], org_name="Org A", role="org:member"
        )
    ]
    listed = _access(client, ctx["token"]).json()
    unlinked_rows = [
        item
        for item in listed["items"]
        if item["display_name"] == "Unlinked Person" and item["user_id"] is None
    ]
    assert len(unlinked_rows) == 1
    assert unlinked_rows[0]["account_link_state"] == "not_linked"
