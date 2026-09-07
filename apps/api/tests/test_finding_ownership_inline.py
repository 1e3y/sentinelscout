"""Milestone 45 — contract pins for inline ownership resolution.

M45 is frontend orchestration only. These tests pin the existing M33/M44
APIs that the modal reuses. They do not prove frontend drift/single-flight
behavior.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import func, select

from app.models.audit import AuditEvent
from app.models.finding import Finding
from app.models.finding_follow_up import FindingFollowUpChange
from tests.test_finding_follow_up import (
    _add_clerk_member,
    _auth,
    _finding,
    _follow_up_audit_count,
    _follow_up_history_count,
    _ids,
    _put_follow_up,
)
from tests.test_finding_ownership_review import REVIEW, UNAVAILABLE, _review
from tests.test_organization_access import _setup
from tests.test_organization_access_mutations import _delete_member


def test_m45_style_owner_change_preserves_null_and_nonnull_due(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    listed = client.get("/v1/organization-members", headers=_auth(ctx["token"]))
    assert listed.status_code == 200, listed.text
    member_ids = {item["user_id"] for item in listed.json()["items"]}
    assert str(ctx["member_id"]) in member_ids

    first = _put_follow_up(
        client,
        ctx["token"],
        finding.id,
        {"assigned_to_user_id": str(ctx["admin_id"]), "follow_up_due_at": None},
    )
    assert first.status_code == 200, first.text
    fresh = client.get(f"/v1/findings/{finding.id}", headers=_auth(ctx["token"]))
    assert fresh.status_code == 200, fresh.text
    due = fresh.json()["follow_up"]["follow_up_due_at"]
    assert due is None
    reassigned = _put_follow_up(
        client,
        ctx["token"],
        finding.id,
        {"assigned_to_user_id": str(ctx["member_id"]), "follow_up_due_at": due},
    )
    assert reassigned.status_code == 200, reassigned.text
    assert reassigned.json()["follow_up_due_at"] is None
    db_session.expire_all()
    row = db_session.get(Finding, finding.id)
    assert row is not None
    assert row.follow_up_due_at is None
    assert row.assigned_to_user_id == ctx["member_id"]

    due_text = "2026-10-01T15:00:00Z"
    set_due = _put_follow_up(
        client,
        ctx["token"],
        finding.id,
        {"assigned_to_user_id": str(ctx["member_id"]), "follow_up_due_at": due_text},
    )
    assert set_due.status_code == 200, set_due.text
    fresh_due = client.get(f"/v1/findings/{finding.id}", headers=_auth(ctx["token"]))
    exact = fresh_due.json()["follow_up"]["follow_up_due_at"]
    assert exact is not None
    history_before = _follow_up_history_count(db_session)
    change = _put_follow_up(
        client,
        ctx["token"],
        finding.id,
        {"assigned_to_user_id": str(ctx["admin_id"]), "follow_up_due_at": exact},
    )
    assert change.status_code == 200, change.text
    after = datetime.fromisoformat(change.json()["follow_up_due_at"].replace("Z", "+00:00"))
    before = datetime.fromisoformat(exact.replace("Z", "+00:00"))
    assert after == before
    assert after == datetime(2026, 10, 1, 15, 0, tzinfo=UTC)
    assert _follow_up_history_count(db_session) == history_before + 1


def test_m45_style_same_owner_same_due_is_m33_noop(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    due = "2026-09-01T16:00:00Z"
    assert _put_follow_up(
        client,
        ctx["token"],
        finding.id,
        {"assigned_to_user_id": str(ctx["member_id"]), "follow_up_due_at": due},
    ).status_code == 200
    fresh = client.get(f"/v1/findings/{finding.id}", headers=_auth(ctx["token"]))
    exact = fresh.json()["follow_up"]["follow_up_due_at"]
    history_before = _follow_up_history_count(db_session)
    audit_before = _follow_up_audit_count(db_session)
    noop = _put_follow_up(
        client,
        ctx["token"],
        finding.id,
        {"assigned_to_user_id": str(ctx["member_id"]), "follow_up_due_at": exact},
    )
    assert noop.status_code == 200, noop.text
    assert _follow_up_history_count(db_session) == history_before
    assert _follow_up_audit_count(db_session) == audit_before


def test_departed_selected_member_rejected_no_write(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    stale_clerk = _add_clerk_member(fake_clerk, clerk_org_id=ctx["clerk_org"], name="Leaving")
    stale_token = make_token(sub=stale_clerk, org_id=ctx["clerk_org"], org_role="org:member")
    stale_id, _ = _ids(client, stale_token)
    removed = _delete_member(client, ctx["token"], stale_id)
    assert removed.status_code == 200, removed.text
    history_before = _follow_up_history_count(db_session)
    rejected = _put_follow_up(
        client,
        ctx["token"],
        finding.id,
        {"assigned_to_user_id": str(stale_id), "follow_up_due_at": None},
    )
    assert rejected.status_code == 400
    assert rejected.json()["error"]["message"] == (
        "Assignee must be a current organization member"
    )
    assert _follow_up_history_count(db_session) == history_before
    db_session.expire_all()
    row = db_session.get(Finding, finding.id)
    assert row is not None
    assert row.assigned_to_user_id is None


def test_resolved_finding_follow_up_put_409(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(
        db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"], status="resolved"
    )
    blocked = _put_follow_up(
        client,
        ctx["token"],
        finding.id,
        {"assigned_to_user_id": str(ctx["admin_id"]), "follow_up_due_at": None},
    )
    assert blocked.status_code == 409
    assert blocked.json()["error"]["message"] == (
        "Resolved findings cannot change follow-up ownership or due date"
    )


def test_m45_style_write_matches_finding_surface_history_audit(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    due = "2026-11-01T00:00:00Z"
    response = _put_follow_up(
        client,
        ctx["token"],
        finding.id,
        {"assigned_to_user_id": str(ctx["member_id"]), "follow_up_due_at": due},
    )
    assert response.status_code == 200, response.text
    changes = list(db_session.scalars(select(FindingFollowUpChange)))
    assert len(changes) == 1
    row = changes[0]
    assert row.previous_assigned_to_user_id is None
    assert row.new_assigned_to_user_id == ctx["member_id"]
    audits = list(
        db_session.scalars(
            select(AuditEvent).where(AuditEvent.action == "finding.follow_up_changed")
        )
    )
    assert len(audits) == 1
    assert audits[0].resource_id == row.id
    assert db_session.scalar(select(func.count()).select_from(AuditEvent).where(
        AuditEvent.action == "finding_ownership_review_assigned"
    )) in {0, None}


def test_m44_get_remains_read_only_after_m45_style_put(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    assert _put_follow_up(
        client,
        ctx["token"],
        finding.id,
        {"assigned_to_user_id": str(ctx["member_id"]), "follow_up_due_at": None},
    ).status_code == 200
    before = _follow_up_history_count(db_session)
    review = _review(client, ctx["token"])
    assert review.status_code == 200, review.text
    item = next(row for row in review.json()["items"] if row["finding_id"] == str(finding.id))
    assert item["assignment_state"] == "current_member"
    assert "Assign owner" not in review.text
    assert _follow_up_history_count(db_session) == before
    assert client.post(REVIEW, headers=_auth(ctx["token"])).status_code in {404, 405}


def test_successful_put_then_m44_refresh_503_does_not_undo_write(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    written = _put_follow_up(
        client,
        ctx["token"],
        finding.id,
        {"assigned_to_user_id": str(ctx["member_id"]), "follow_up_due_at": None},
    )
    assert written.status_code == 200, written.text
    fake_clerk.fail_membership_presence = True
    refresh = _review(client, ctx["token"])
    assert refresh.status_code == 503
    assert refresh.json()["error"]["message"] == UNAVAILABLE
    db_session.expire_all()
    row = db_session.get(Finding, finding.id)
    assert row is not None
    assert row.assigned_to_user_id == ctx["member_id"]
    assert _follow_up_history_count(db_session) == 1
