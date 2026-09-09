"""Milestone 47 — optional M33 precondition + due-only client contract pins.

M47 frontend orchestration is not executed here. These tests pin the wire
contract the modal depends on, plus the datetime-local helper script.
"""

from __future__ import annotations

import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from fastapi import HTTPException
from sqlalchemy import select

from app.models.finding import Finding
from app.models.finding_follow_up import FindingFollowUpChange
from app.services.findings.follow_up import FOLLOW_UP_CHANGED_DETAIL
from app.services.organization_members import assert_assignable_org_member
from tests.test_finding_follow_up import (
    _add_clerk_member,
    _auth,
    _finding,
    _follow_up_audit_count,
    _follow_up_history_count,
    _ids,
    _put_follow_up,
)
from tests.test_organization_access import _setup
from tests.test_organization_access_mutations import _delete_member

CONFLICT = FOLLOW_UP_CHANGED_DETAIL
RESOLVED = "Resolved findings cannot change follow-up ownership or due date"
STALE = "Assignee must be a current organization member"
WEB_ROOT = Path(__file__).resolve().parents[2] / "web"
DATETIME_SCRIPT = WEB_ROOT / "scripts" / "assert-datetime-local.mjs"
M51_SCRIPT = WEB_ROOT / "scripts" / "assert-conditional-follow-up-writes.mjs"
M47_MODAL = (
    WEB_ROOT / "app" / "(app)" / "dashboard" / "finding-follow-up-due-modal.tsx"
)
M45_MODAL = (
    WEB_ROOT / "app" / "(app)" / "dashboard" / "finding-ownership-assign-modal.tsx"
)
FINDINGS_PANEL = WEB_ROOT / "app" / "(app)" / "dashboard" / "findings-panel.tsx"
API_TS = WEB_ROOT / "lib" / "api.ts"


def _expected(owner: str | None, due: str | None) -> dict:
    return {"assigned_to_user_id": owner, "follow_up_due_at": due}


def _conditional(owner: str | None, due: str | None, expected_owner: str | None, expected_due: str | None) -> dict:
    return {
        "assigned_to_user_id": owner,
        "follow_up_due_at": due,
        "expected_follow_up": _expected(expected_owner, expected_due),
    }


def _count_assignable(monkeypatch):
    calls = {"n": 0}

    def wrapped(*args, **kwargs):
        calls["n"] += 1
        return assert_assignable_org_member(*args, **kwargs)

    monkeypatch.setattr(
        "app.services.findings.follow_up.assert_assignable_org_member",
        wrapped,
    )
    return calls


def test_omitted_expected_follow_up_keeps_legacy_last_write_wins(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    first = _put_follow_up(
        client,
        ctx["token"],
        finding.id,
        {"assigned_to_user_id": str(ctx["member_id"]), "follow_up_due_at": "2026-10-01T15:00:00Z"},
    )
    assert first.status_code == 200, first.text
    overwritten = _put_follow_up(
        client,
        ctx["token"],
        finding.id,
        {"assigned_to_user_id": str(ctx["admin_id"]), "follow_up_due_at": "2026-11-01T12:00:00Z"},
    )
    assert overwritten.status_code == 200, overwritten.text
    db_session.expire_all()
    row = db_session.get(Finding, finding.id)
    assert row is not None
    assert row.assigned_to_user_id == ctx["admin_id"]
    assert row.follow_up_due_at == datetime(2026, 11, 1, 12, 0, tzinfo=UTC)


def test_explicit_expected_follow_up_null_is_422(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    history_before = _follow_up_history_count(db_session)
    response = _put_follow_up(
        client,
        ctx["token"],
        finding.id,
        {
            "assigned_to_user_id": str(ctx["admin_id"]),
            "follow_up_due_at": "2026-10-01T15:00:00Z",
            "expected_follow_up": None,
        },
    )
    assert response.status_code == 422, response.text
    assert response.json()["error"]["code"] == "validation_error"
    assert _follow_up_history_count(db_session) == history_before
    db_session.expire_all()
    row = db_session.get(Finding, finding.id)
    assert row is not None
    assert row.assigned_to_user_id is None
    assert row.follow_up_due_at is None


def test_expected_object_missing_owner_key_is_422(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    response = _put_follow_up(
        client,
        ctx["token"],
        finding.id,
        {
            "assigned_to_user_id": None,
            "follow_up_due_at": "2026-10-01T15:00:00Z",
            "expected_follow_up": {"follow_up_due_at": None},
        },
    )
    assert response.status_code == 422, response.text


def test_expected_object_missing_due_key_is_422(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    response = _put_follow_up(
        client,
        ctx["token"],
        finding.id,
        {
            "assigned_to_user_id": None,
            "follow_up_due_at": "2026-10-01T15:00:00Z",
            "expected_follow_up": {"assigned_to_user_id": None},
        },
    )
    assert response.status_code == 422, response.text


def test_naive_expected_due_is_422(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    response = _put_follow_up(
        client,
        ctx["token"],
        finding.id,
        _conditional(None, "2026-10-01T15:00:00Z", None, "2026-10-01T15:00:00"),
    )
    assert response.status_code == 422, response.text


def test_complete_null_null_expected_object_allows_due_write(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    response = _put_follow_up(
        client,
        ctx["token"],
        finding.id,
        _conditional(None, "2026-10-01T15:00:00Z", None, None),
    )
    assert response.status_code == 200, response.text
    db_session.expire_all()
    row = db_session.get(Finding, finding.id)
    assert row is not None
    assert row.assigned_to_user_id is None
    assert row.follow_up_due_at == datetime(2026, 10, 1, 15, 0, tzinfo=UTC)


def test_expected_owner_mismatch_409_keeps_locked_owner(
    client, make_token, seed_user_a, fake_clerk, db_session, monkeypatch
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    seeded = _put_follow_up(
        client,
        ctx["token"],
        finding.id,
        {"assigned_to_user_id": str(ctx["member_id"]), "follow_up_due_at": "2026-10-01T15:00:00Z"},
    )
    assert seeded.status_code == 200, seeded.text
    history_before = _follow_up_history_count(db_session)
    audit_before = _follow_up_audit_count(db_session)
    assign_calls = _count_assignable(monkeypatch)
    conflict = _put_follow_up(
        client,
        ctx["token"],
        finding.id,
        _conditional(
            str(ctx["admin_id"]),
            "2026-11-01T12:00:00Z",
            str(ctx["admin_id"]),
            "2026-10-01T15:00:00Z",
        ),
    )
    assert conflict.status_code == 409, conflict.text
    assert conflict.json()["error"]["message"] == CONFLICT
    assert assign_calls["n"] == 0
    assert _follow_up_history_count(db_session) == history_before
    assert _follow_up_audit_count(db_session) == audit_before
    db_session.expire_all()
    row = db_session.get(Finding, finding.id)
    assert row is not None
    assert row.assigned_to_user_id == ctx["member_id"]
    assert row.follow_up_due_at == datetime(2026, 10, 1, 15, 0, tzinfo=UTC)


def test_expected_due_mismatch_409_keeps_locked_due(
    client, make_token, seed_user_a, fake_clerk, db_session, monkeypatch
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    seeded = _put_follow_up(
        client,
        ctx["token"],
        finding.id,
        {"assigned_to_user_id": str(ctx["admin_id"]), "follow_up_due_at": "2026-12-01T00:00:00Z"},
    )
    assert seeded.status_code == 200, seeded.text
    history_before = _follow_up_history_count(db_session)
    assign_calls = _count_assignable(monkeypatch)
    conflict = _put_follow_up(
        client,
        ctx["token"],
        finding.id,
        _conditional(
            str(ctx["admin_id"]),
            "2026-12-15T00:00:00Z",
            str(ctx["admin_id"]),
            "2026-11-01T00:00:00Z",
        ),
    )
    assert conflict.status_code == 409, conflict.text
    assert conflict.json()["error"]["message"] == CONFLICT
    assert assign_calls["n"] == 0
    assert _follow_up_history_count(db_session) == history_before
    db_session.expire_all()
    row = db_session.get(Finding, finding.id)
    assert row is not None
    assert row.assigned_to_user_id == ctx["admin_id"]
    assert row.follow_up_due_at == datetime(2026, 12, 1, 0, 0, tzinfo=UTC)


def test_expected_due_compares_canonical_instants_not_strings(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    seeded = _put_follow_up(
        client,
        ctx["token"],
        finding.id,
        {"assigned_to_user_id": str(ctx["admin_id"]), "follow_up_due_at": "2026-09-01T16:00:00Z"},
    )
    assert seeded.status_code == 200, seeded.text
    matched = _put_follow_up(
        client,
        ctx["token"],
        finding.id,
        _conditional(
            str(ctx["admin_id"]),
            "2026-10-01T12:00:00Z",
            str(ctx["admin_id"]),
            "2026-09-01T12:00:00-04:00",
        ),
    )
    assert matched.status_code == 200, matched.text
    db_session.expire_all()
    row = db_session.get(Finding, finding.id)
    assert row is not None
    assert row.follow_up_due_at == datetime(2026, 10, 1, 12, 0, tzinfo=UTC)


def test_resolved_keeps_resolved_409_with_expected_object(
    client, make_token, seed_user_a, fake_clerk, db_session, monkeypatch
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(
        db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"], status="resolved"
    )
    assign_calls = _count_assignable(monkeypatch)
    blocked = _put_follow_up(
        client,
        ctx["token"],
        finding.id,
        _conditional(str(ctx["admin_id"]), "2026-10-01T15:00:00Z", None, None),
    )
    assert blocked.status_code == 409, blocked.text
    assert blocked.json()["error"]["message"] == RESOLVED
    assert blocked.json()["error"]["message"] != CONFLICT
    assert assign_calls["n"] == 0


def test_stale_requested_owner_is_400_after_matching_precondition(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    stale_clerk = _add_clerk_member(fake_clerk, clerk_org_id=ctx["clerk_org"], name="Leaving")
    stale_token = make_token(sub=stale_clerk, org_id=ctx["clerk_org"], org_role="org:member")
    stale_id, _ = _ids(client, stale_token)
    assigned = _put_follow_up(
        client,
        ctx["token"],
        finding.id,
        {"assigned_to_user_id": str(stale_id), "follow_up_due_at": "2026-10-01T15:00:00Z"},
    )
    assert assigned.status_code == 200, assigned.text
    removed = _delete_member(client, ctx["token"], stale_id)
    assert removed.status_code == 200, removed.text
    history_before = _follow_up_history_count(db_session)
    rejected = _put_follow_up(
        client,
        ctx["token"],
        finding.id,
        _conditional(
            str(stale_id),
            "2026-11-01T15:00:00Z",
            str(stale_id),
            "2026-10-01T15:00:00Z",
        ),
    )
    assert rejected.status_code == 400, rejected.text
    assert rejected.json()["error"]["message"] == STALE
    assert _follow_up_history_count(db_session) == history_before
    db_session.expire_all()
    row = db_session.get(Finding, finding.id)
    assert row is not None
    assert row.assigned_to_user_id == stale_id
    assert row.follow_up_due_at == datetime(2026, 10, 1, 15, 0, tzinfo=UTC)


def test_provider_unavailable_is_502_after_matching_precondition(
    client, make_token, seed_user_a, fake_clerk, db_session, monkeypatch
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    assigned = _put_follow_up(
        client,
        ctx["token"],
        finding.id,
        {"assigned_to_user_id": str(ctx["admin_id"]), "follow_up_due_at": "2026-10-01T15:00:00Z"},
    )
    assert assigned.status_code == 200, assigned.text

    def presentation_unavailable(*_args, **_kwargs):
        raise RuntimeError("provider unavailable")

    monkeypatch.setattr(
        "app.services.findings.follow_up.clerk_user_is_org_member",
        presentation_unavailable,
    )
    got = client.get(f"/v1/findings/{finding.id}", headers=_auth(ctx["token"]))
    assert got.status_code == 200, got.text
    owner = got.json()["follow_up"]["owner"]
    assert owner["user_id"] == str(ctx["admin_id"])
    assert owner["current_member"] is False

    def verify_unavailable(*_args, **_kwargs):
        raise HTTPException(
            status_code=502,
            detail="Failed to verify organization membership",
        )

    monkeypatch.setattr(
        "app.services.findings.follow_up.assert_assignable_org_member",
        verify_unavailable,
    )
    history_before = _follow_up_history_count(db_session)
    failed = _put_follow_up(
        client,
        ctx["token"],
        finding.id,
        _conditional(
            str(ctx["admin_id"]),
            "2026-11-01T15:00:00Z",
            str(ctx["admin_id"]),
            "2026-10-01T15:00:00Z",
        ),
    )
    assert failed.status_code == 502, failed.text
    assert failed.json()["error"]["message"] == "Failed to verify organization membership"
    assert _follow_up_history_count(db_session) == history_before
    db_session.expire_all()
    row = db_session.get(Finding, finding.id)
    assert row is not None
    assert row.assigned_to_user_id == ctx["admin_id"]
    assert row.follow_up_due_at == datetime(2026, 10, 1, 15, 0, tzinfo=UTC)


def test_null_owner_due_change_skips_membership_and_keeps_null_owner(
    client, make_token, seed_user_a, fake_clerk, db_session, monkeypatch
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    assign_calls = _count_assignable(monkeypatch)
    response = _put_follow_up(
        client,
        ctx["token"],
        finding.id,
        _conditional(None, "2026-10-01T15:00:00Z", None, None),
    )
    assert response.status_code == 200, response.text
    assert assign_calls["n"] == 0
    db_session.expire_all()
    row = db_session.get(Finding, finding.id)
    assert row is not None
    assert row.assigned_to_user_id is None
    assert row.follow_up_due_at == datetime(2026, 10, 1, 15, 0, tzinfo=UTC)
    changes = list(db_session.scalars(select(FindingFollowUpChange)))
    assert len(changes) == 1
    assert changes[0].previous_assigned_to_user_id is None
    assert changes[0].new_assigned_to_user_id is None


def test_single_finding_clients_pin_conditional_helpers():
    modal = M47_MODAL.read_text()
    api = API_TS.read_text()
    m45 = M45_MODAL.read_text()
    findings = FINDINGS_PANEL.read_text()
    assert "updateFindingFollowUpConditionally" in api
    assert "expected_follow_up: ExpectedFollowUpState" in api
    assert "writeFindingFollowUpDueConditionally" in modal
    assert "updateFindingFollowUp(" not in modal
    assert "updateFindingFollowUpConditionally" not in modal
    assert "expected_follow_up:" in modal
    assert "updateFindingFollowUp(" not in m45
    assert "updateFindingFollowUpConditionally" not in m45
    assert "updateFindingOwnershipConditionally" in m45
    assert "updateFindingFollowUp(" not in findings
    assert "updateFindingFollowUpConditionally" in findings
    assert "expected_follow_up" in findings


def test_m47_request_body_shape_is_owner_due_and_expected_object(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    snapshot_owner = str(ctx["admin_id"])
    snapshot_due = "2026-10-01T15:00:00Z"
    proposed_due = "2026-11-01T16:30:00Z"
    seeded = _put_follow_up(
        client,
        ctx["token"],
        finding.id,
        {"assigned_to_user_id": snapshot_owner, "follow_up_due_at": snapshot_due},
    )
    assert seeded.status_code == 200, seeded.text
    body = {
        "assigned_to_user_id": snapshot_owner,
        "follow_up_due_at": proposed_due,
        "expected_follow_up": {
            "assigned_to_user_id": snapshot_owner,
            "follow_up_due_at": snapshot_due,
        },
    }
    assert set(body) == {"assigned_to_user_id", "follow_up_due_at", "expected_follow_up"}
    assert set(body["expected_follow_up"]) == {"assigned_to_user_id", "follow_up_due_at"}
    written = _put_follow_up(client, ctx["token"], finding.id, body)
    assert written.status_code == 200, written.text
    db_session.expire_all()
    row = db_session.get(Finding, finding.id)
    assert row is not None
    assert str(row.assigned_to_user_id) == snapshot_owner
    assert row.follow_up_due_at == datetime(2026, 11, 1, 16, 30, tzinfo=UTC)


def test_conditional_combined_owner_due_write_emits_one_history_and_audit(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    history_before = _follow_up_history_count(db_session)
    audit_before = _follow_up_audit_count(db_session)

    changed = _put_follow_up(
        client,
        ctx["token"],
        finding.id,
        _conditional(str(ctx["member_id"]), "2026-11-01T16:30:00Z", None, None),
    )

    assert changed.status_code == 200, changed.text
    assert changed.json()["owner"]["user_id"] == str(ctx["member_id"])
    assert _follow_up_history_count(db_session) == history_before + 1
    assert _follow_up_audit_count(db_session) == audit_before + 1


def test_datetime_local_helper_contract():
    assert DATETIME_SCRIPT.is_file(), DATETIME_SCRIPT
    env = {**os.environ, "TZ": "America/New_York"}
    result = subprocess.run(
        ["node", str(DATETIME_SCRIPT)],
        cwd=str(WEB_ROOT),
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_m51_conditional_follow_up_write_contract():
    assert M51_SCRIPT.is_file(), M51_SCRIPT
    env = {**os.environ, "TZ": "America/Los_Angeles"}
    result = subprocess.run(
        ["node", str(M51_SCRIPT)],
        cwd=str(WEB_ROOT),
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr

