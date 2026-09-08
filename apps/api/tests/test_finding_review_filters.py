"""Milestone 48 — target/severity/status filters for M44 and M46 reviews."""

from __future__ import annotations

import os
import subprocess
from base64 import urlsafe_b64encode
from datetime import UTC, datetime, timedelta
from pathlib import Path
from app.models.asset import Asset
from app.models.finding import Finding
from app.services.findings.follow_up_review import (
    INVALID_CURSOR_DETAIL as M46_INVALID,
)
from app.services.findings.follow_up_review import encode_follow_up_review_cursor
from app.services.findings.ownership_review import (
    INVALID_CURSOR_DETAIL as M44_INVALID,
)
from app.services.findings.ownership_review import encode_ownership_review_cursor
from app.services.findings.review_filters import (
    OMITTED_FILTER_TOKEN,
    normalize_review_filters,
)
from tests.test_finding_follow_up import _auth, _finding, _put_follow_up
from tests.test_finding_follow_up_review import _review as _m46
from tests.test_finding_ownership_review import _review as _m44
from tests.test_organization_access import _setup

WEB_ROOT = Path(__file__).resolve().parents[2] / "web"
SNAPSHOT_SCRIPT = WEB_ROOT / "scripts" / "assert-review-request-snapshot.mjs"


def _target_id(db, finding: Finding):
    asset = db.get(Asset, finding.asset_id)
    assert asset is not None
    return asset.target_id


def _set_severity(db, finding: Finding, severity: str) -> None:
    finding.severity = severity
    db.add(finding)
    db.commit()
    db.refresh(finding)


def _v1_ownership_cursor(*, created_at: datetime, finding_id) -> str:
    payload = f"v1|{created_at.isoformat()}|{finding_id}"
    return urlsafe_b64encode(payload.encode("utf-8")).decode("ascii").rstrip("=")


def _v1_follow_up_cursor(
    *,
    due_filter: str,
    evaluation_time: datetime,
    created_at: datetime,
    finding_id,
) -> str:
    payload = "|".join(
        (
            "v1",
            due_filter,
            evaluation_time.isoformat(),
            created_at.isoformat(),
            str(finding_id),
        )
    )
    return urlsafe_b64encode(payload.encode("utf-8")).decode("ascii").rstrip("=")


def test_m44_omitted_filters_match_unfiltered_collection(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    first = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    second = _finding(
        db_session,
        organization_id=ctx["org_id"],
        user_id=ctx["admin_id"],
        status="in_progress",
    )
    _set_severity(db_session, second, "high")
    unfiltered = _m44(client, ctx["token"])
    assert unfiltered.status_code == 200, unfiltered.text
    omitted = _m44(client, ctx["token"])
    assert {item["finding_id"] for item in omitted.json()["items"]} == {
        item["finding_id"] for item in unfiltered.json()["items"]
    }
    assert {str(first.id), str(second.id)} <= {
        item["finding_id"] for item in omitted.json()["items"]
    }


def test_m44_target_severity_status_and_combined_filters(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    medium_open = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    high_progress = _finding(
        db_session,
        organization_id=ctx["org_id"],
        user_id=ctx["admin_id"],
        status="in_progress",
    )
    _set_severity(db_session, high_progress, "high")
    ready = _finding(
        db_session,
        organization_id=ctx["org_id"],
        user_id=ctx["admin_id"],
        status="ready_for_retest",
    )
    target_a = _target_id(db_session, medium_open)
    by_target = _m44(client, ctx["token"], target_id=str(target_a))
    assert {item["finding_id"] for item in by_target.json()["items"]} == {str(medium_open.id)}
    by_severity = _m44(client, ctx["token"], severity="high")
    assert {item["finding_id"] for item in by_severity.json()["items"]} == {
        str(high_progress.id)
    }
    by_status = _m44(client, ctx["token"], status="ready_for_retest")
    assert {item["finding_id"] for item in by_status.json()["items"]} == {str(ready.id)}
    combined = _m44(
        client,
        ctx["token"],
        target_id=str(_target_id(db_session, high_progress)),
        severity="high",
        status="in_progress",
    )
    assert {item["finding_id"] for item in combined.json()["items"]} == {
        str(high_progress.id)
    }


def test_m44_sql_filters_before_limit(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    older_high = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    newer_medium = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    _set_severity(db_session, older_high, "high")
    older_high.created_at = datetime(2026, 1, 1, tzinfo=UTC)
    newer_medium.created_at = datetime(2026, 2, 1, tzinfo=UTC)
    db_session.add_all([older_high, newer_medium])
    db_session.commit()
    page = _m44(client, ctx["token"], page_size=1, severity="high")
    assert page.status_code == 200, page.text
    assert [item["finding_id"] for item in page.json()["items"]] == [str(older_high.id)]


def test_m44_cross_org_target_is_empty_not_an_oracle(
    client, make_token, seed_user_a, seed_user_b, fake_clerk, db_session
):
    ctx_a = _setup(client, make_token, seed_user_a, fake_clerk)
    clerk_b, org_b = seed_user_b
    token_b = make_token(sub=clerk_b, org_id=org_b, org_role="org:admin")
    from tests.test_finding_follow_up import _ids

    admin_b, org_b_id = _ids(client, token_b)
    foreign = _finding(db_session, organization_id=org_b_id, user_id=admin_b)
    local = _finding(db_session, organization_id=ctx_a["org_id"], user_id=ctx_a["admin_id"])
    foreign_target = _target_id(db_session, foreign)
    response = _m44(client, ctx_a["token"], target_id=str(foreign_target))
    assert response.status_code == 200, response.text
    ids = {item["finding_id"] for item in response.json()["items"]}
    assert ids == set()
    assert str(local.id) not in ids
    assert str(foreign.id) not in ids


def test_m44_invalid_filters_and_resolved_status(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    assert _m44(client, ctx["token"], target_id="not-a-uuid").status_code == 422
    assert _m44(client, ctx["token"], severity="catastrophic").status_code == 422
    assert _m44(client, ctx["token"], status="resolved").status_code == 422
    assert _m44(client, ctx["token"], status="closed").status_code == 422


def test_m44_assignment_state_query_does_not_filter(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    unassigned = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    assigned = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    assert _put_follow_up(
        client,
        ctx["token"],
        assigned.id,
        {"assigned_to_user_id": str(ctx["member_id"]), "follow_up_due_at": None},
    ).status_code == 200
    plain = {item["finding_id"] for item in _m44(client, ctx["token"]).json()["items"]}
    spoofed = {
        item["finding_id"]
        for item in _m44(client, ctx["token"], assignment_state="unassigned").json()["items"]
    }
    assert {str(unassigned.id), str(assigned.id)} <= plain
    assert spoofed == plain


def test_m44_provider_bounds_on_filtered_page(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    unassigned = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    assigned = _finding(
        db_session,
        organization_id=ctx["org_id"],
        user_id=ctx["admin_id"],
        status="in_progress",
    )
    _set_severity(db_session, assigned, "critical")
    assert _put_follow_up(
        client,
        ctx["token"],
        assigned.id,
        {"assigned_to_user_id": str(ctx["member_id"]), "follow_up_due_at": None},
    ).status_code == 200
    before = fake_clerk.membership_presence_calls
    emptyish = _m44(client, ctx["token"], status="open", target_id=str(_target_id(db_session, unassigned)))
    assert emptyish.status_code == 200
    assert all(item["assignment_state"] == "unassigned" for item in emptyish.json()["items"])
    assert fake_clerk.membership_presence_calls == before
    assigned_page = _m44(client, ctx["token"], severity="critical")
    assert assigned_page.status_code == 200
    assert fake_clerk.membership_presence_calls == before + 1


def test_m44_cursor_binds_filters_and_v1_policy(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    high = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    critical = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    _set_severity(db_session, high, "high")
    _set_severity(db_session, critical, "critical")
    high.created_at = datetime(2026, 3, 2, tzinfo=UTC)
    critical.created_at = datetime(2026, 3, 3, tzinfo=UTC)
    other = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    _set_severity(db_session, other, "high")
    other.created_at = datetime(2026, 3, 1, tzinfo=UTC)
    db_session.add_all([high, critical, other])
    db_session.commit()
    first = _m44(client, ctx["token"], page_size=1, severity="high")
    cursor = first.json()["next_cursor"]
    assert cursor
    assert _m44(client, ctx["token"], page_size=1, severity="high", cursor=cursor).status_code == 200
    mismatch = _m44(client, ctx["token"], page_size=1, severity="critical", cursor=cursor)
    assert mismatch.status_code == 400
    assert mismatch.json()["error"]["message"] == M44_INVALID
    omitted = _m44(client, ctx["token"], page_size=1, cursor=cursor)
    assert omitted.status_code == 400
    v1 = _v1_ownership_cursor(created_at=high.created_at, finding_id=high.id)
    assert _m44(client, ctx["token"], cursor=v1).status_code == 200
    assert _m44(client, ctx["token"], severity="high", cursor=v1).status_code == 400
    minted = encode_ownership_review_cursor(
        created_at=high.created_at,
        finding_id=high.id,
        filters=normalize_review_filters(target_id=None, severity="high", status=None),
    )
    assert minted != v1
    target_mismatch = encode_ownership_review_cursor(
        created_at=high.created_at,
        finding_id=high.id,
        filters=normalize_review_filters(
            target_id=_target_id(db_session, high), severity=None, status=None
        ),
    )
    assert _m44(client, ctx["token"], target_id=str(_target_id(db_session, critical)), cursor=target_mismatch).status_code == 400
    status_cursor = encode_ownership_review_cursor(
        created_at=high.created_at,
        finding_id=high.id,
        filters=normalize_review_filters(target_id=None, severity=None, status="open"),
    )
    assert _m44(client, ctx["token"], cursor=status_cursor).status_code == 400


def test_m46_due_plus_dimension_filters_and_sql_before_limit(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    none = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    overdue_high = _finding(
        db_session,
        organization_id=ctx["org_id"],
        user_id=ctx["admin_id"],
        status="in_progress",
    )
    upcoming_medium = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    _set_severity(db_session, overdue_high, "high")
    overdue_high.follow_up_due_at = datetime(2020, 1, 1, tzinfo=UTC)
    upcoming_medium.follow_up_due_at = datetime(2099, 1, 1, tzinfo=UTC)
    overdue_high.created_at = datetime(2026, 1, 1, tzinfo=UTC)
    upcoming_medium.created_at = datetime(2026, 2, 1, tzinfo=UTC)
    db_session.add_all([overdue_high, upcoming_medium])
    db_session.commit()
    before = (
        fake_clerk.membership_presence_calls,
        fake_clerk.memberships_raw_calls,
        fake_clerk.get_membership_calls,
    )
    combined = _m46(
        client,
        ctx["token"],
        due_state="overdue",
        severity="high",
        status="in_progress",
        target_id=str(_target_id(db_session, overdue_high)),
    )
    assert combined.status_code == 200, combined.text
    assert {item["finding_id"] for item in combined.json()["items"]} == {
        str(overdue_high.id)
    }
    limited = _m46(client, ctx["token"], page_size=1, due_state="overdue", severity="high")
    assert [item["finding_id"] for item in limited.json()["items"]] == [str(overdue_high.id)]
    assert (
        fake_clerk.membership_presence_calls,
        fake_clerk.memberships_raw_calls,
        fake_clerk.get_membership_calls,
    ) == before
    assert str(none.id) not in {item["finding_id"] for item in combined.json()["items"]}


def test_m46_invalid_filters_and_resolved_status(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    assert _m46(client, ctx["token"], target_id="not-a-uuid").status_code == 422
    assert _m46(client, ctx["token"], severity="catastrophic").status_code == 422
    assert _m46(client, ctx["token"], status="resolved").status_code == 422
    assert _m46(client, ctx["token"], due_state="all").status_code == 422


def test_m46_cross_org_target_is_empty_not_an_oracle(
    client, make_token, seed_user_a, seed_user_b, fake_clerk, db_session
):
    ctx_a = _setup(client, make_token, seed_user_a, fake_clerk)
    clerk_b, org_b = seed_user_b
    token_b = make_token(sub=clerk_b, org_id=org_b, org_role="org:admin")
    from tests.test_finding_follow_up import _ids

    admin_b, org_b_id = _ids(client, token_b)
    foreign = _finding(db_session, organization_id=org_b_id, user_id=admin_b)
    local = _finding(db_session, organization_id=ctx_a["org_id"], user_id=ctx_a["admin_id"])
    foreign.follow_up_due_at = datetime(2020, 1, 1, tzinfo=UTC)
    db_session.add(foreign)
    db_session.commit()
    response = _m46(client, ctx_a["token"], target_id=str(_target_id(db_session, foreign)))
    assert response.status_code == 200, response.text
    ids = {item["finding_id"] for item in response.json()["items"]}
    assert ids == set()
    assert str(local.id) not in ids
    assert str(foreign.id) not in ids


def test_m46_assignment_state_query_does_not_filter(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    first = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    second = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    plain = {item["finding_id"] for item in _m46(client, ctx["token"]).json()["items"]}
    spoofed = {
        item["finding_id"]
        for item in _m46(client, ctx["token"], assignment_state="unassigned").json()["items"]
    }
    assert {str(first.id), str(second.id)} <= plain
    assert spoofed == plain


def test_m46_cursor_binds_all_filters_and_v1_policy(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    older = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    _set_severity(db_session, finding, "high")
    _set_severity(db_session, older, "high")
    finding.follow_up_due_at = datetime(2020, 1, 1, tzinfo=UTC)
    older.follow_up_due_at = datetime(2020, 1, 2, tzinfo=UTC)
    finding.created_at = datetime(2026, 4, 2, tzinfo=UTC)
    older.created_at = datetime(2026, 4, 1, tzinfo=UTC)
    db_session.add_all([finding, older])
    db_session.commit()
    first = _m46(client, ctx["token"], page_size=1, due_state="overdue", severity="high")
    cursor = first.json()["next_cursor"]
    assert cursor
    assert _m46(
        client, ctx["token"], due_state="overdue", severity="high", cursor=cursor
    ).status_code == 200
    assert _m46(
        client, ctx["token"], due_state="overdue", severity="critical", cursor=cursor
    ).status_code == 400
    assert _m46(client, ctx["token"], due_state="upcoming", severity="high", cursor=cursor).status_code == 400
    now = datetime.now(UTC)
    v1 = _v1_follow_up_cursor(
        due_filter="overdue",
        evaluation_time=now - timedelta(minutes=5),
        created_at=finding.created_at,
        finding_id=finding.id,
    )
    assert _m46(client, ctx["token"], due_state="overdue", cursor=v1).status_code == 200
    assert _m46(
        client, ctx["token"], due_state="overdue", severity="high", cursor=v1
    ).status_code == 400
    v2 = encode_follow_up_review_cursor(
        due_filter="overdue",
        evaluation_time=now - timedelta(minutes=5),
        created_at=finding.created_at,
        finding_id=finding.id,
        filters=normalize_review_filters(target_id=None, severity="high", status=None),
    )
    assert _m46(client, ctx["token"], due_state="overdue", severity="high", cursor=v2).status_code == 200
    assert _m46(client, ctx["token"], due_state="overdue", cursor=v2).status_code == 400
    expired = encode_follow_up_review_cursor(
        due_filter="all",
        evaluation_time=now - timedelta(hours=2),
        created_at=finding.created_at,
        finding_id=finding.id,
    )
    expired_response = _m46(client, ctx["token"], cursor=expired)
    assert expired_response.status_code == 400
    assert expired_response.json()["error"]["message"] == M46_INVALID


def test_m48_frontend_snapshot_contract():
    assert SNAPSHOT_SCRIPT.is_file(), SNAPSHOT_SCRIPT
    result = subprocess.run(
        ["node", str(SNAPSHOT_SCRIPT)],
        cwd=str(WEB_ROOT),
        env=os.environ.copy(),
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    modal_m45 = (
        WEB_ROOT / "app" / "(app)" / "dashboard" / "finding-ownership-assign-modal.tsx"
    ).read_text()
    modal_m47 = (
        WEB_ROOT / "app" / "(app)" / "dashboard" / "finding-follow-up-due-modal.tsx"
    ).read_text()
    m44 = (
        WEB_ROOT / "app" / "(app)" / "dashboard" / "finding-ownership-review-panel.tsx"
    ).read_text()
    m46 = (
        WEB_ROOT / "app" / "(app)" / "dashboard" / "finding-follow-up-review-panel.tsx"
    ).read_text()
    filters = (
        WEB_ROOT / "app" / "(app)" / "dashboard" / "finding-review-filters.tsx"
    ).read_text()
    api = (WEB_ROOT / "lib" / "api.ts").read_text()
    assert "updateFindingFollowUp(" in modal_m45
    assert "expected_follow_up" not in modal_m45
    assert "writeFindingFollowUpDueConditionally" in modal_m47
    assert "shouldApplyReviewResult" in m44
    assert "shouldApplyReviewResult" in m46
    assert "ownershipRefreshCursor" in m44
    assert "openedPageRef" in m44
    assert "viewRef.current" in m44
    assert "refreshFirstPageCurrent" in m46
    assert m46.count("refreshFirstPageCurrent") >= 5
    assert "viewRef.current" in m46
    assert "assignment_state" not in filters
    assert "Assign owner" in m44
    assert "fetchTargets" in m44
    assert "fetchTargets" in m46
    assert 'setTargetsError("Targets could not be loaded.")' in m44
    assert 'setTargetsError("Targets could not be loaded.")' in m46
    assert "Finding ownership could not be verified." not in filters
    assert "Finding follow-up review could not be loaded." not in filters
    assert "No findings match the selected filters." in m44
    assert "No active findings." in m44
    assert "No active findings match the selected follow-up filters." in m46
    assert "No matching findings." in m46
    assert 'setTargetId("")' in m44
    assert 'setTargetId("")' in m46
    assert "appendReviewFilters" in api
    assert 'params.set("severity", "all")' not in api
    assert OMITTED_FILTER_TOKEN == "*"
