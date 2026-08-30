from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from app.models.asset import Asset
from app.models.audit import AuditEvent
from app.models.candidate import SecurityCandidate
from app.models.finding import Finding
from app.models.finding_follow_up import FindingFollowUpChange
from app.models.operation import Operation
from app.models.report import AssessmentReport
from app.models.target import AuthorizedTarget
from app.models.validation import ValidationAttempt
from app.services.clerk import ClerkOrgMembership, ClerkUserInfo
from app.services.organization_members import INVALID_MEMBER_CURSOR_DETAIL
from sqlalchemy import func, select
from tests.test_reports import _generate, _operation_with_open_finding


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _ids(client, token: str) -> tuple[UUID, UUID]:
    response = client.get("/v1/me", headers=_auth(token))
    assert response.status_code == 200, response.text
    body = response.json()
    return UUID(body["id"]), UUID(body["active_organization_id"])


def _finding(db, *, organization_id: UUID, user_id: UUID, status: str = "open") -> Finding:
    suffix = uuid4().hex
    target = AuthorizedTarget(
        organization_id=organization_id,
        created_by_user_id=user_id,
        domain=f"follow-up-{suffix}.example",
        status="verified",
    )
    db.add(target)
    db.flush()
    operation = Operation(
        organization_id=organization_id,
        target_id=target.id,
        created_by_user_id=user_id,
        status="completed",
        source="manual",
        completed_at=datetime.now(UTC),
    )
    db.add(operation)
    db.flush()
    asset = Asset(
        organization_id=organization_id,
        target_id=target.id,
        hostname=target.domain,
        url=f"https://{target.domain}",
    )
    db.add(asset)
    db.flush()
    candidate = SecurityCandidate(
        organization_id=organization_id,
        operation_id=operation.id,
        asset_id=asset.id,
        candidate_type="staging_dev_exposed",
        title="Staging environment exposed",
        summary="Deterministic rule matched.",
        status="supported",
        evidence={},
    )
    db.add(candidate)
    db.flush()
    validation = ValidationAttempt(
        organization_id=organization_id,
        operation_id=operation.id,
        candidate_id=candidate.id,
        asset_id=asset.id,
        status="supported",
        validation_method="http_recheck",
        summary="Observed.",
        evidence={"observation_ids": []},
        completed_at=datetime.now(UTC),
    )
    db.add(validation)
    db.flush()
    finding = Finding(
        organization_id=organization_id,
        operation_id=operation.id,
        candidate_id=candidate.id,
        asset_id=asset.id,
        title=candidate.title,
        summary=candidate.summary,
        severity="medium",
        status=status,
        business_impact="Catalog impact.",
        remediation_guidance="Catalog guidance.",
        evidence={
            "candidate_type": candidate.candidate_type,
            "provenance": {
                "validation_attempt_id": str(validation.id),
                "observation_ids": [],
            },
        },
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return finding


def _put_follow_up(client, token: str, finding_id: UUID, body: dict):
    return client.put(
        f"/v1/findings/{finding_id}/follow-up",
        headers=_auth(token),
        json=body,
    )


def _members(client, token: str, **params):
    return client.get(
        "/v1/organization-members",
        headers=_auth(token),
        params=params or None,
    )


def _add_clerk_member(
    fake_clerk,
    *,
    clerk_org_id: str,
    role: str = "org:member",
    name: str | None = None,
) -> str:
    clerk_id = f"user_{uuid4().hex}"
    fake_clerk.users[clerk_id] = ClerkUserInfo(
        clerk_user_id=clerk_id,
        email=f"{clerk_id}@example.com",
        name=name or clerk_id[:16],
        email_verified=True,
    )
    fake_clerk.memberships[clerk_id] = [
        ClerkOrgMembership(clerk_org_id=clerk_org_id, org_name="Org A", role=role)
    ]
    return clerk_id


def _assert_no_email(payload) -> None:
    if isinstance(payload, dict):
        assert "email" not in payload
        for value in payload.values():
            _assert_no_email(value)
    elif isinstance(payload, list):
        for item in payload:
            _assert_no_email(item)


def _follow_up_history_count(db) -> int:
    return int(
        db.scalar(select(func.count()).select_from(FindingFollowUpChange)) or 0
    )


def _follow_up_audit_count(db) -> int:
    return int(
        db.scalar(
            select(func.count())
            .select_from(AuditEvent)
            .where(AuditEvent.action == "finding.follow_up_changed")
        )
        or 0
    )


# ----------------------------------------------------------- membership authority


def test_listed_members_are_assignable_and_emails_are_omitted(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    admin_clerk, clerk_org = seed_user_a
    token = make_token(sub=admin_clerk, org_id=clerk_org, org_role="org:admin")
    admin_id, organization_id = _ids(client, token)
    finding = _finding(db_session, organization_id=organization_id, user_id=admin_id)

    extra = [
        _add_clerk_member(fake_clerk, clerk_org_id=clerk_org, name=f"Member {i}")
        for i in range(3)
    ]
    listed = _members(client, token)
    assert listed.status_code == 200, listed.text
    body = listed.json()
    _assert_no_email(body)
    user_ids = {UUID(item["user_id"]) for item in body["items"]}
    assert admin_id in user_ids
    assert len(user_ids) == 1 + len(extra)

    due = "2026-10-01T15:00:00Z"
    for user_id in user_ids:
        response = _put_follow_up(
            client,
            token,
            finding.id,
            {"assigned_to_user_id": str(user_id), "follow_up_due_at": due},
        )
        assert response.status_code == 200, response.text
        payload = response.json()
        _assert_no_email(payload)
        assert payload["owner"]["user_id"] == str(user_id)
        assert payload["owner"]["current_member"] is True

    after = _members(client, token).json()
    assert {item["user_id"] for item in after["items"]} == {
        str(uid) for uid in user_ids
    }


def test_cross_org_and_nonexistent_assignees_rejected(
    client, make_token, seed_user_a, seed_user_b, db_session
):
    admin_clerk, clerk_org = seed_user_a
    token = make_token(sub=admin_clerk, org_id=clerk_org, org_role="org:admin")
    admin_id, organization_id = _ids(client, token)
    finding = _finding(db_session, organization_id=organization_id, user_id=admin_id)

    other_clerk, other_org = seed_user_b
    other_token = make_token(sub=other_clerk, org_id=other_org, org_role="org:admin")
    other_user_id, _ = _ids(client, other_token)

    cross = _put_follow_up(
        client,
        token,
        finding.id,
        {
            "assigned_to_user_id": str(other_user_id),
            "follow_up_due_at": "2026-10-01T15:00:00Z",
        },
    )
    assert cross.status_code == 400, cross.text
    assert "organization member" in cross.json()["error"]["message"].lower()

    missing = _put_follow_up(
        client,
        token,
        finding.id,
        {
            "assigned_to_user_id": str(uuid4()),
            "follow_up_due_at": "2026-10-01T15:00:00Z",
        },
    )
    assert missing.status_code == 400, missing.text
    assert "organization member" in missing.json()["error"]["message"].lower()


def test_organization_members_and_follow_up_require_active_org(
    client, make_token, seed_user_a, db_session
):
    clerk_user, clerk_org = seed_user_a
    with_org = make_token(sub=clerk_user, org_id=clerk_org, org_role="org:admin")
    user_id, organization_id = _ids(client, with_org)
    finding = _finding(db_session, organization_id=organization_id, user_id=user_id)

    bare = make_token(sub=clerk_user)
    assert _members(client, bare).status_code == 400
    assert (
        _put_follow_up(
            client,
            bare,
            finding.id,
            {"assigned_to_user_id": str(user_id), "follow_up_due_at": None},
        ).status_code
        == 400
    )


# ----------------------------------------------------------- member pagination


def test_member_page_size_max_and_malformed_cursor(
    client, make_token, seed_user_a
):
    clerk_user, clerk_org = seed_user_a
    token = make_token(sub=clerk_user, org_id=clerk_org, org_role="org:admin")
    _ids(client, token)

    ok = _members(client, token, page_size=100)
    assert ok.status_code == 200, ok.text
    assert ok.json()["page_size"] == 100

    oversized = _members(client, token, page_size=101)
    assert oversized.status_code == 422

    bad = _members(client, token, cursor="not-a-cursor")
    assert bad.status_code == 400
    assert bad.json()["error"]["message"] == INVALID_MEMBER_CURSOR_DETAIL


def test_member_cursor_walks_without_dupes_or_gaps(
    client, make_token, seed_user_a, fake_clerk
):
    admin_clerk, clerk_org = seed_user_a
    token = make_token(sub=admin_clerk, org_id=clerk_org, org_role="org:admin")
    _ids(client, token)

    for index in range(6):
        _add_clerk_member(
            fake_clerk, clerk_org_id=clerk_org, name=f"Paged {index:02d}"
        )

    page_size = 3
    seen: list[str] = []
    cursor = None
    pages = 0
    while True:
        params = {"page_size": page_size}
        if cursor:
            params["cursor"] = cursor
        response = _members(client, token, **params)
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["page_size"] == page_size
        page_ids = [item["user_id"] for item in body["items"]]
        assert len(page_ids) == len(set(page_ids))
        seen.extend(page_ids)
        pages += 1
        cursor = body["next_cursor"]
        if cursor is None:
            break

    assert pages >= 3
    assert len(seen) == len(set(seen)) == 7
    full = _members(client, token, page_size=100).json()
    assert {item["user_id"] for item in full["items"]} == set(seen)


# ----------------------------------------------------------- due time


def test_due_time_timezone_rules_and_mutations(
    client, make_token, seed_user_a, db_session
):
    clerk_user, clerk_org = seed_user_a
    token = make_token(sub=clerk_user, org_id=clerk_org, org_role="org:admin")
    user_id, organization_id = _ids(client, token)
    finding = _finding(db_session, organization_id=organization_id, user_id=user_id)

    naive = _put_follow_up(
        client,
        token,
        finding.id,
        {
            "assigned_to_user_id": None,
            "follow_up_due_at": "2026-09-01T12:00:00",
        },
    )
    assert naive.status_code == 422, naive.text

    past = "2020-01-15T08:30:00Z"
    set_past = _put_follow_up(
        client,
        token,
        finding.id,
        {"assigned_to_user_id": None, "follow_up_due_at": past},
    )
    assert set_past.status_code == 200, set_past.text
    assert set_past.json()["follow_up_due_at"] is not None
    assert datetime.fromisoformat(
        set_past.json()["follow_up_due_at"].replace("Z", "+00:00")
    ) == datetime(2020, 1, 15, 8, 30, tzinfo=UTC)

    z_due = "2026-09-01T16:00:00Z"
    offset_due = "2026-09-01T12:00:00-04:00"
    first = _put_follow_up(
        client,
        token,
        finding.id,
        {"assigned_to_user_id": str(user_id), "follow_up_due_at": z_due},
    )
    assert first.status_code == 200, first.text
    db_session.expire_all()
    finding_after = db_session.get(Finding, finding.id)
    assert finding_after is not None
    updated_at = finding_after.updated_at
    history_before = _follow_up_history_count(db_session)
    audit_before = _follow_up_audit_count(db_session)

    noop = _put_follow_up(
        client,
        token,
        finding.id,
        {"assigned_to_user_id": str(user_id), "follow_up_due_at": offset_due},
    )
    assert noop.status_code == 200, noop.text
    db_session.expire_all()
    assert _follow_up_history_count(db_session) == history_before
    assert _follow_up_audit_count(db_session) == audit_before
    finding_noop = db_session.get(Finding, finding.id)
    assert finding_noop is not None
    assert finding_noop.updated_at == updated_at

    updated = _put_follow_up(
        client,
        token,
        finding.id,
        {
            "assigned_to_user_id": str(user_id),
            "follow_up_due_at": "2026-11-01T00:00:00Z",
        },
    )
    assert updated.status_code == 200, updated.text
    assert datetime.fromisoformat(
        updated.json()["follow_up_due_at"].replace("Z", "+00:00")
    ) == datetime(2026, 11, 1, tzinfo=UTC)

    cleared = _put_follow_up(
        client,
        token,
        finding.id,
        {"assigned_to_user_id": str(user_id), "follow_up_due_at": None},
    )
    assert cleared.status_code == 200, cleared.text
    assert cleared.json()["follow_up_due_at"] is None
    assert cleared.json()["owner"]["user_id"] == str(user_id)


# ----------------------------------------------------------- owner shape


def test_owner_shape_membership_flag_and_explicit_unassign(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    admin_clerk, clerk_org = seed_user_a
    token = make_token(sub=admin_clerk, org_id=clerk_org, org_role="org:admin")
    admin_id, organization_id = _ids(client, token)
    finding = _finding(db_session, organization_id=organization_id, user_id=admin_id)

    unread = client.get(f"/v1/findings/{finding.id}", headers=_auth(token))
    assert unread.status_code == 200, unread.text
    follow_up = unread.json()["follow_up"]
    assert follow_up["owner"] is None
    assert follow_up["follow_up_due_at"] is None
    _assert_no_email(follow_up)

    member_clerk = _add_clerk_member(
        fake_clerk, clerk_org_id=clerk_org, name="Assignee"
    )
    member_token = make_token(
        sub=member_clerk, org_id=clerk_org, org_role="org:member"
    )
    member_id, _ = _ids(client, member_token)

    assigned = _put_follow_up(
        client,
        token,
        finding.id,
        {
            "assigned_to_user_id": str(member_id),
            "follow_up_due_at": "2026-12-01T00:00:00Z",
        },
    )
    assert assigned.status_code == 200, assigned.text
    assert assigned.json()["owner"] == {
        "user_id": str(member_id),
        "display_name": "Assignee",
        "current_member": True,
    }
    _assert_no_email(assigned.json())

    got = client.get(f"/v1/findings/{finding.id}", headers=_auth(token)).json()
    assert got["follow_up"]["owner"]["current_member"] is True
    _assert_no_email(got["follow_up"])

    inbox = client.get(
        "/v1/findings/inbox",
        headers=_auth(token),
        params={"assigned_to_user_id": str(member_id)},
    )
    assert inbox.status_code == 200, inbox.text
    rows = inbox.json()["items"]
    assert len(rows) == 1
    assert rows[0]["owner"]["user_id"] == str(member_id)
    assert rows[0]["owner"]["current_member"] is True
    _assert_no_email(rows[0]["owner"])

    fake_clerk.memberships[member_clerk] = []
    after_leave = client.get(f"/v1/findings/{finding.id}", headers=_auth(token))
    assert after_leave.status_code == 200, after_leave.text
    owner = after_leave.json()["follow_up"]["owner"]
    assert owner["user_id"] == str(member_id)
    assert owner["current_member"] is False
    _assert_no_email(owner)

    # Restored only so assignability checks stay consistent if later PUTs run;
    # unassign does not require current membership of the previous owner.
    unassigned = _put_follow_up(
        client,
        token,
        finding.id,
        {"assigned_to_user_id": None, "follow_up_due_at": None},
    )
    assert unassigned.status_code == 200, unassigned.text
    assert unassigned.json()["owner"] is None
    assert unassigned.json()["follow_up_due_at"] is None

    cleared = client.get(f"/v1/findings/{finding.id}", headers=_auth(token)).json()
    assert cleared["follow_up"]["owner"] is None


# ----------------------------------------------------------- filter conflict


def test_inbox_assigned_and_unassigned_filters_conflict(
    client, make_token, seed_user_a
):
    clerk_user, clerk_org = seed_user_a
    token = make_token(sub=clerk_user, org_id=clerk_org, org_role="org:admin")
    user_id, _ = _ids(client, token)
    response = client.get(
        "/v1/findings/inbox",
        headers=_auth(token),
        params={"assigned_to_user_id": str(user_id), "unassigned": True},
    )
    assert response.status_code == 422, response.text


# ----------------------------------------------------------- history / timeline


def test_follow_up_history_audit_timeline_and_roles(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    admin_clerk, clerk_org = seed_user_a
    admin_token = make_token(sub=admin_clerk, org_id=clerk_org, org_role="org:admin")
    admin_id, organization_id = _ids(client, admin_token)
    finding = _finding(db_session, organization_id=organization_id, user_id=admin_id)

    member_clerk = _add_clerk_member(
        fake_clerk, clerk_org_id=clerk_org, name="History Member"
    )
    member_token = make_token(
        sub=member_clerk, org_id=clerk_org, org_role="org:member"
    )
    member_id, _ = _ids(client, member_token)

    due = "2026-08-20T18:00:00Z"
    changed = _put_follow_up(
        client,
        admin_token,
        finding.id,
        {"assigned_to_user_id": str(member_id), "follow_up_due_at": due},
    )
    assert changed.status_code == 200, changed.text

    db_session.expire_all()
    rows = list(db_session.scalars(select(FindingFollowUpChange)))
    assert len(rows) == 1
    row = rows[0]
    assert row.finding_id == finding.id
    assert row.changed_by_user_id == admin_id
    assert row.previous_assigned_to_user_id is None
    assert row.new_assigned_to_user_id == member_id
    assert row.previous_due_at is None
    assert row.new_due_at == datetime(2026, 8, 20, 18, 0, tzinfo=UTC)

    audits = list(
        db_session.scalars(
            select(AuditEvent).where(AuditEvent.action == "finding.follow_up_changed")
        )
    )
    assert len(audits) == 1
    assert audits[0].resource_type == "finding_follow_up_change"
    assert audits[0].resource_id == row.id
    assert audits[0].event_metadata["finding_id"] == str(finding.id)
    assert audits[0].event_metadata["follow_up_change_id"] == str(row.id)
    assert audits[0].event_metadata["previous_assigned_to_user_id"] is None
    assert audits[0].event_metadata["new_assigned_to_user_id"] == str(member_id)

    history_before = _follow_up_history_count(db_session)
    audit_before = _follow_up_audit_count(db_session)
    noop = _put_follow_up(
        client,
        admin_token,
        finding.id,
        {
            "assigned_to_user_id": str(member_id),
            "follow_up_due_at": "2026-08-20T14:00:00-04:00",
        },
    )
    assert noop.status_code == 200, noop.text
    db_session.expire_all()
    assert _follow_up_history_count(db_session) == history_before
    assert _follow_up_audit_count(db_session) == audit_before

    timeline = client.get(
        f"/v1/findings/{finding.id}/timeline",
        headers=_auth(admin_token),
        params={"page_size": 50},
    )
    assert timeline.status_code == 200, timeline.text
    follow_up_events = [
        event
        for event in timeline.json()["events"]
        if event["event_type"] == "FOLLOW_UP_CHANGED"
    ]
    assert len(follow_up_events) == 1
    assert follow_up_events[0]["event_id"] == f"follow-up-changed:{row.id}"
    assert follow_up_events[0]["details"]["new_owner"]["user_id"] == str(member_id)

    member_update = _put_follow_up(
        client,
        member_token,
        finding.id,
        {
            "assigned_to_user_id": str(admin_id),
            "follow_up_due_at": "2026-09-01T00:00:00Z",
        },
    )
    assert member_update.status_code == 200, member_update.text
    assert member_update.json()["owner"]["user_id"] == str(admin_id)

    resolved = _finding(
        db_session,
        organization_id=organization_id,
        user_id=admin_id,
        status="resolved",
    )
    blocked = _put_follow_up(
        client,
        admin_token,
        resolved.id,
        {"assigned_to_user_id": str(admin_id), "follow_up_due_at": None},
    )
    assert blocked.status_code == 409, blocked.text


# ----------------------------------------------------------- reports


def test_follow_up_change_does_not_create_new_report_version(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    clerk_user, clerk_org = seed_user_a
    token = make_token(sub=clerk_user, org_id=clerk_org, org_role="org:admin")
    user_id, _ = _ids(client, token)
    _, operation_id, finding_id = _operation_with_open_finding(
        client, token, dns_resolver, engine, "follow-up-report.example"
    )

    first = _generate(client, token, operation_id)
    assert first.status_code == 201, first.text
    first_body = first.json()

    changed = _put_follow_up(
        client,
        token,
        UUID(finding_id),
        {
            "assigned_to_user_id": str(user_id),
            "follow_up_due_at": (
                datetime.now(UTC) + timedelta(days=7)
            ).isoformat().replace("+00:00", "Z"),
        },
    )
    assert changed.status_code == 200, changed.text

    second = _generate(client, token, operation_id)
    assert second.status_code == 200, second.text
    assert second.json()["id"] == first_body["id"]
    assert second.json()["snapshot_digest"] == first_body["snapshot_digest"]
    assert second.json()["report_version"] == first_body["report_version"]
    assert len(list(db_session.scalars(select(AssessmentReport)))) == 1
