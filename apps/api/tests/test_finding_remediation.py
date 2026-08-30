from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from app.core.config import reset_settings_cache
from app.models.asset import Asset
from app.models.audit import AuditEvent
from app.models.candidate import SecurityCandidate
from app.models.finding import Finding
from app.models.finding_remediation import FindingRemediationRevision
from app.models.operation import Operation
from app.models.retest import RetestAttempt
from app.models.target import AuthorizedTarget
from app.models.validation import ValidationAttempt
from app.services.authorization import explicit_org_actor
from app.services.clerk import ClerkOrgMembership, ClerkUserInfo
from app.services.findings.remediation_record import (
    INVALID_REMEDIATION_CURSOR_DETAIL,
    encode_remediation_cursor,
    list_remediation_revisions,
    record_remediation_revision,
)
from sqlalchemy import event, func, select
from sqlalchemy.orm import sessionmaker


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
        domain=f"remediation-{suffix}.example",
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


def _post(client, token: str, finding_id: UUID, summary: str):
    return client.post(
        f"/v1/findings/{finding_id}/remediation",
        headers=_auth(token),
        json={"summary": summary},
    )


def test_admin_records_immutable_revisions_and_audit_excludes_body(
    client, make_token, seed_user_a, db_session
):
    clerk_user, clerk_org = seed_user_a
    token = make_token(sub=clerk_user, org_id=clerk_org, org_role="org:admin")
    user_id, organization_id = _ids(client, token)
    finding = _finding(
        db_session, organization_id=organization_id, user_id=user_id
    )

    secret_body = "  Rotated configuration; literal <script>x</script> {{value}}.  "
    first = _post(client, token, finding.id, secret_body)
    assert first.status_code == 201, first.text
    assert first.json()["revision_number"] == 1
    assert first.json()["summary"] == secret_body.strip()
    assert first.json()["created_by_user_id"] == str(user_id)
    assert first.json()["created_by_name"] == "Alice"
    second = _post(client, token, finding.id, "Correction without overwrite.")
    assert second.status_code == 201, second.text
    assert second.json()["revision_number"] == 2

    db_session.expire_all()
    stored = list(
        db_session.scalars(
            select(FindingRemediationRevision).order_by(
                FindingRemediationRevision.revision_number
            )
        )
    )
    assert [row.summary for row in stored] == [
        secret_body.strip(),
        "Correction without overwrite.",
    ]
    finding_after = db_session.get(Finding, finding.id)
    assert finding_after is not None
    assert finding_after.status == "open"

    audits = list(
        db_session.scalars(
            select(AuditEvent).where(
                AuditEvent.action == "finding.remediation_recorded"
            )
        )
    )
    assert len(audits) == 2
    assert audits[0].actor_type == "user"
    assert audits[0].actor_user_id == user_id
    assert audits[0].resource_type == "finding_remediation_revision"
    assert audits[0].event_metadata["finding_id"] == str(finding.id)
    assert audits[0].event_metadata["remediation_revision_id"] == str(stored[0].id)
    assert audits[0].event_metadata["revision_number"] == 1
    assert secret_body.strip() not in audits[0].summary
    assert secret_body.strip() not in str(audits[0].event_metadata)

    audit_count = len(audits)
    read = client.get(
        f"/v1/findings/{finding.id}/remediation", headers=_auth(token)
    )
    assert read.status_code == 200
    db_session.expire_all()
    assert (
        db_session.scalar(
            select(func.count())
            .select_from(AuditEvent)
            .where(AuditEvent.action == "finding.remediation_recorded")
        )
        == audit_count
    )


def test_member_can_record_but_cross_org_and_unauthenticated_cannot(
    client,
    fake_clerk,
    make_token,
    seed_user_a,
    seed_user_b,
    db_session,
):
    admin_clerk, clerk_org = seed_user_a
    admin_token = make_token(
        sub=admin_clerk, org_id=clerk_org, org_role="org:admin"
    )
    admin_id, organization_id = _ids(client, admin_token)
    finding = _finding(
        db_session, organization_id=organization_id, user_id=admin_id
    )

    member_clerk = f"user_{uuid4().hex}"
    fake_clerk.users[member_clerk] = ClerkUserInfo(
        clerk_user_id=member_clerk,
        email="member@example.com",
        name="Member",
        email_verified=True,
    )
    fake_clerk.memberships[member_clerk] = [
        ClerkOrgMembership(
            clerk_org_id=clerk_org,
            org_name="Org A",
            role="org:member",
        )
    ]
    member_token = make_token(
        sub=member_clerk, org_id=clerk_org, org_role="org:member"
    )
    member_id, _ = _ids(client, member_token)
    response = _post(client, member_token, finding.id, "Member-authored change.")
    assert response.status_code == 201, response.text
    assert response.json()["created_by_user_id"] == str(member_id)

    other_clerk, other_org = seed_user_b
    other_token = make_token(
        sub=other_clerk, org_id=other_org, org_role="org:admin"
    )
    _ids(client, other_token)
    assert _post(client, other_token, finding.id, "Cross org").status_code == 404
    assert (
        client.get(
            f"/v1/findings/{finding.id}/remediation",
            headers=_auth(other_token),
            params={
                "cursor": encode_remediation_cursor(
                    revision_number=1,
                    revision_id=UUID(response.json()["id"]),
                )
            },
        ).status_code
        == 404
    )
    assert _post(client, "", finding.id, "No auth").status_code == 401


@pytest.mark.parametrize(
    "summary",
    [
        "한국어 변경 기록",
        "Исправлена конфигурация",
        "Διορθώθηκε η ρύθμιση",
        "設定を更新しました",
        "تم تحديث الإعداد",
        "Updated safely 😀",
        "Deployment reviewed 👩‍💻",
    ],
)
def test_broad_unicode_round_trips(
    summary, client, make_token, seed_user_a, db_session
):
    clerk_user, clerk_org = seed_user_a
    token = make_token(sub=clerk_user, org_id=clerk_org)
    user_id, organization_id = _ids(client, token)
    finding = _finding(
        db_session, organization_id=organization_id, user_id=user_id
    )
    response = _post(client, token, finding.id, summary)
    assert response.status_code == 201, response.text
    assert response.json()["summary"] == summary


@pytest.mark.parametrize(
    "summary",
    ["unsafe\u202evalue", "bad\u0007value", "bad\u0085value", "bad\u0085"],
)
def test_bidi_spoofing_and_controls_are_rejected(
    summary, client, make_token, seed_user_a, db_session
):
    clerk_user, clerk_org = seed_user_a
    token = make_token(sub=clerk_user, org_id=clerk_org)
    user_id, organization_id = _ids(client, token)
    finding = _finding(
        db_session, organization_id=organization_id, user_id=user_id
    )
    response = _post(client, token, finding.id, summary)
    assert response.status_code == 422


def test_summary_length_empty_and_resolved_rules(
    client, make_token, seed_user_a, db_session
):
    clerk_user, clerk_org = seed_user_a
    token = make_token(sub=clerk_user, org_id=clerk_org)
    user_id, organization_id = _ids(client, token)
    finding = _finding(
        db_session, organization_id=organization_id, user_id=user_id
    )
    assert _post(client, token, finding.id, " \n\t ").status_code == 422
    assert _post(client, token, finding.id, "x" * 4000).status_code == 201
    assert _post(client, token, finding.id, "x" * 4001).status_code == 422

    resolved = _finding(
        db_session,
        organization_id=organization_id,
        user_id=user_id,
        status="resolved",
    )
    response = _post(client, token, resolved.id, "Too late")
    assert response.status_code == 409


def test_dedicated_remediation_rate_limit(
    client, make_token, seed_user_a, db_session, monkeypatch
):
    clerk_user, clerk_org = seed_user_a
    token = make_token(sub=clerk_user, org_id=clerk_org)
    user_id, organization_id = _ids(client, token)
    finding = _finding(
        db_session, organization_id=organization_id, user_id=user_id
    )
    monkeypatch.setenv("RATE_LIMIT_FINDING_REMEDIATION", "1")
    reset_settings_cache()
    try:
        assert _post(client, token, finding.id, "First").status_code == 201
        limited = _post(client, token, finding.id, "Second")
        assert limited.status_code == 429
        assert int(limited.headers["retry-after"]) >= 1
    finally:
        reset_settings_cache()


def test_history_cursor_retrieves_every_revision_without_duplicates(
    client, make_token, seed_user_a, db_session
):
    clerk_user, clerk_org = seed_user_a
    token = make_token(sub=clerk_user, org_id=clerk_org)
    user_id, organization_id = _ids(client, token)
    finding = _finding(
        db_session, organization_id=organization_id, user_id=user_id
    )
    rows = [
        FindingRemediationRevision(
            organization_id=organization_id,
            finding_id=finding.id,
            revision_number=number,
            summary=f"Revision {number}",
            created_by_user_id=user_id,
        )
        for number in range(1, 56)
    ]
    db_session.add_all(rows)
    db_session.commit()

    seen: list[int] = []
    cursor = None
    first_latest = None
    while True:
        response = client.get(
            f"/v1/findings/{finding.id}/remediation",
            headers=_auth(token),
            params={"page_size": 20, **({"cursor": cursor} if cursor else {})},
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["revision_count"] == 55
        assert body["page_size"] == 20
        if first_latest is None:
            first_latest = body["latest"]
        assert body["latest"] == first_latest
        seen.extend(row["revision_number"] for row in body["revisions"])
        cursor = body["next_cursor"]
        if cursor is None:
            break

    assert seen == list(range(55, 0, -1))
    assert len(seen) == len(set(seen))
    malformed = client.get(
        f"/v1/findings/{finding.id}/remediation",
        headers=_auth(token),
        params={"cursor": "not-a-cursor"},
    )
    assert malformed.status_code == 400
    assert malformed.json()["error"]["message"] == INVALID_REMEDIATION_CURSOR_DETAIL
    assert (
        client.get(
            f"/v1/findings/{finding.id}/remediation",
            headers=_auth(token),
            params={"page_size": 51},
        ).status_code
        == 422
    )

    assert (
        client.patch(
            f"/v1/findings/{finding.id}/remediation/{rows[0].id}",
            headers=_auth(token),
            json={"summary": "overwrite"},
        ).status_code
        == 404
    )
    assert (
        client.delete(
            f"/v1/findings/{finding.id}/remediation/{rows[0].id}",
            headers=_auth(token),
        ).status_code
        == 404
    )


def test_history_queries_are_bounded_and_author_lookup_is_not_n_plus_one(
    client, make_token, seed_user_a, db_session, engine
):
    clerk_user, clerk_org = seed_user_a
    token = make_token(sub=clerk_user, org_id=clerk_org)
    user_id, organization_id = _ids(client, token)
    finding = _finding(
        db_session, organization_id=organization_id, user_id=user_id
    )
    db_session.add_all(
        [
            FindingRemediationRevision(
                organization_id=organization_id,
                finding_id=finding.id,
                revision_number=number,
                summary=f"Revision {number}",
                created_by_user_id=user_id,
            )
            for number in range(1, 31)
        ]
    )
    db_session.commit()

    statements: list[str] = []

    def capture(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement)

    session = sessionmaker(bind=engine, autocommit=False, autoflush=False)()
    event.listen(engine, "before_cursor_execute", capture)
    try:
        result = list_remediation_revisions(
            session,
            finding_id=finding.id,
            user_id=user_id,
            page_size=20,
        )
    finally:
        event.remove(engine, "before_cursor_execute", capture)
        session.close()
    assert len(result.revisions) == 20
    selects = [
        statement
        for statement in statements
        if statement.lstrip().lower().startswith("select")
    ]
    assert len(selects) == 5
    assert sum(" JOIN users " in statement for statement in selects) == 1
    joined = " ".join(selects).lower()
    assert "users.email" not in joined
    assert "finding_remediation_revisions.summary" in joined


def test_concurrent_submissions_are_consecutive_and_session_recovers(
    client, make_token, seed_user_a, db_session, engine
):
    clerk_user, clerk_org = seed_user_a
    token = make_token(sub=clerk_user, org_id=clerk_org)
    user_id, organization_id = _ids(client, token)
    finding = _finding(
        db_session, organization_id=organization_id, user_id=user_id
    )
    finding_id = finding.id
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    actor = explicit_org_actor(
        user_id=user_id,
        organization_id=organization_id,
        normalized_role="member",
    )

    def submit(summary: str) -> int:
        session = factory()
        try:
            current = session.get(Finding, finding_id)
            assert current is not None
            created = record_remediation_revision(
                session,
                finding=current,
                summary=summary,
                actor=actor,
            )
            # The committed session remains usable after allocation.
            assert session.scalar(select(func.count()).select_from(AuditEvent)) >= 1
            return created.revision.revision_number
        finally:
            session.close()

    with ThreadPoolExecutor(max_workers=2) as executor:
        numbers = sorted(executor.map(submit, ["First concurrent", "Second concurrent"]))

    assert numbers == [1, 2]
    db_session.expire_all()
    stored = list(
        db_session.scalars(
            select(FindingRemediationRevision).where(
                FindingRemediationRevision.finding_id == finding_id
            )
        )
    )
    assert len(stored) == 2
    assert {row.summary for row in stored} == {
        "First concurrent",
        "Second concurrent",
    }


def test_unique_constraint_retry_uses_recovered_savepoint(
    client, make_token, seed_user_a, db_session, monkeypatch
):
    clerk_user, clerk_org = seed_user_a
    token = make_token(sub=clerk_user, org_id=clerk_org)
    user_id, organization_id = _ids(client, token)
    finding = _finding(
        db_session, organization_id=organization_id, user_id=user_id
    )
    db_session.add(
        FindingRemediationRevision(
            organization_id=organization_id,
            finding_id=finding.id,
            revision_number=1,
            summary="Existing revision",
            created_by_user_id=user_id,
        )
    )
    db_session.commit()

    original_scalar = db_session.scalar
    stale_max_returned = False

    def scalar_with_one_stale_allocation(statement, *args, **kwargs):
        nonlocal stale_max_returned
        if (
            not stale_max_returned
            and "max(finding_remediation_revisions.revision_number)"
            in str(statement)
        ):
            stale_max_returned = True
            return 1
        return original_scalar(statement, *args, **kwargs)

    monkeypatch.setattr(db_session, "scalar", scalar_with_one_stale_allocation)
    actor = explicit_org_actor(
        user_id=user_id,
        organization_id=organization_id,
        normalized_role="member",
    )
    created = record_remediation_revision(
        db_session,
        finding=finding,
        summary="Survived unique conflict",
        actor=actor,
    )
    assert stale_max_returned is True
    assert created.revision.revision_number == 2
    # The same Session remains transactionally usable after the savepoint retry.
    assert (
        db_session.scalar(
            select(func.count())
            .select_from(FindingRemediationRevision)
            .where(FindingRemediationRevision.finding_id == finding.id)
        )
        == 2
    )


def test_ready_for_retest_requires_record_and_record_does_not_queue_or_resolve(
    client, make_token, seed_user_a, db_session
):
    clerk_user, clerk_org = seed_user_a
    token = make_token(sub=clerk_user, org_id=clerk_org)
    user_id, organization_id = _ids(client, token)
    finding = _finding(
        db_session,
        organization_id=organization_id,
        user_id=user_id,
        status="in_progress",
    )
    blocked = client.post(
        f"/v1/findings/{finding.id}/ready-for-retest",
        headers=_auth(token),
    )
    assert blocked.status_code == 400
    assert (
        blocked.json()["error"]["message"]
        == "Record what you changed before requesting a retest."
    )
    remediation_body = "Configuration updated."
    assert _post(client, token, finding.id, remediation_body).status_code == 201
    inbox = client.get("/v1/findings/inbox", headers=_auth(token))
    assert inbox.status_code == 200, inbox.text
    inbox_row = inbox.json()["items"][0]
    assert inbox_row["remediation"]["revision_count"] == 1
    assert inbox_row["remediation"]["latest_recorded_at"]
    assert remediation_body not in inbox.text
    assert inbox_row["retests"]["current_state"] == "none"
    ready = client.post(
        f"/v1/findings/{finding.id}/ready-for-retest",
        headers=_auth(token),
    )
    assert ready.status_code == 200, ready.text
    assert ready.json()["status"] == "ready_for_retest"
    assert ready.json()["resolved_at"] is None
    assert (
        db_session.scalar(
            select(func.count())
            .select_from(RetestAttempt)
            .where(RetestAttempt.finding_id == finding.id)
        )
        == 0
    )
