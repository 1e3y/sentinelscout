from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import event, func, select

from app.models.alert import NotificationOutbox
from app.models.asset import Asset
from app.models.audit import AuditEvent
from app.models.candidate import SecurityCandidate
from app.models.finding import Finding
from app.models.finding_remediation import FindingRemediationRevision
from app.models.operation import Operation
from app.models.report import AssessmentReport
from app.models.report_delivery import AssessmentReportDeliveryOutbox
from app.models.report_generation_job import AssessmentReportGenerationJob
from app.models.report_share import AssessmentReportShare
from app.models.retest import RetestAttempt
from app.models.target import AuthorizedTarget
from app.models.validation import ValidationAttempt
from app.services.clerk import ClerkOrgMembership, ClerkUserInfo
from app.services.findings.timeline import (
    INVALID_TIMELINE_CURSOR_DETAIL,
    list_finding_timeline,
)


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _ids(client, token: str) -> tuple[UUID, UUID]:
    response = client.get("/v1/me", headers=_auth(token))
    assert response.status_code == 200, response.text
    body = response.json()
    return UUID(body["id"]), UUID(body["active_organization_id"])


def _add_member(fake_clerk, make_token, clerk_org: str) -> str:
    clerk_user = f"user_{uuid4().hex}"
    fake_clerk.users[clerk_user] = ClerkUserInfo(
        clerk_user_id=clerk_user,
        email=f"{clerk_user}@example.com",
        name="Second Member",
        email_verified=True,
    )
    fake_clerk.memberships[clerk_user] = [
        ClerkOrgMembership(
            clerk_org_id=clerk_org,
            org_name="Org A",
            role="org:member",
        )
    ]
    return make_token(sub=clerk_user, org_id=clerk_org, org_role="org:member")


def _finding(
    db,
    *,
    organization_id: UUID,
    user_id: UUID,
    status: str = "open",
    created_at: datetime | None = None,
) -> Finding:
    suffix = uuid4().hex
    target = AuthorizedTarget(
        organization_id=organization_id,
        created_by_user_id=user_id,
        domain=f"timeline-{suffix}.example",
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
        validation_method="staging_indicator_confirmation",
        summary="Observed.",
        evidence={"observation_ids": []},
        completed_at=datetime.now(UTC),
    )
    db.add(validation)
    db.flush()
    moment = created_at or datetime.now(UTC)
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
        created_at=moment,
        updated_at=moment,
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return finding


def _timeline(client, token: str, finding_id: UUID, **params):
    return client.get(
        f"/v1/findings/{finding_id}/timeline",
        headers=_auth(token),
        params=params or None,
    )


def _workflow_audit(
    db,
    *,
    finding: Finding,
    user_id: UUID,
    action: str,
    previous_status: str,
    new_status: str,
    created_at: datetime | None = None,
) -> AuditEvent:
    row = AuditEvent(
        organization_id=finding.organization_id,
        actor_type="user",
        actor_user_id=user_id,
        action=action,
        resource_type="finding",
        resource_id=finding.id,
        summary="Workflow transition.",
        event_metadata={
            "finding_id": str(finding.id),
            "previous_status": previous_status,
            "new_status": new_status,
        },
        created_at=created_at or datetime.now(UTC),
    )
    db.add(row)
    db.flush()
    return row


def _attempt(
    db,
    *,
    finding: Finding,
    status: str,
    created_at: datetime,
    completed_at: datetime | None,
) -> RetestAttempt:
    validation_id = UUID(finding.evidence["provenance"]["validation_attempt_id"])
    attempt = RetestAttempt(
        organization_id=finding.organization_id,
        finding_id=finding.id,
        candidate_id=finding.candidate_id,
        asset_id=finding.asset_id,
        original_validation_attempt_id=validation_id,
        status=status,
        method="staging_indicator_confirmation",
        summary=f"Stored {status} summary.",
        evidence={"secret": "must-not-leak"},
        created_at=created_at,
        completed_at=completed_at,
    )
    db.add(attempt)
    db.flush()
    return attempt


def test_complete_timeline_uses_canonical_sources_and_truthful_provenance(
    client, make_token, seed_user_a, db_session
):
    clerk_user, clerk_org = seed_user_a
    token = make_token(sub=clerk_user, org_id=clerk_org, org_role="org:admin")
    user_id, organization_id = _ids(client, token)
    promoted_at = datetime.now(UTC) - timedelta(days=1)
    finding = _finding(
        db_session,
        organization_id=organization_id,
        user_id=user_id,
        created_at=promoted_at,
    )

    assert (
        client.post(
            f"/v1/findings/{finding.id}/start-remediation", headers=_auth(token)
        ).status_code
        == 200
    )
    for summary in ("Changed the exposed configuration.", "Added a deny rule."):
        response = client.post(
            f"/v1/findings/{finding.id}/remediation",
            headers=_auth(token),
            json={"summary": summary},
        )
        assert response.status_code == 201, response.text
    assert (
        client.post(
            f"/v1/findings/{finding.id}/ready-for-retest", headers=_auth(token)
        ).status_code
        == 200
    )
    queued = client.post(
        f"/v1/findings/{finding.id}/retest", headers=_auth(token)
    )
    assert queued.status_code == 202, queued.text

    attempt = db_session.get(RetestAttempt, UUID(queued.json()["id"]))
    assert attempt is not None
    completed_at = datetime.now(UTC)
    attempt.status = "passed"
    attempt.summary = "The condition was no longer observed."
    attempt.completed_at = completed_at
    refreshed = db_session.get(Finding, finding.id)
    assert refreshed is not None
    refreshed.status = "resolved"
    refreshed.resolved_at = completed_at
    refreshed.updated_at = completed_at
    refreshed.evidence = {
        **refreshed.evidence,
        "resolving_retest_id": str(attempt.id),
        "resolved_via": "retest_passed",
    }
    db_session.add_all(
        [
            AuditEvent(
                organization_id=organization_id,
                actor_type="worker",
                actor_user_id=user_id,
                action="retest.completed",
                resource_type="retest_attempt",
                resource_id=attempt.id,
                summary="Duplicate representation of the terminal attempt.",
                event_metadata={
                    "finding_id": str(finding.id),
                    "retest_id": str(attempt.id),
                    "retest_status": "passed",
                },
            ),
            AuditEvent(
                organization_id=organization_id,
                actor_type="worker",
                actor_user_id=user_id,
                action="finding.resolved",
                resource_type="finding",
                resource_id=finding.id,
                summary="Duplicate representation of persisted resolution.",
                event_metadata={
                    "finding_id": str(finding.id),
                    "retest_id": str(attempt.id),
                    "status": "resolved",
                },
            ),
        ]
    )
    db_session.commit()

    response = _timeline(client, token, finding.id, page_size=50)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["history_completeness"] == "complete"
    assert body["history_gaps"] == []
    assert body["current_retest_state"] == "passed"
    assert body["remediation_revision_count"] == 2

    events = body["events"]
    event_types = [item["event_type"] for item in events]
    assert event_types.count("SUPPORTED_FINDING_PROMOTED") == 1
    assert event_types.count("REMEDIATION_STARTED") == 1
    assert event_types.count("REMEDIATION_REVISION_RECORDED") == 2
    assert event_types.count("READY_FOR_RETEST") == 1
    assert event_types.count("RETEST_QUEUED") == 1
    assert event_types.count("RETEST_COMPLETED") == 1
    assert event_types.count("FINDING_RESOLVED") == 1

    by_type = {item["event_type"]: item for item in events}
    assert datetime.fromisoformat(
        by_type["SUPPORTED_FINDING_PROMOTED"]["occurred_at"]
    ) == promoted_at
    assert "first detected" not in response.text.lower()
    assert by_type["RETEST_QUEUED"]["provenance"] == "human_workflow"
    assert by_type["RETEST_QUEUED"]["title"] == "Retest requested"
    assert by_type["RETEST_QUEUED"]["actor"]["user_id"] == str(user_id)
    assert by_type["RETEST_COMPLETED"]["provenance"] == "scout_retest"
    assert by_type["RETEST_COMPLETED"]["actor"] == {
        "actor_type": "worker",
        "user_id": None,
        "display_name": None,
    }
    assert by_type["FINDING_RESOLVED"]["provenance"] == "finding_record"
    assert (
        by_type["FINDING_RESOLVED"]["details"]["statement"]
        == "Passing retest confirmed the condition was no longer observed."
    )
    assert "must-not-leak" not in response.text
    assert "alice@example.com" not in response.text
    assert "metadata" not in response.text
    summaries = {
        event["details"]["summary"]
        for event in events
        if event["event_type"] == "REMEDIATION_REVISION_RECORDED"
    }
    assert summaries == {
        "Changed the exposed configuration.",
        "Added a deny rule.",
    }


def test_exact_retest_request_actor_link_never_uses_timestamp_proximity(
    client,
    fake_clerk,
    make_token,
    seed_user_a,
    db_session,
):
    clerk_admin, clerk_org = seed_user_a
    admin_token = make_token(
        sub=clerk_admin, org_id=clerk_org, org_role="org:admin"
    )
    admin_id, organization_id = _ids(client, admin_token)
    member_token = _add_member(fake_clerk, make_token, clerk_org)
    member_id, _ = _ids(client, member_token)
    finding = _finding(
        db_session, organization_id=organization_id, user_id=admin_id
    )
    assert client.post(
        f"/v1/findings/{finding.id}/start-remediation", headers=_auth(admin_token)
    ).status_code == 200
    assert client.post(
        f"/v1/findings/{finding.id}/remediation",
        headers=_auth(admin_token),
        json={"summary": "Recorded work."},
    ).status_code == 201
    assert client.post(
        f"/v1/findings/{finding.id}/ready-for-retest", headers=_auth(admin_token)
    ).status_code == 200

    first_response = client.post(
        f"/v1/findings/{finding.id}/retest", headers=_auth(admin_token)
    )
    first = db_session.get(RetestAttempt, UUID(first_response.json()["id"]))
    assert first is not None
    first.status = "failed"
    first.completed_at = datetime.now(UTC)
    db_session.commit()

    second_response = client.post(
        f"/v1/findings/{finding.id}/retest", headers=_auth(member_token)
    )
    second = db_session.get(RetestAttempt, UUID(second_response.json()["id"]))
    assert second is not None
    second.status = "failed"
    second.completed_at = datetime.now(UTC)
    db_session.commit()

    third = _attempt(
        db_session,
        finding=finding,
        status="running",
        created_at=datetime.now(UTC),
        completed_at=None,
    )
    db_session.add(
        AuditEvent(
            organization_id=organization_id,
            actor_type="user",
            actor_user_id=admin_id,
            action="retest.requested",
            resource_type="retest_attempt",
            resource_id=third.id,
            summary="Deliberately mismatched exact relationship.",
            event_metadata={
                "finding_id": str(finding.id),
                "retest_id": str(second.id),
            },
            created_at=third.created_at,
        )
    )
    db_session.commit()

    response = _timeline(client, admin_token, finding.id, page_size=50)
    assert response.status_code == 200, response.text
    assert _timeline(client, member_token, finding.id).status_code == 200
    queued = {
        event["details"]["retest_attempt_id"]: event
        for event in response.json()["events"]
        if event["event_type"] == "RETEST_QUEUED"
    }
    assert queued[str(first.id)]["actor"]["user_id"] == str(admin_id)
    assert queued[str(second.id)]["actor"]["user_id"] == str(member_id)
    assert queued[str(third.id)]["actor"] is None
    assert queued[str(third.id)]["actor"] is not queued[str(first.id)]["actor"]


def test_active_retest_outranks_older_failure_in_m30_and_m32(
    client, make_token, seed_user_a, db_session
):
    clerk_user, clerk_org = seed_user_a
    token = make_token(sub=clerk_user, org_id=clerk_org, org_role="org:admin")
    user_id, organization_id = _ids(client, token)
    finding = _finding(
        db_session, organization_id=organization_id, user_id=user_id
    )
    finding.status = "ready_for_retest"
    _workflow_audit(
        db_session,
        finding=finding,
        user_id=user_id,
        action="finding.remediation_started",
        previous_status="open",
        new_status="in_progress",
    )
    _workflow_audit(
        db_session,
        finding=finding,
        user_id=user_id,
        action="finding.ready_for_retest",
        previous_status="in_progress",
        new_status="ready_for_retest",
    )
    failed = _attempt(
        db_session,
        finding=finding,
        status="failed",
        created_at=datetime.now(UTC) - timedelta(hours=1),
        completed_at=datetime.now(UTC) - timedelta(minutes=59),
    )
    _attempt(
        db_session,
        finding=finding,
        status="running",
        created_at=datetime.now(UTC),
        completed_at=None,
    )
    db_session.commit()

    timeline = _timeline(client, token, finding.id).json()
    inbox = client.get("/v1/findings/inbox", headers=_auth(token)).json()
    inbox_row = next(
        item for item in inbox["items"] if item["finding_id"] == str(finding.id)
    )
    assert timeline["current_retest_state"] == "in_progress"
    assert inbox_row["retests"]["current_state"] == "in_progress"
    assert any(
        event["event_type"] == "RETEST_COMPLETED"
        and event["details"]["retest_attempt_id"] == str(failed.id)
        and event["details"]["status"] == "failed"
        for event in timeline["events"]
    )


@pytest.mark.parametrize(
    ("attempt_status", "expected_state"),
    [
        (None, "none"),
        ("pending", "in_progress"),
        ("passed", "passed"),
        ("failed", "failed"),
        ("inconclusive", "inconclusive"),
        ("error", "error"),
    ],
)
def test_m30_and_m32_share_every_current_retest_state(
    client,
    make_token,
    seed_user_a,
    db_session,
    attempt_status,
    expected_state,
):
    clerk_user, clerk_org = seed_user_a
    token = make_token(sub=clerk_user, org_id=clerk_org, org_role="org:admin")
    user_id, organization_id = _ids(client, token)
    finding = _finding(
        db_session, organization_id=organization_id, user_id=user_id
    )
    if attempt_status is not None:
        _attempt(
            db_session,
            finding=finding,
            status=attempt_status,
            created_at=datetime.now(UTC),
            completed_at=(
                None
                if attempt_status in {"pending", "running"}
                else datetime.now(UTC)
            ),
        )
        db_session.commit()

    timeline = _timeline(client, token, finding.id).json()
    inbox = client.get("/v1/findings/inbox", headers=_auth(token)).json()
    inbox_row = next(
        item for item in inbox["items"] if item["finding_id"] == str(finding.id)
    )
    assert timeline["current_retest_state"] == expected_state
    assert inbox_row["retests"]["current_state"] == expected_state


def test_history_gaps_explain_missing_and_ambiguous_durable_sources(
    client, make_token, seed_user_a, db_session
):
    clerk_user, clerk_org = seed_user_a
    token = make_token(sub=clerk_user, org_id=clerk_org, org_role="org:admin")
    user_id, organization_id = _ids(client, token)
    finding = _finding(
        db_session, organization_id=organization_id, user_id=user_id
    )
    finding.status = "resolved"
    finding.resolved_at = datetime.now(UTC)
    _attempt(
        db_session,
        finding=finding,
        status="error",
        created_at=datetime.now(UTC) - timedelta(minutes=1),
        completed_at=None,
    )
    db_session.commit()

    body = _timeline(client, token, finding.id).json()
    assert body["history_completeness"] == "partial"
    assert set(body["history_gaps"]) == {
        "remediation_started_timestamp_unavailable",
        "ready_for_retest_timestamp_unavailable",
        "resolution_retest_link_unavailable",
        "retest_completion_timestamp_unavailable",
    }
    types = {event["event_type"] for event in body["events"]}
    assert "REMEDIATION_STARTED" not in types
    assert "READY_FOR_RETEST" not in types
    assert "RETEST_COMPLETED" not in types

    finding.resolved_at = None
    db_session.commit()
    missing_resolution_time = _timeline(client, token, finding.id).json()
    assert (
        "resolution_timestamp_unavailable"
        in missing_resolution_time["history_gaps"]
    )

    finding.status = "ready_for_retest"
    for offset in (1, 2):
        _workflow_audit(
            db_session,
            finding=finding,
            user_id=user_id,
            action="finding.remediation_started",
            previous_status="open",
            new_status="in_progress",
            created_at=finding.created_at + timedelta(seconds=offset),
        )
    _workflow_audit(
        db_session,
        finding=finding,
        user_id=user_id,
        action="finding.ready_for_retest",
        previous_status="in_progress",
        new_status="ready_for_retest",
        created_at=finding.created_at + timedelta(seconds=3),
    )
    db_session.commit()
    duplicate_body = _timeline(client, token, finding.id).json()
    assert "workflow_transition_ambiguous" in duplicate_body["history_gaps"]
    assert (
        sum(
            event["event_type"] == "REMEDIATION_STARTED"
            for event in duplicate_body["events"]
        )
        == 1
    )


def test_mixed_timeline_cursor_walks_every_event_and_rejects_bad_inputs(
    client, make_token, seed_user_a, db_session
):
    clerk_user, clerk_org = seed_user_a
    token = make_token(sub=clerk_user, org_id=clerk_org, org_role="org:admin")
    user_id, organization_id = _ids(client, token)
    finding = _finding(
        db_session, organization_id=organization_id, user_id=user_id
    )
    shared_time = datetime.now(UTC)
    for number in range(1, 56):
        db_session.add(
            FindingRemediationRevision(
                organization_id=organization_id,
                finding_id=finding.id,
                revision_number=number,
                summary=f"Revision {number}",
                created_by_user_id=user_id,
                created_at=shared_time,
            )
        )
    db_session.commit()

    seen: list[str] = []
    cursor = None
    while True:
        response = _timeline(
            client,
            token,
            finding.id,
            page_size=20,
            **({"cursor": cursor} if cursor else {}),
        )
        assert response.status_code == 200, response.text
        body = response.json()
        seen.extend(event["event_id"] for event in body["events"])
        cursor = body["next_cursor"]
        if cursor is None:
            break
    assert len(seen) == 56
    assert len(set(seen)) == 56
    revision_ids = [
        UUID(event_id.split(":", 1)[1])
        for event_id in seen
        if event_id.startswith("remediation-revision:")
    ]
    assert revision_ids == sorted(revision_ids, reverse=True)

    malformed = _timeline(client, token, finding.id, cursor="not-a-cursor")
    assert malformed.status_code == 400
    assert malformed.json()["error"]["message"] == INVALID_TIMELINE_CURSOR_DETAIL
    assert _timeline(client, token, finding.id, page_size=51).status_code == 422


def test_timeline_active_org_rbac_and_read_only_persistence(
    client,
    make_token,
    seed_user_a,
    seed_user_b,
    db_session,
):
    clerk_a, org_a = seed_user_a
    token_a = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    user_a, organization_a = _ids(client, token_a)
    finding = _finding(
        db_session, organization_id=organization_a, user_id=user_a
    )
    clerk_b, org_b = seed_user_b
    token_b = make_token(sub=clerk_b, org_id=org_b, org_role="org:admin")
    _ids(client, token_b)

    before = db_session.execute(
        select(
            Finding.status,
            Finding.updated_at,
            Finding.resolved_at,
        ).where(Finding.id == finding.id)
    ).one()
    counts_before = (
        db_session.scalar(select(func.count()).select_from(AuditEvent)),
        db_session.scalar(
            select(func.count()).select_from(FindingRemediationRevision)
        ),
        db_session.scalar(select(func.count()).select_from(RetestAttempt)),
        db_session.scalar(select(func.count()).select_from(AssessmentReport)),
        db_session.scalar(
            select(func.count()).select_from(AssessmentReportGenerationJob)
        ),
        db_session.scalar(select(func.count()).select_from(AssessmentReportShare)),
        db_session.scalar(
            select(func.count()).select_from(AssessmentReportDeliveryOutbox)
        ),
        db_session.scalar(select(func.count()).select_from(NotificationOutbox)),
    )
    assert _timeline(client, token_a, finding.id).status_code == 200
    assert (
        _timeline(client, token_b, finding.id, cursor="not-a-cursor").status_code
        == 404
    )
    assert client.get(f"/v1/findings/{finding.id}/timeline").status_code == 401
    candidate_only = _timeline(client, token_a, finding.candidate_id)
    assert candidate_only.status_code == 404
    db_session.expire_all()
    after = db_session.execute(
        select(
            Finding.status,
            Finding.updated_at,
            Finding.resolved_at,
        ).where(Finding.id == finding.id)
    ).one()
    counts_after = (
        db_session.scalar(select(func.count()).select_from(AuditEvent)),
        db_session.scalar(
            select(func.count()).select_from(FindingRemediationRevision)
        ),
        db_session.scalar(select(func.count()).select_from(RetestAttempt)),
        db_session.scalar(select(func.count()).select_from(AssessmentReport)),
        db_session.scalar(
            select(func.count()).select_from(AssessmentReportGenerationJob)
        ),
        db_session.scalar(select(func.count()).select_from(AssessmentReportShare)),
        db_session.scalar(
            select(func.count()).select_from(AssessmentReportDeliveryOutbox)
        ),
        db_session.scalar(select(func.count()).select_from(NotificationOutbox)),
    )
    assert after == before
    assert counts_after == counts_before


def test_timeline_service_query_count_is_fixed_and_selects_no_sensitive_tables(
    client, make_token, seed_user_a, db_session, engine
):
    clerk_user, clerk_org = seed_user_a
    token = make_token(sub=clerk_user, org_id=clerk_org, org_role="org:admin")
    user_id, organization_id = _ids(client, token)
    finding = _finding(
        db_session, organization_id=organization_id, user_id=user_id
    )
    for number in range(1, 31):
        db_session.add(
            FindingRemediationRevision(
                organization_id=organization_id,
                finding_id=finding.id,
                revision_number=number,
                summary=f"Revision {number}",
                created_by_user_id=user_id,
            )
        )
    db_session.commit()
    finding_id = finding.id

    statements: list[str] = []

    def capture(_conn, _cursor, statement, _parameters, _context, _executemany):
        if statement.lstrip().upper().startswith("SELECT"):
            statements.append(statement.lower())

    event.listen(engine, "before_cursor_execute", capture)
    try:
        one = list_finding_timeline(
            db_session,
            finding_id=finding_id,
            organization_id=organization_id,
            page_size=1,
        )
        count_one = len(statements)
        statements.clear()
        fifty = list_finding_timeline(
            db_session,
            finding_id=finding_id,
            organization_id=organization_id,
            page_size=50,
        )
        captured = list(statements)
    finally:
        event.remove(engine, "before_cursor_execute", capture)

    assert one.events
    assert fifty.events
    assert count_one == 4
    assert len(captured) == 4
    page_sql = max(captured, key=len)
    assert "union all" in page_sql
    assert "bounded_retest_requests" in page_sql
    assert "join lateral" in page_sql
    assert "users.email" not in page_sql
    assert "retest_attempts.evidence" not in page_sql
    for forbidden in (
        "assessment_reports",
        "operation_coverage",
        "operation_diff",
        "report_shares",
        "delivery_outbox",
        "recipient",
        "discovery_observations",
        "validation_attempts",
    ):
        assert forbidden not in page_sql
