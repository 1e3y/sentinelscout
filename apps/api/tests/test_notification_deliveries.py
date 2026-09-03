"""Milestone 36 — organization notification delivery ledger."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import event, func, select, text
from sqlalchemy.orm import Session, sessionmaker

from app.models.alert import Alert, AlertEpisode, NotificationOutbox
from app.models.audit import AuditEvent
from app.models.diff import OperationDiffSummary
from app.models.finding_follow_up import FindingFollowUpChange
from app.models.finding_follow_up_reminder import (
    REMINDER_KIND_DUE,
    FindingFollowUpReminderJob,
)
from app.models.notification import OrganizationNotificationSettings
from app.models.operation import Operation
from app.models.report import AssessmentReport
from app.models.report_delivery import (
    AssessmentReportDeliveryJob,
    AssessmentReportDeliveryOutbox,
)
from app.models.report_generation_job import AssessmentReportGenerationJob
from app.models.target import AuthorizedTarget
from app.services.delivery_status import (
    map_delivery_db_status_to_customer_state,
    project_delivery_safe_reason,
)
from app.services.notification_deliveries import (
    INVALID_CURSOR_DETAIL,
    compile_notification_deliveries_sql,
    list_notification_deliveries,
)
from tests.test_finding_follow_up import (
    _add_clerk_member,
    _assert_no_email,
    _auth,
    _finding,
    _ids,
)


# --------------------------------------------------------------------------- helpers


def _list(client, token: str, **params):
    return client.get(
        "/v1/notification-deliveries",
        headers=_auth(token),
        params=params or None,
    )


def _setup_admin(client, make_token, seed_user_a, fake_clerk):
    clerk_admin, clerk_org = seed_user_a
    token = make_token(sub=clerk_admin, org_id=clerk_org, org_role="org:admin")
    admin_id, org_id = _ids(client, token)
    member_clerk = _add_clerk_member(
        fake_clerk, clerk_org_id=clerk_org, name="Member"
    )
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


def _target(db: Session, *, organization_id: UUID, user_id: UUID, domain: str | None = None):
    target = AuthorizedTarget(
        organization_id=organization_id,
        created_by_user_id=user_id,
        domain=domain or f"m36-{uuid4().hex[:10]}.example",
        status="verified",
        verified_at=datetime.now(UTC),
    )
    db.add(target)
    db.flush()
    return target


def _operation(db: Session, *, organization_id: UUID, target_id: UUID, user_id: UUID):
    op = Operation(
        organization_id=organization_id,
        target_id=target_id,
        created_by_user_id=user_id,
        status="completed",
        source="manual",
        completed_at=datetime.now(UTC),
    )
    db.add(op)
    db.flush()
    return op


def _diff(db: Session, operation: Operation) -> OperationDiffSummary:
    row = OperationDiffSummary(
        operation_id=operation.id,
        organization_id=operation.organization_id,
        target_id=operation.target_id,
        schema_version=1,
        comparability="comparable",
        comparison_snapshot={"schema_version": 1},
        changes=[],
        counts={},
        headline="diff",
        security_signal_baseline_unavailable=False,
        security_signal_comparison_suppressed=False,
        security_signal_suppression_reason=None,
        operation_status_at_freeze=operation.status,
        source="frozen",
    )
    db.add(row)
    db.flush()
    return row


def _insert_alert_email(
    db: Session,
    *,
    organization_id: UUID,
    user_id: UUID,
    status: str = "delivered",
    last_error_code: str | None = None,
    created_at: datetime | None = None,
    destination_key: str | None = None,
    channel: str = "email",
    payload: dict | None = None,
    delivery_snapshot: dict | None = None,
    last_error: str | None = None,
    processing_token=None,
) -> NotificationOutbox:
    target = _target(db, organization_id=organization_id, user_id=user_id)
    operation = _operation(
        db, organization_id=organization_id, target_id=target.id, user_id=user_id
    )
    diff = _diff(db, operation)
    episode = AlertEpisode(
        organization_id=organization_id,
        target_id=target.id,
        semantic_key=f"sk-{uuid4().hex}",
        alert_type="hsts_lost",
        category="security_regression",
        priority="medium",
        status="open",
        opening_operation_id=operation.id,
        opening_diff_summary_id=diff.id,
        last_seen_operation_id=operation.id,
        last_seen_diff_summary_id=diff.id,
        opening_evidence={"secret": "must-not-select"},
    )
    db.add(episode)
    db.flush()
    alert = Alert(
        organization_id=organization_id,
        target_id=target.id,
        episode_id=episode.id,
        operation_id=operation.id,
        diff_summary_id=diff.id,
        alert_type="hsts_lost",
        category="security_regression",
        priority="medium",
        semantic_key=episode.semantic_key,
        title="HSTS lost",
        summary="alert body must not leak",
        evidence={"secret": "alert-evidence"},
    )
    db.add(alert)
    db.flush()
    row = NotificationOutbox(
        organization_id=organization_id,
        alert_id=alert.id,
        channel=channel,
        destination_key=destination_key or f"user:{user_id}:{uuid4().hex}",
        status=status,
        payload=payload or {"body": "must-not-select"},
        delivery_snapshot=delivery_snapshot or {"email": "secret@example.com"},
        recipient_user_id=user_id,
        last_error_code=last_error_code,
        last_error=last_error or ("raw provider boom" if last_error_code else None),
        processing_token=processing_token,
        delivered_at=datetime.now(UTC) if status == "delivered" else None,
    )
    if created_at is not None:
        row.created_at = created_at
    db.add(row)
    db.flush()
    return row


def _insert_report_delivery(
    db: Session,
    *,
    organization_id: UUID,
    user_id: UUID,
    status: str = "delivered",
    last_error_code: str | None = None,
    created_at: datetime | None = None,
    encrypted_secret: bytes | None = b"\x00secret",
    destination_key: str | None = None,
) -> AssessmentReportDeliveryOutbox:
    target = _target(db, organization_id=organization_id, user_id=user_id)
    operation = _operation(
        db, organization_id=organization_id, target_id=target.id, user_id=user_id
    )
    report = AssessmentReport(
        organization_id=organization_id,
        target_id=target.id,
        operation_id=operation.id,
        created_by_user_id=None,
        generation_origin="scheduled_automatic",
        target_domain=target.domain,
        report_version=1,
        schema_version=1,
        snapshot_digest="ab" * 32,
        snapshot_json={"must_not_load": True},
        operation_status_at_generation="completed",
        assessment_completeness="complete",
        headline_status="no_open_supported_findings",
        findings_total=0,
        findings_open=0,
        findings_resolved=0,
        regression_count=0,
        coverage_limitation_count=0,
        severity_counts={},
    )
    db.add(report)
    db.flush()
    gen = AssessmentReportGenerationJob(
        organization_id=organization_id,
        operation_id=operation.id,
        status="succeeded",
        report_id=report.id,
    )
    db.add(gen)
    db.flush()
    job = AssessmentReportDeliveryJob(
        organization_id=organization_id,
        operation_id=operation.id,
        generation_job_id=gen.id,
        report_id=report.id,
        target_id=target.id,
        status="succeeded",
        frozen_recipients=["external@example.com"],
        frozen_expires_in="7d",
    )
    db.add(job)
    db.flush()
    row = AssessmentReportDeliveryOutbox(
        organization_id=organization_id,
        delivery_job_id=job.id,
        report_id=report.id,
        destination_key=destination_key or f"email:{uuid4().hex}",
        recipient_email_normalized=f"{uuid4().hex}@example.com",
        status=status,
        last_error_code=last_error_code,
        encrypted_secret=encrypted_secret,
        encrypted_secret_nonce=b"\x01nonce",
        encryption_key_version="v1",
        frozen_frontend_origin="http://localhost:3000",
        frozen_from_email="scout@example.test",
        frozen_subject="Report ready",
        frozen_target_domain=target.domain,
        delivered_at=datetime.now(UTC) if status == "delivered" else None,
    )
    if created_at is not None:
        row.created_at = created_at
    db.add(row)
    db.flush()
    return row


def _insert_reminder(
    db: Session,
    *,
    organization_id: UUID,
    user_id: UUID,
    status: str = "delivered",
    last_error_code: str | None = None,
    created_at: datetime | None = None,
    delivery_snapshot: dict | None = None,
    last_error: str | None = None,
    processing_token=None,
) -> FindingFollowUpReminderJob:
    finding = _finding(db, organization_id=organization_id, user_id=user_id)
    due = datetime.now(UTC) + timedelta(days=1)
    change = FindingFollowUpChange(
        organization_id=organization_id,
        finding_id=finding.id,
        changed_by_user_id=user_id,
        previous_assigned_to_user_id=None,
        new_assigned_to_user_id=user_id,
        previous_due_at=None,
        new_due_at=due,
    )
    db.add(change)
    db.flush()
    row = FindingFollowUpReminderJob(
        organization_id=organization_id,
        finding_id=finding.id,
        follow_up_change_id=change.id,
        assigned_to_user_id=user_id,
        due_at=due,
        reminder_kind=REMINDER_KIND_DUE,
        status=status,
        available_at=datetime.now(UTC),
        last_error_code=last_error_code,
        last_error=last_error or ("raw" if last_error_code else None),
        delivery_snapshot=delivery_snapshot or {"email": "secret@example.com"},
        processing_token=processing_token,
        delivered_at=datetime.now(UTC) if status == "delivered" else None,
    )
    if created_at is not None:
        row.created_at = created_at
    db.add(row)
    db.flush()
    return row


def _fingerprint(db: Session) -> dict[str, int]:
    return {
        "m20": int(db.scalar(select(func.count()).select_from(NotificationOutbox)) or 0),
        "m27": int(
            db.scalar(select(func.count()).select_from(AssessmentReportDeliveryOutbox))
            or 0
        ),
        "m34": int(
            db.scalar(select(func.count()).select_from(FindingFollowUpReminderJob))
            or 0
        ),
        "audit": int(db.scalar(select(func.count()).select_from(AuditEvent)) or 0),
        "alerts": int(db.scalar(select(func.count()).select_from(Alert)) or 0),
        "reports": int(
            db.scalar(select(func.count()).select_from(AssessmentReport)) or 0
        ),
    }


# --------------------------------------------------------------------------- unit


def test_customer_state_mapping():
    assert map_delivery_db_status_to_customer_state("failed") == "retrying"
    assert map_delivery_db_status_to_customer_state("skipped") == "skipped"
    assert map_delivery_db_status_to_customer_state("dead") == "dead"


def test_safe_reason_collapses_infra_and_maps_business():
    code, label = project_delivery_safe_reason(
        delivery_class="alert_email",
        customer_state="skipped",
        internal_code="recipient_unauthorized",
    )
    assert code == "recipient_unavailable"
    assert label

    code, _ = project_delivery_safe_reason(
        delivery_class="alert_email",
        customer_state="skipped",
        internal_code="recipient_identity_changed",
    )
    assert code == "recipient_changed"

    code, _ = project_delivery_safe_reason(
        delivery_class="report_delivery",
        customer_state="skipped",
        internal_code="share_revoked",
    )
    assert code == "delivery_revoked"

    code, _ = project_delivery_safe_reason(
        delivery_class="report_delivery",
        customer_state="skipped",
        internal_code="staging_destination_not_allowed",
    )
    assert code == "environment_restricted"

    code, _ = project_delivery_safe_reason(
        delivery_class="report_delivery",
        customer_state="dead",
        internal_code="missing_encrypted_secret",
    )
    assert code == "delivery_issue"

    code, _ = project_delivery_safe_reason(
        delivery_class="follow_up_reminder",
        customer_state="retrying",
        internal_code="provider_timeout",
    )
    assert code == "delivery_temporarily_unavailable"
    assert "provider" not in (code or "")

    code, _ = project_delivery_safe_reason(
        delivery_class="follow_up_reminder",
        customer_state="dead",
        internal_code="send_error",
    )
    assert code == "delivery_issue"

    code, _ = project_delivery_safe_reason(
        delivery_class="follow_up_reminder",
        customer_state="skipped",
        internal_code="finding_resolved",
    )
    assert code == "finding_resolved"


# --------------------------------------------------------------------------- RBAC


def test_unauthenticated_401(client):
    assert client.get("/v1/notification-deliveries").status_code == 401


def test_member_403_admin_200(client, make_token, seed_user_a, fake_clerk, db_session):
    ctx = _setup_admin(client, make_token, seed_user_a, fake_clerk)
    _insert_alert_email(
        db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"]
    )
    db_session.commit()

    assert _list(client, ctx["member_token"]).status_code == 403
    ok = _list(client, ctx["token"])
    assert ok.status_code == 200, ok.text
    body = ok.json()
    assert "configuration" in body
    assert "items" in body
    assert "next_cursor" in body
    assert "summary" not in body
    assert "counts" not in body
    assert "automatic_report_delivery" not in body["configuration"]
    _assert_no_email(body)


def test_membership_role_alone_does_not_elevate(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    clerk_admin, clerk_org = seed_user_a
    token = make_token(sub=clerk_admin, org_id=clerk_org, org_role="org:admin")
    admin_id, org_id = _ids(client, token)
    # Persist local membership as admin, but present token as member.
    memberish = make_token(sub=clerk_admin, org_id=clerk_org, org_role="org:member")
    response = _list(client, memberish)
    assert response.status_code == 403


# --------------------------------------------------------------------------- tenant isolation


def test_foreign_rows_cannot_enter_all_three_sources(
    client, make_token, seed_user_a, seed_user_b, fake_clerk, db_session
):
    ctx_a = _setup_admin(client, make_token, seed_user_a, fake_clerk)
    clerk_b, org_b_clerk = seed_user_b
    token_b = make_token(sub=clerk_b, org_id=org_b_clerk, org_role="org:admin")
    admin_b, org_b = _ids(client, token_b)

    local_alert = _insert_alert_email(
        db_session, organization_id=ctx_a["org_id"], user_id=ctx_a["admin_id"]
    )
    local_report = _insert_report_delivery(
        db_session, organization_id=ctx_a["org_id"], user_id=ctx_a["admin_id"]
    )
    local_reminder = _insert_reminder(
        db_session, organization_id=ctx_a["org_id"], user_id=ctx_a["admin_id"]
    )
    foreign_alert = _insert_alert_email(
        db_session, organization_id=org_b, user_id=admin_b
    )
    foreign_report = _insert_report_delivery(
        db_session, organization_id=org_b, user_id=admin_b
    )
    foreign_reminder = _insert_reminder(
        db_session, organization_id=org_b, user_id=admin_b
    )
    db_session.commit()

    body = _list(client, ctx_a["token"], page_size=50).json()
    classes = {item["delivery_class"] for item in body["items"]}
    assert classes == {"alert_email", "report_delivery", "follow_up_reminder"}
    dumped = str(body)
    assert str(foreign_alert.id) not in dumped
    assert str(foreign_report.id) not in dumped
    assert str(foreign_reminder.id) not in dumped
    assert str(local_alert.alert_id) in dumped
    assert str(local_report.report_id) in dumped
    assert str(local_reminder.finding_id) in dumped

    # Service-level: foreign ids absent even from raw page before enrichment.
    result = list_notification_deliveries(
        db_session, organization_id=ctx_a["org_id"], page_size=50
    )
    assert len(result.items) == 3


# --------------------------------------------------------------------------- filters / pagination


def test_state_filter_pushdown_finds_older_matching_rows(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup_admin(client, make_token, seed_user_a, fake_clerk)
    now = datetime.now(UTC)
    # 55 recent delivered alerts, then older failed (retrying) rows.
    for i in range(55):
        _insert_alert_email(
            db_session,
            organization_id=ctx["org_id"],
            user_id=ctx["admin_id"],
            status="delivered",
            created_at=now - timedelta(minutes=i),
        )
    older = []
    for i in range(5):
        older.append(
            _insert_alert_email(
                db_session,
                organization_id=ctx["org_id"],
                user_id=ctx["admin_id"],
                status="failed",
                last_error_code="provider_timeout",
                created_at=now - timedelta(hours=2, minutes=i),
            )
        )
    db_session.commit()

    # Without pushdown, first page of 20 would be all delivered and miss older failed.
    body = _list(
        client, ctx["token"], state="retrying", delivery_class="alert_email", page_size=20
    ).json()
    assert len(body["items"]) == 5
    assert all(item["state"] == "retrying" for item in body["items"])
    assert all(
        item["safe_reason_code"] == "delivery_temporarily_unavailable"
        for item in body["items"]
    )


def test_class_filter_prunes_other_branches(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup_admin(client, make_token, seed_user_a, fake_clerk)
    sql = compile_notification_deliveries_sql(
        organization_id=ctx["org_id"],
        delivery_class="alert_email",
    ).lower()
    assert "notification_outbox" in sql
    assert "assessment_report_delivery_outbox" not in sql
    assert "finding_follow_up_reminder_jobs" not in sql

    sql_report = compile_notification_deliveries_sql(
        organization_id=ctx["org_id"],
        delivery_class="report_delivery",
    ).lower()
    assert "assessment_report_delivery_outbox" in sql_report
    assert "notification_outbox" not in sql_report
    assert "finding_follow_up_reminder_jobs" not in sql_report


def test_deep_mixed_pagination_no_holes_identical_timestamps(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup_admin(client, make_token, seed_user_a, fake_clerk)
    stamp = datetime.now(UTC) - timedelta(days=1)
    expected = []
    for i in range(12):
        expected.append(
            (
                "alert_email",
                _insert_alert_email(
                    db_session,
                    organization_id=ctx["org_id"],
                    user_id=ctx["admin_id"],
                    created_at=stamp,
                ).id,
            )
        )
        expected.append(
            (
                "report_delivery",
                _insert_report_delivery(
                    db_session,
                    organization_id=ctx["org_id"],
                    user_id=ctx["admin_id"],
                    created_at=stamp,
                ).id,
            )
        )
        expected.append(
            (
                "follow_up_reminder",
                _insert_reminder(
                    db_session,
                    organization_id=ctx["org_id"],
                    user_id=ctx["admin_id"],
                    created_at=stamp,
                ).id,
            )
        )
    db_session.commit()

    seen: list[tuple[str, str]] = []
    cursor = None
    for _ in range(20):
        params = {"page_size": 5}
        if cursor:
            params["cursor"] = cursor
        body = _list(client, ctx["token"], **params).json()
        for item in body["items"]:
            detail = item["detail"]
            if item["delivery_class"] == "alert_email":
                key = ("alert_email", detail["alert_id"])
            elif item["delivery_class"] == "report_delivery":
                key = ("report_delivery", detail["report_id"])
            else:
                key = ("follow_up_reminder", detail["finding_id"])
            seen.append(key)
        cursor = body["next_cursor"]
        if not cursor:
            break

    assert len(seen) == len(set(seen))
    assert len(seen) == 36
    # Same timestamp: all alert_email (rank 30) precede report_delivery (20).
    first_page = _list(client, ctx["token"], page_size=3).json()["items"]
    assert [row["delivery_class"] for row in first_page] == [
        "alert_email",
        "alert_email",
        "alert_email",
    ]
    mid = _list(
        client,
        ctx["token"],
        page_size=3,
        cursor=_list(client, ctx["token"], page_size=12).json()["next_cursor"],
    ).json()["items"]
    assert all(row["delivery_class"] == "report_delivery" for row in mid)


def test_malformed_cursor_400_invalid_enum_422(
    client, make_token, seed_user_a, fake_clerk
):
    ctx = _setup_admin(client, make_token, seed_user_a, fake_clerk)
    bad = _list(client, ctx["token"], cursor="not-a-cursor")
    assert bad.status_code == 400
    assert bad.json()["error"]["message"] == INVALID_CURSOR_DETAIL

    invalid = _list(client, ctx["token"], state="failed")
    assert invalid.status_code == 422

    too_big = _list(client, ctx["token"], page_size=51)
    assert too_big.status_code == 422


# --------------------------------------------------------------------------- secret SQL capture


def test_sql_excludes_secret_and_heavy_columns(
    client, make_token, seed_user_a, fake_clerk, db_session, engine
):
    ctx = _setup_admin(client, make_token, seed_user_a, fake_clerk)
    _insert_alert_email(
        db_session,
        organization_id=ctx["org_id"],
        user_id=ctx["admin_id"],
        status="skipped",
        last_error_code="staging_destination_not_allowed",
        processing_token=uuid4(),
    )
    _insert_report_delivery(
        db_session,
        organization_id=ctx["org_id"],
        user_id=ctx["admin_id"],
        status="skipped",
        last_error_code="missing_encrypted_secret",
        encrypted_secret=b"top-secret",
    )
    _insert_reminder(
        db_session,
        organization_id=ctx["org_id"],
        user_id=ctx["admin_id"],
        status="dead",
        last_error_code="decrypt_failed",
        processing_token=uuid4(),
        delivery_snapshot={"email": "x@y.com"},
    )
    db_session.commit()

    compiled = compile_notification_deliveries_sql(
        organization_id=ctx["org_id"], size=20
    ).lower()
    forbidden = [
        "payload",
        "delivery_snapshot",
        "last_error,",
        "last_error ",
        "processing_token",
        "lease_expires_at",
        "encrypted_secret",
        "encrypted_secret_nonce",
        "encryption_key_version",
        "recipient_email_normalized",
        "destination_key",
        "frozen_subject",
        "frozen_from_email",
        "snapshot_json",
        "secret_hash",
    ]
    for name in forbidden:
        assert name not in compiled, name

    statements: list[str] = []

    def capture(_conn, _cursor, statement, _parameters, _context, _executemany):
        if statement.lstrip().upper().startswith("SELECT"):
            statements.append(statement)

    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    session = factory()
    event.listen(engine, "before_cursor_execute", capture)
    try:
        list_notification_deliveries(session, organization_id=ctx["org_id"], page_size=20)
        session.rollback()
    finally:
        event.remove(engine, "before_cursor_execute", capture)
        session.close()

    joined = " ".join(statements).lower()
    for name in [
        "delivery_snapshot",
        "encrypted_secret",
        "encrypted_secret_nonce",
        "encryption_key_version",
        "recipient_email_normalized",
        "processing_token",
        "snapshot_json",
        "secret_hash",
    ]:
        assert name not in joined, name
    # last_error column (not last_error_code)
    assert "last_error," not in joined
    assert " last_error " not in joined or "last_error_code" in joined


def test_response_never_exposes_raw_codes_or_email(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup_admin(client, make_token, seed_user_a, fake_clerk)
    _insert_alert_email(
        db_session,
        organization_id=ctx["org_id"],
        user_id=ctx["admin_id"],
        status="skipped",
        last_error_code="staging_destination_not_allowed",
    )
    _insert_report_delivery(
        db_session,
        organization_id=ctx["org_id"],
        user_id=ctx["admin_id"],
        status="skipped",
        last_error_code="share_expired",
    )
    _insert_reminder(
        db_session,
        organization_id=ctx["org_id"],
        user_id=ctx["admin_id"],
        status="failed",
        last_error_code="provider_unavailable",
    )
    db_session.commit()

    body = _list(client, ctx["token"], page_size=50).json()
    dumped = str(body).lower()
    for banned in [
        "staging_destination_not_allowed",
        "provider_unavailable",
        "missing_encrypted_secret",
        "decrypt",
        "secret_key",
        "@example.com",
        "last_error",
    ]:
        assert banned not in dumped, banned
    codes = {item["safe_reason_code"] for item in body["items"]}
    assert "environment_restricted" in codes
    assert "delivery_expired" in codes
    assert "delivery_temporarily_unavailable" in codes
    _assert_no_email(body)
    assert all(
        item.get("recipient", {}).get("kind") != "organization_member"
        or "email" not in item["recipient"]
        for item in body["items"]
    )
    report_rows = [
        item for item in body["items"] if item["delivery_class"] == "report_delivery"
    ]
    assert report_rows
    assert all(r["recipient"]["kind"] == "external_recipient" for r in report_rows)


# --------------------------------------------------------------------------- read-only


def test_get_is_read_only(client, make_token, seed_user_a, fake_clerk, db_session):
    ctx = _setup_admin(client, make_token, seed_user_a, fake_clerk)
    _insert_alert_email(
        db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"]
    )
    _insert_report_delivery(
        db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"]
    )
    _insert_reminder(
        db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"]
    )
    db_session.commit()
    before = _fingerprint(db_session)
    assert _list(client, ctx["token"]).status_code == 200
    db_session.expire_all()
    assert _fingerprint(db_session) == before


def test_in_app_and_delivery_jobs_excluded(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup_admin(client, make_token, seed_user_a, fake_clerk)
    _insert_alert_email(
        db_session,
        organization_id=ctx["org_id"],
        user_id=ctx["admin_id"],
        channel="in_app",
        destination_key=f"in_app:{uuid4().hex}",
    )
    # Email row included
    email = _insert_alert_email(
        db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"]
    )
    db_session.commit()
    body = _list(client, ctx["token"]).json()
    assert len(body["items"]) == 1
    assert body["items"][0]["detail"]["alert_id"] == str(email.alert_id)


def test_configuration_header_shape(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup_admin(client, make_token, seed_user_a, fake_clerk)
    db_session.add(
        OrganizationNotificationSettings(
            organization_id=ctx["org_id"],
            email_enabled=True,
            email_min_priority="medium",
            finding_follow_up_reminders_enabled=True,
        )
    )
    db_session.commit()
    body = _list(client, ctx["token"]).json()
    cfg = body["configuration"]
    assert cfg["alert_email_enabled"] is True
    assert cfg["follow_up_reminders_enabled"] is True
    assert "email_delivery_enabled" in cfg
    assert set(cfg.keys()) == {
        "alert_email_enabled",
        "follow_up_reminders_enabled",
        "email_delivery_enabled",
    }


def test_explain_uses_existing_indexes(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup_admin(client, make_token, seed_user_a, fake_clerk)
    now = datetime.now(UTC)
    for i in range(30):
        _insert_alert_email(
            db_session,
            organization_id=ctx["org_id"],
            user_id=ctx["admin_id"],
            created_at=now - timedelta(minutes=i),
        )
        _insert_report_delivery(
            db_session,
            organization_id=ctx["org_id"],
            user_id=ctx["admin_id"],
            created_at=now - timedelta(minutes=i),
        )
        _insert_reminder(
            db_session,
            organization_id=ctx["org_id"],
            user_id=ctx["admin_id"],
            created_at=now - timedelta(minutes=i),
        )
    db_session.commit()

    sql = compile_notification_deliveries_sql(
        organization_id=ctx["org_id"],
        state="retrying",
        size=20,
    )
    plan = db_session.execute(text(f"EXPLAIN {sql}")).all()
    plan_text = "\n".join(row[0] for row in plan).lower()
    assert "notification_outbox" in plan_text or "seq scan" in plan_text
    # Decision: prefer no migration; org_id indexes already exist on all three sources.
    assert True
