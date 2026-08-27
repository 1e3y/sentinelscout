from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.attributes import flag_modified

from app.models.audit import AuditEvent
from app.models.coverage import OperationCoverageSummary
from app.models.monitoring import MonitoringConfiguration
from app.models.operation import Operation
from app.models.report import AssessmentReport
from app.models.report_generation_job import AssessmentReportGenerationJob
from app.services.discovery.runner import FakeDiscoveryTools, ProbeResult
from app.services.reports.auto import (
    BACKOFF_CAP_SECONDS,
    MAX_ATTEMPTS,
    claim_report_generation_job,
    complete_claimed_job,
    process_one_automatic_report,
    retry_delay_seconds,
)
from app.services.reports.snapshot import content_digest
from app.services.scheduler_runtime import process_one_scheduled_monitoring
from app.services.worker_runtime import process_one_operation
from tests.test_reports import _auth, _create_verified_target, _generate


def _clean_probe(host: str) -> ProbeResult:
    return ProbeResult(
        url=f"https://{host}",
        status_code=200,
        title="Home",
        headers_observed=True,
        headers={"strict-transport-security": "max-age=31536000"},
        headers_present=("strict-transport-security",),
        content_type="text/html",
        requested_url=f"https://{host}",
        final_url=f"https://{host}",
        scheme="https",
    )


def _enable_monitoring(
    client,
    token: str,
    target_id: str,
    *,
    auto_generate_reports: bool | None = None,
    frequency: str = "daily",
):
    payload: dict = {"enabled": True, "frequency": frequency}
    if auto_generate_reports is not None:
        payload["auto_generate_reports"] = auto_generate_reports
    response = client.put(
        f"/v1/targets/{target_id}/monitoring",
        headers=_auth(token),
        json=payload,
    )
    assert response.status_code == 200, response.text
    return response.json()


def _due_monitoring(db_session, target_id: str) -> MonitoringConfiguration:
    db_session.expire_all()
    config = db_session.scalar(
        select(MonitoringConfiguration).where(
            MonitoringConfiguration.target_id == UUID(target_id)
        )
    )
    assert config is not None
    config.next_run_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    db_session.commit()
    return config


def _complete_scheduled(
    client,
    token: str,
    dns_resolver,
    engine,
    db_session,
    domain: str,
    *,
    auto_generate_reports: bool = True,
):
    target_id = _create_verified_target(client, token, domain, dns_resolver)
    _enable_monitoring(
        client, token, target_id, auto_generate_reports=auto_generate_reports
    )
    _due_monitoring(db_session, target_id)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    scheduled = process_one_scheduled_monitoring(factory)
    assert scheduled is not None
    assert scheduled.source == "scheduled"
    tools = FakeDiscoveryTools(
        hosts_by_domain={domain: []},
        probes_by_host={domain: _clean_probe(domain)},
    )
    result = process_one_operation(factory, tools=tools)
    assert result is not None
    assert result.status == "completed"
    return target_id, result.id, factory


def _job_for_operation(db_session, operation_id) -> AssessmentReportGenerationJob | None:
    db_session.expire_all()
    return db_session.scalar(
        select(AssessmentReportGenerationJob).where(
            AssessmentReportGenerationJob.operation_id == operation_id
        )
    )


def _report_count(db_session, operation_id) -> int:
    db_session.expire_all()
    return int(
        db_session.scalar(
            select(func.count()).select_from(AssessmentReport).where(
                AssessmentReport.operation_id == operation_id
            )
        )
        or 0
    )


def test_retry_delay_is_bounded_exponential():
    assert retry_delay_seconds(1) == 60
    assert retry_delay_seconds(2) == 120
    assert retry_delay_seconds(3) == 240
    assert retry_delay_seconds(20) == BACKOFF_CAP_SECONDS


def test_legacy_monitoring_put_preserves_auto_generate_reports(
    client, make_token, seed_user_a, dns_resolver
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    target_id = _create_verified_target(client, token, "auto-put.example", dns_resolver)

    enabled = _enable_monitoring(client, token, target_id, auto_generate_reports=True)
    assert enabled["auto_generate_reports"] is True

    legacy = client.put(
        f"/v1/targets/{target_id}/monitoring",
        headers=_auth(token),
        json={"enabled": True, "frequency": "weekly"},
    )
    assert legacy.status_code == 200, legacy.text
    assert legacy.json()["auto_generate_reports"] is True
    assert legacy.json()["frequency"] == "weekly"

    disabled = client.put(
        f"/v1/targets/{target_id}/monitoring",
        headers=_auth(token),
        json={"enabled": True, "frequency": "weekly", "auto_generate_reports": False},
    )
    assert disabled.json()["auto_generate_reports"] is False

    got = client.get(f"/v1/targets/{target_id}/monitoring", headers=_auth(token))
    assert got.json()["auto_generate_reports"] is False


def test_auto_report_config_audit_uses_verified_admin(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    target_id = _create_verified_target(client, token, "auto-audit.example", dns_resolver)
    _enable_monitoring(client, token, target_id, auto_generate_reports=True)
    events = list(
        db_session.scalars(
            select(AuditEvent)
            .where(AuditEvent.action == "monitoring.auto_reports_enabled")
            .order_by(AuditEvent.created_at.desc())
        )
    )
    assert events
    event = events[0]
    assert event.actor_type == "user"
    assert event.actor_user_id is not None
    assert event.event_metadata.get("auto_generate_reports") is True
    assert event.event_metadata.get("authorization_role") == "admin"


def test_scheduled_completed_with_auto_flag_enqueues_and_generates(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    target_id, operation_id, factory = _complete_scheduled(
        client, token, dns_resolver, engine, db_session, "auto-ok.example"
    )
    coverage = db_session.scalar(
        select(OperationCoverageSummary).where(
            OperationCoverageSummary.operation_id == operation_id
        )
    )
    assert coverage is not None
    job = _job_for_operation(db_session, operation_id)
    assert job is not None
    assert job.status == "pending"
    operation = db_session.get(Operation, operation_id)
    assert job.organization_id == operation.organization_id

    processed = process_one_automatic_report(factory)
    assert processed is not None
    assert processed.status == "succeeded"
    assert processed.report_id is not None

    report = db_session.get(AssessmentReport, processed.report_id)
    assert report is not None
    assert report.generation_origin == "scheduled_automatic"
    assert report.created_by_user_id is None
    envelope = report.snapshot_json["envelope"]
    assert envelope["origin"] == "scheduled_automatic"
    assert "generated_by" not in envelope
    assert report.snapshot_json["content"]["coverage"]["follow_up_frozen_for_report"][
        "source"
    ] == "computed_at_report_generation"
    assert "origin" not in report.snapshot_json["content"]
    assert content_digest(report.snapshot_json["content"]) == report.snapshot_digest

    listed = client.get("/v1/reports", headers=_auth(token)).json()
    assert listed[0]["generation_origin"] == "scheduled_automatic"
    assert listed[0]["created_by_user_id"] is None

    generated = list(
        db_session.scalars(
            select(AuditEvent).where(
                AuditEvent.action == "assessment_report.generated",
                AuditEvent.resource_id == report.id,
            )
        )
    )
    assert len(generated) == 1
    audit = generated[0]
    assert audit.actor_type == "worker"
    assert audit.actor_user_id is None
    assert audit.event_metadata.get("generation_origin") == "scheduled_automatic"
    assert audit.event_metadata.get("generation_reason") == "scheduled_monitoring"
    assert "authorization_role" not in audit.event_metadata
    assert "authorization_basis" not in audit.event_metadata
    listed_target = client.get(
        f"/v1/targets/{target_id}/monitoring", headers=_auth(token)
    ).json()
    assert listed_target["auto_generate_reports"] is True


def test_no_job_when_auto_flag_false(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    _, disabled_op, _ = _complete_scheduled(
        client,
        token,
        dns_resolver,
        engine,
        db_session,
        "auto-off.example",
        auto_generate_reports=False,
    )
    assert _job_for_operation(db_session, disabled_op) is None


def test_no_job_for_manual_completed_operation(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    domain = "auto-manual.example"
    target_id = _create_verified_target(client, token, domain, dns_resolver)
    _enable_monitoring(client, token, target_id, auto_generate_reports=True)
    manual_id = client.post(
        "/v1/operations", headers=_auth(token), json={"target_id": target_id}
    ).json()["id"]
    tools = FakeDiscoveryTools(
        hosts_by_domain={domain: []},
        probes_by_host={domain: _clean_probe(domain)},
    )
    assert process_one_operation(factory, tools=tools).status == "completed"
    assert _job_for_operation(db_session, UUID(manual_id)) is None


def test_no_job_for_queued_operation(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    queued_domain = "auto-queued.example"
    queued_target = _create_verified_target(client, token, queued_domain, dns_resolver)
    _enable_monitoring(client, token, queued_target, auto_generate_reports=True)
    queued_id = client.post(
        "/v1/operations", headers=_auth(token), json={"target_id": queued_target}
    ).json()["id"]
    assert _job_for_operation(db_session, UUID(queued_id)) is None


def test_no_job_for_failed_scheduled_operation(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    fail_domain = "auto-fail.example"
    fail_target = _create_verified_target(client, token, fail_domain, dns_resolver)
    _enable_monitoring(client, token, fail_target, auto_generate_reports=True)
    _due_monitoring(db_session, fail_target)
    scheduled = process_one_scheduled_monitoring(factory)
    assert scheduled is not None
    failed = process_one_operation(
        factory,
        tools=FakeDiscoveryTools(
            hosts_by_domain={fail_domain: []},
            probes_by_host={},
            fail_discover_with="subfinder exited with an error",
        ),
    )
    assert failed.status == "failed"
    assert _job_for_operation(db_session, failed.id) is None


def test_no_job_for_stopped_scheduled_operation(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    stop_domain = "auto-stop.example"
    stop_target = _create_verified_target(client, token, stop_domain, dns_resolver)
    _enable_monitoring(client, token, stop_target, auto_generate_reports=True)
    _due_monitoring(db_session, stop_target)
    stop_op = process_one_scheduled_monitoring(factory)
    assert stop_op is not None
    stopped = client.post(
        f"/v1/operations/{stop_op.id}/stop", headers=_auth(token)
    )
    assert stopped.status_code == 200, stopped.text
    assert stopped.json()["status"] == "stopped"
    assert _job_for_operation(db_session, stop_op.id) is None


def test_disable_after_enqueue_skips_and_is_not_resurrected(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    target_id, operation_id, factory = _complete_scheduled(
        client, token, dns_resolver, engine, db_session, "auto-skip.example"
    )
    job = _job_for_operation(db_session, operation_id)
    assert job is not None
    assert job.status == "pending"

    disabled = client.put(
        f"/v1/targets/{target_id}/monitoring",
        headers=_auth(token),
        json={"enabled": True, "frequency": "daily", "auto_generate_reports": False},
    )
    assert disabled.json()["auto_generate_reports"] is False

    processed = process_one_automatic_report(factory)
    assert processed is not None
    assert processed.status == "skipped"
    assert processed.last_error_code == "auto_generate_reports_disabled"
    assert processed.report_id is None
    assert _report_count(db_session, operation_id) == 0

    reenabled = client.put(
        f"/v1/targets/{target_id}/monitoring",
        headers=_auth(token),
        json={"enabled": True, "frequency": "daily", "auto_generate_reports": True},
    )
    assert reenabled.json()["auto_generate_reports"] is True
    assert process_one_automatic_report(factory) is None
    db_session.expire_all()
    job = db_session.get(AssessmentReportGenerationJob, job.id)
    assert job.status == "skipped"
    assert _report_count(db_session, operation_id) == 0


def test_forced_exception_before_commit_is_atomic_and_retryable(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    _, operation_id, factory = _complete_scheduled(
        client, token, dns_resolver, engine, db_session, "auto-crash.example"
    )

    def boom():
        raise RuntimeError("forced crash before outer commit")

    crashed = process_one_automatic_report(factory, before_success_commit=boom)
    assert crashed is not None
    assert crashed.status == "pending"
    assert crashed.report_id is None
    assert _report_count(db_session, operation_id) == 0
    operation = db_session.get(Operation, operation_id)
    assert operation.status == "completed"

    db_session.expire_all()
    job = _job_for_operation(db_session, operation_id)
    job.available_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    db_session.commit()

    processed = process_one_automatic_report(factory)
    assert processed.status == "succeeded"
    assert processed.report_id is not None
    assert _report_count(db_session, operation_id) == 1


def test_lease_fencing_stale_worker_cannot_clobber(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    _, operation_id, factory = _complete_scheduled(
        client, token, dns_resolver, engine, db_session, "auto-fence.example"
    )
    t0 = datetime.now(timezone.utc)
    db_a = factory()
    try:
        claimed = claim_report_generation_job(db_a, now=t0, lease_seconds=1)
        assert claimed is not None
        row, token_a = claimed
        job_id = row.id
    finally:
        db_a.close()

    processed = process_one_automatic_report(
        factory, now=t0 + timedelta(seconds=5), lease_seconds=300
    )
    assert processed is not None
    assert processed.status == "succeeded"
    report_id = processed.report_id

    db_late = factory()
    try:
        owned = complete_claimed_job(
            db_late,
            job_id=job_id,
            processing_token=token_a,
            values={
                "status": "failed",
                "last_error_code": "stale_worker",
            },
        )
        assert owned is False
        current = db_late.get(AssessmentReportGenerationJob, job_id)
        assert current is not None
        assert current.status == "succeeded"
        assert current.report_id == report_id
        assert current.last_error_code is None
        assert current.processing_token is None
        assert current.lease_expires_at is None
    finally:
        db_late.close()


def test_identical_manual_report_is_reused_without_rewrite(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    _, operation_id, factory = _complete_scheduled(
        client, token, dns_resolver, engine, db_session, "auto-reuse.example"
    )
    created = _generate(client, token, str(operation_id))
    assert created.status_code == 201, created.text
    manual = created.json()
    assert manual["generation_origin"] == "manual"
    assert manual["created_by_user_id"] is not None
    generated_before = db_session.scalar(
        select(func.count()).select_from(AuditEvent).where(
            AuditEvent.action == "assessment_report.generated"
        )
    )

    processed = process_one_automatic_report(factory)
    assert processed.status == "succeeded"
    assert str(processed.report_id) == manual["id"]
    db_session.expire_all()
    report = db_session.get(AssessmentReport, processed.report_id)
    assert report.generation_origin == "manual"
    assert report.created_by_user_id is not None
    assert report.report_version == 1
    generated_after = db_session.scalar(
        select(func.count()).select_from(AuditEvent).where(
            AuditEvent.action == "assessment_report.generated"
        )
    )
    assert generated_after == generated_before
    assert _report_count(db_session, operation_id) == 1


def test_retry_backoff_and_terminal_failure_audit(
    client, make_token, seed_user_a, dns_resolver, engine, db_session, monkeypatch
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    _, operation_id, factory = _complete_scheduled(
        client, token, dns_resolver, engine, db_session, "auto-retry.example"
    )

    def boom(*_args, **_kwargs):
        raise RuntimeError("generation exploded")

    monkeypatch.setattr(
        "app.services.reports.auto.build_report_digest_for_operation", boom
    )
    t0 = datetime.now(timezone.utc) + timedelta(days=30)
    first = process_one_automatic_report(factory, now=t0)
    assert first.status == "pending"
    assert first.last_error_code == "generation_error"
    assert first.processing_token is None
    assert _report_count(db_session, operation_id) == 0
    operation = db_session.get(Operation, operation_id)
    assert operation.status == "completed"

    last = None
    for index in range(MAX_ATTEMPTS - 1):
        last = process_one_automatic_report(
            factory, now=t0 + timedelta(days=index + 1)
        )
    assert last is not None
    assert last.status == "failed"
    assert last.last_error_code == "max_attempts_exceeded"
    failures = list(
        db_session.scalars(
            select(AuditEvent).where(
                AuditEvent.action == "assessment_report.generation_failed"
            )
        )
    )
    assert len(failures) == 1
    assert failures[0].actor_type == "worker"
    assert failures[0].actor_user_id is None
    assert _report_count(db_session, operation_id) == 0


def test_duplicate_enqueue_is_noop(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    _, operation_id, _factory = _complete_scheduled(
        client, token, dns_resolver, engine, db_session, "auto-dup.example"
    )
    from app.services.reports.auto import enqueue_automatic_report_job

    operation = db_session.get(Operation, operation_id)
    enqueue_automatic_report_job(db_session, operation)
    db_session.commit()
    count = db_session.scalar(
        select(func.count()).select_from(AssessmentReportGenerationJob).where(
            AssessmentReportGenerationJob.operation_id == operation_id
        )
    )
    assert count == 1


def test_old_envelope_without_origin_still_exports_pdf_and_share(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    operation_id = None
    target_id = _create_verified_target(
        client, token, "auto-oldenv.example", dns_resolver
    )
    operation_id = client.post(
        "/v1/operations", headers=_auth(token), json={"target_id": target_id}
    ).json()["id"]
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    tools = FakeDiscoveryTools(
        hosts_by_domain={"auto-oldenv.example": []},
        probes_by_host={"auto-oldenv.example": _clean_probe("auto-oldenv.example")},
    )
    assert process_one_operation(factory, tools=tools).status == "completed"
    report_id = _generate(client, token, operation_id).json()["id"]
    row = db_session.get(AssessmentReport, report_id)
    snapshot = dict(row.snapshot_json)
    envelope = dict(snapshot["envelope"])
    envelope.pop("origin", None)
    snapshot["envelope"] = envelope
    row.snapshot_json = snapshot
    flag_modified(row, "snapshot_json")
    db_session.commit()

    pdf = client.get(f"/v1/reports/{report_id}/pdf", headers=_auth(token))
    assert pdf.status_code == 200, pdf.text
    assert pdf.content.startswith(b"%PDF")

    created = client.post(
        f"/v1/reports/{report_id}/shares",
        headers=_auth(token),
        json={"expires_in": "24h"},
    )
    assert created.status_code == 201, created.text
    share_url = created.json()["share_url"]
    secret = share_url.rsplit("#", 1)[-1]
    share_id = created.json()["id"]
    payload = client.post(
        f"/v1/shared-reports/{share_id}/resolve",
        json={"secret": secret},
    ).json()
    assert payload["report"]["generation_origin"] == "manual"
    dumped = json.dumps(payload)
    assert "generated_by" not in dumped
    assert "created_by_user_id" not in dumped


def test_automatic_report_share_and_pdf_hide_null_actor(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    _, operation_id, factory = _complete_scheduled(
        client, token, dns_resolver, engine, db_session, "auto-share.example"
    )
    processed = process_one_automatic_report(factory)
    report_id = str(processed.report_id)

    pdf = client.get(f"/v1/reports/{report_id}/pdf", headers=_auth(token))
    assert pdf.status_code == 200, pdf.text
    from io import BytesIO

    from pypdf import PdfReader

    text = "\n".join(
        (page.extract_text() or "") for page in PdfReader(BytesIO(pdf.content)).pages
    )
    assert "Automatic after scheduled assessment" in text

    created = client.post(
        f"/v1/reports/{report_id}/shares",
        headers=_auth(token),
        json={"expires_in": "24h"},
    ).json()
    secret = created["share_url"].rsplit("#", 1)[-1]
    payload = client.post(
        f"/v1/shared-reports/{created['id']}/resolve",
        json={"secret": secret},
    ).json()
    assert payload["report"]["generation_origin"] == "scheduled_automatic"
    dumped = json.dumps(payload)
    assert "generated_by" not in dumped
    assert "created_by_user_id" not in dumped
