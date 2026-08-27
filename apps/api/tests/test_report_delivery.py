from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from cryptography.exceptions import InvalidTag
from sqlalchemy import func, select
from sqlalchemy.orm import sessionmaker

from app.core.config import get_settings, reset_settings_cache
from app.models.audit import AuditEvent
from app.models.report import AssessmentReport
from app.models.report_delivery import (
    AssessmentReportDeliveryJob,
    AssessmentReportDeliveryOutbox,
)
from app.models.report_share import AssessmentReportShare
from app.services.clerk import ClerkOrgMembership, ClerkUserInfo
from app.services.discovery.runner import FakeDiscoveryTools
from app.services.email_provider import FakeEmailProvider
from app.services.reports.auto import process_one_automatic_report
from app.services.reports.delivery import (
    claim_delivery_job,
    claim_delivery_outbox,
    complete_claimed_delivery_job,
    complete_claimed_delivery_outbox,
    process_one_delivery_intent,
    process_one_report_delivery_email,
)
from app.services.reports.delivery_crypto import (
    decrypt_share_secret,
    encrypt_share_secret,
    parse_report_delivery_key,
)
from app.services.reports.share import hash_share_secret
from app.services.scheduler_runtime import process_one_scheduled_monitoring
from app.services.worker_runtime import process_one_operation
from tests.test_report_auto import _auth, _clean_probe, _due_monitoring
from tests.test_reports import _create_verified_target


@pytest.fixture(autouse=True)
def _reset_settings():
    reset_settings_cache()
    yield
    reset_settings_cache()


def _enable_mail(monkeypatch, *, enabled: bool = True) -> None:
    monkeypatch.setenv("EMAIL_DELIVERY_ENABLED", "true" if enabled else "false")
    monkeypatch.setenv("EMAIL_PROVIDER", "fake")
    monkeypatch.setenv("EMAIL_FROM", "scout@example.test")
    reset_settings_cache()


def _configure_delivery(
    client,
    token: str,
    target_id: str,
    *,
    recipients: list[str] | None = None,
    auto_deliver: bool | None = True,
    expires_in: str | None = "7d",
    auto_generate: bool | None = True,
):
    payload: dict = {"enabled": True, "frequency": "daily"}
    if auto_generate is not None:
        payload["auto_generate_reports"] = auto_generate
    if auto_deliver is not None:
        payload["auto_deliver_reports"] = auto_deliver
    if expires_in is not None:
        payload["auto_deliver_expires_in"] = expires_in
    if recipients is not None:
        payload["recipients"] = recipients
    response = client.put(
        f"/v1/targets/{target_id}/monitoring",
        headers=_auth(token),
        json=payload,
    )
    assert response.status_code == 200, response.text
    return response.json()


def _prepare_ready_report(
    client,
    token,
    dns_resolver,
    engine,
    db_session,
    domain: str,
    *,
    recipients: list[str],
    monkeypatch,
    mail_enabled: bool,
):
    _enable_mail(monkeypatch, enabled=mail_enabled)
    target_id = _create_verified_target(client, token, domain, dns_resolver)
    _configure_delivery(client, token, target_id, recipients=recipients)
    _due_monitoring(db_session, target_id)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    scheduled = process_one_scheduled_monitoring(factory)
    assert scheduled is not None
    tools = FakeDiscoveryTools(
        hosts_by_domain={domain: []},
        probes_by_host={domain: _clean_probe(domain)},
    )
    operation = process_one_operation(factory, tools=tools)
    assert operation is not None
    processed = process_one_automatic_report(factory)
    assert processed is not None
    assert processed.status == "succeeded"
    db_session.expire_all()
    report = db_session.scalar(
        select(AssessmentReport).where(AssessmentReport.operation_id == operation.id)
    )
    assert report is not None
    return target_id, operation.id, report, factory


def _intent(db_session, operation_id) -> AssessmentReportDeliveryJob | None:
    db_session.expire_all()
    return db_session.scalar(
        select(AssessmentReportDeliveryJob).where(
            AssessmentReportDeliveryJob.operation_id == operation_id
        )
    )


def _outbox(db_session, job_id) -> list[AssessmentReportDeliveryOutbox]:
    db_session.expire_all()
    return list(
        db_session.scalars(
            select(AssessmentReportDeliveryOutbox).where(
                AssessmentReportDeliveryOutbox.delivery_job_id == job_id
            )
        ).all()
    )


def test_pending_outbox_has_no_plaintext_secret_or_fragment(
    client, make_token, seed_user_a, dns_resolver, engine, db_session, monkeypatch
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    _, _, _, factory = _prepare_ready_report(
        client,
        token,
        dns_resolver,
        engine,
        db_session,
        "del-secret.example",
        recipients=["alpha@example.com"],
        monkeypatch=monkeypatch,
        mail_enabled=True,
    )
    intent = process_one_delivery_intent(factory, settings=get_settings())
    assert intent is not None
    assert intent.status == "succeeded"
    rows = _outbox(db_session, intent.id)
    assert len(rows) == 1
    row = rows[0]
    blob = json.dumps(
        {
            "destination_key": row.destination_key,
            "frozen_frontend_origin": row.frozen_frontend_origin,
            "frozen_subject": row.frozen_subject,
            "frozen_from_email": row.frozen_from_email,
            "status": row.status,
        }
    )
    assert "/share/" not in blob
    assert "#" not in blob
    assert row.encrypted_secret is not None
    assert row.encrypted_secret_nonce is not None
    assert row.encrypted_secret is not None
    assert row.encrypted_secret_nonce is not None
    key = parse_report_delivery_key(get_settings().report_delivery_secret_key)
    secret = decrypt_share_secret(
        nonce=bytes(row.encrypted_secret_nonce),
        ciphertext=bytes(row.encrypted_secret),
        key=key,
    )
    share = db_session.get(AssessmentReportShare, row.share_id)
    assert share is not None
    assert hash_share_secret(secret) == share.secret_hash
    wrong = parse_report_delivery_key("bb" * 32)
    with pytest.raises(InvalidTag):
        decrypt_share_secret(
            nonce=bytes(row.encrypted_secret_nonce),
            ciphertext=bytes(row.encrypted_secret),
            key=wrong,
        )


def test_email_paused_leaves_intent_pending_without_shares(
    client, make_token, seed_user_a, dns_resolver, engine, db_session, monkeypatch
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    _, operation_id, _, factory = _prepare_ready_report(
        client,
        token,
        dns_resolver,
        engine,
        db_session,
        "del-pause.example",
        recipients=["paused@example.com"],
        monkeypatch=monkeypatch,
        mail_enabled=False,
    )
    intent = _intent(db_session, operation_id)
    assert intent is not None
    assert intent.status == "pending"
    assert process_one_delivery_intent(factory, settings=get_settings()) is None
    db_session.expire_all()
    assert db_session.scalar(select(func.count()).select_from(AssessmentReportShare)) == 0
    assert (
        db_session.scalar(select(func.count()).select_from(AssessmentReportDeliveryOutbox))
        == 0
    )
    _enable_mail(monkeypatch, enabled=True)
    materialized = process_one_delivery_intent(factory, settings=get_settings())
    assert materialized is not None
    assert materialized.status == "succeeded"
    assert len(_outbox(db_session, materialized.id)) == 1


def test_missing_encryption_key_fails_closed(
    client, make_token, seed_user_a, dns_resolver, engine, db_session, monkeypatch
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    _, operation_id, _, factory = _prepare_ready_report(
        client,
        token,
        dns_resolver,
        engine,
        db_session,
        "del-nokey.example",
        recipients=["nokey@example.com"],
        monkeypatch=monkeypatch,
        mail_enabled=True,
    )
    monkeypatch.setenv("REPORT_DELIVERY_SECRET_KEY", "")
    reset_settings_cache()
    assert process_one_delivery_intent(factory, settings=get_settings()) is None
    intent = _intent(db_session, operation_id)
    assert intent is not None
    assert intent.status == "pending"
    db_session.expire_all()
    assert db_session.scalar(select(func.count()).select_from(AssessmentReportShare)) == 0
    assert client.get("/ready").json()["status"] == "ready"


def test_recipient_freeze_additions_do_not_join(
    client, make_token, seed_user_a, dns_resolver, engine, db_session, monkeypatch
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    target_id, _, _, factory = _prepare_ready_report(
        client,
        token,
        dns_resolver,
        engine,
        db_session,
        "del-freeze.example",
        recipients=["alpha@example.com"],
        monkeypatch=monkeypatch,
        mail_enabled=True,
    )
    _configure_delivery(
        client,
        token,
        target_id,
        recipients=["alpha@example.com", "bravo@example.com"],
    )
    intent = process_one_delivery_intent(factory, settings=get_settings())
    assert intent is not None
    rows = _outbox(db_session, intent.id)
    emails = {row.recipient_email_normalized for row in rows}
    assert emails == {"alpha@example.com"}


def test_remove_recipient_before_materialization_skips(
    client, make_token, seed_user_a, dns_resolver, engine, db_session, monkeypatch
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    target_id, _, _, factory = _prepare_ready_report(
        client,
        token,
        dns_resolver,
        engine,
        db_session,
        "del-remove.example",
        recipients=["alpha@example.com"],
        monkeypatch=monkeypatch,
        mail_enabled=True,
    )
    _configure_delivery(client, token, target_id, recipients=["bravo@example.com"])
    intent = process_one_delivery_intent(factory, settings=get_settings())
    assert intent is not None
    assert intent.status == "skipped"
    db_session.expire_all()
    assert db_session.scalar(select(func.count()).select_from(AssessmentReportShare)) == 0
    assert (
        db_session.scalar(select(func.count()).select_from(AssessmentReportDeliveryOutbox))
        == 0
    )


def test_remove_recipient_after_materialization_revokes_and_scrubs(
    client, make_token, seed_user_a, dns_resolver, engine, db_session, monkeypatch
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    target_id, _, _, factory = _prepare_ready_report(
        client,
        token,
        dns_resolver,
        engine,
        db_session,
        "del-revoke.example",
        recipients=["alpha@example.com"],
        monkeypatch=monkeypatch,
        mail_enabled=True,
    )
    intent = process_one_delivery_intent(factory, settings=get_settings())
    assert intent is not None
    rows = _outbox(db_session, intent.id)
    assert len(rows) == 1
    share_id = rows[0].share_id
    _configure_delivery(client, token, target_id, recipients=[])
    provider = FakeEmailProvider()
    processed = process_one_report_delivery_email(
        factory, provider=provider, settings=get_settings()
    )
    assert processed is not None
    db_session.expire_all()
    row = db_session.get(AssessmentReportDeliveryOutbox, processed.id)
    share = db_session.get(AssessmentReportShare, share_id)
    assert row.status == "skipped"
    assert row.last_error_code == "recipient_removed"
    assert row.encrypted_secret is None
    assert row.encrypted_secret_nonce is None
    assert share.revoked_at is not None
    assert provider.requests == []


def test_per_recipient_shares_are_independent(
    client, make_token, seed_user_a, dns_resolver, engine, db_session, monkeypatch
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    _, _, report, factory = _prepare_ready_report(
        client,
        token,
        dns_resolver,
        engine,
        db_session,
        "del-two.example",
        recipients=["alpha@example.com", "bravo@example.com"],
        monkeypatch=monkeypatch,
        mail_enabled=True,
    )
    intent = process_one_delivery_intent(factory, settings=get_settings())
    assert intent is not None
    rows = _outbox(db_session, intent.id)
    assert len(rows) == 2
    shares = [
        db_session.get(AssessmentReportShare, row.share_id) for row in rows
    ]
    hashes = {share.secret_hash for share in shares}
    assert len(hashes) == 2
    first = shares[0]
    revoke = client.post(
        f"/v1/report-shares/{first.id}/revoke",
        headers=_auth(token),
    )
    assert revoke.status_code == 200
    db_session.expire_all()
    other = db_session.get(AssessmentReportShare, shares[1].id)
    assert other.revoked_at is None
    listed = client.get(
        f"/v1/reports/{report.id}/shares", headers=_auth(token)
    ).json()
    assert all(item["creation_origin"] == "scheduled_automatic" for item in listed)
    assert all(item["created_by_user_id"] is None for item in listed)


def test_repeated_materialization_reuses_rows(
    client, make_token, seed_user_a, dns_resolver, engine, db_session, monkeypatch
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    _, operation_id, _, factory = _prepare_ready_report(
        client,
        token,
        dns_resolver,
        engine,
        db_session,
        "del-idem.example",
        recipients=["alpha@example.com"],
        monkeypatch=monkeypatch,
        mail_enabled=True,
    )
    first = process_one_delivery_intent(factory, settings=get_settings())
    assert first is not None
    second = process_one_delivery_intent(factory, settings=get_settings())
    assert second is None
    db_session.expire_all()
    assert (
        db_session.scalar(select(func.count()).select_from(AssessmentReportShare)) == 1
    )
    assert (
        db_session.scalar(select(func.count()).select_from(AssessmentReportDeliveryOutbox))
        == 1
    )
    intents = list(
        db_session.scalars(
            select(AssessmentReportDeliveryJob).where(
                AssessmentReportDeliveryJob.operation_id == operation_id
            )
        )
    )
    assert len(intents) == 1


def test_stale_claimant_cannot_complete_intent(
    client, make_token, seed_user_a, dns_resolver, engine, db_session, monkeypatch
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    _, _, _, factory = _prepare_ready_report(
        client,
        token,
        dns_resolver,
        engine,
        db_session,
        "del-fence.example",
        recipients=["alpha@example.com"],
        monkeypatch=monkeypatch,
        mail_enabled=True,
    )
    db = factory()
    try:
        claimed = claim_delivery_job(db)
        assert claimed is not None
        job, token_a = claimed
        owned = complete_claimed_delivery_job(
            db,
            job_id=job.id,
            processing_token=uuid4(),
            values={"status": "succeeded"},
        )
        assert owned is False
        current = db.get(AssessmentReportDeliveryJob, job.id)
        assert current.status == "processing"
        assert current.processing_token == token_a
    finally:
        db.close()


def test_stale_claimant_cannot_complete_outbox(
    client, make_token, seed_user_a, dns_resolver, engine, db_session, monkeypatch
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    _, _, _, factory = _prepare_ready_report(
        client,
        token,
        dns_resolver,
        engine,
        db_session,
        "del-outbox-fence.example",
        recipients=["alpha@example.com"],
        monkeypatch=monkeypatch,
        mail_enabled=True,
    )
    intent = process_one_delivery_intent(factory, settings=get_settings())
    assert intent is not None
    db = factory()
    try:
        claimed = claim_delivery_outbox(db)
        assert claimed is not None
        row, token_a = claimed
        owned = complete_claimed_delivery_outbox(
            db,
            outbox_id=row.id,
            processing_token=uuid4(),
            values={"status": "delivered"},
        )
        assert owned is False
        current = db.get(AssessmentReportDeliveryOutbox, row.id)
        assert current.status == "processing"
        assert current.processing_token == token_a
        assert current.encrypted_secret is not None
    finally:
        db.close()


def test_provider_send_uses_outbox_id_and_scrubs_secret(
    client, make_token, seed_user_a, dns_resolver, engine, db_session, monkeypatch, caplog
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    _, _, _, factory = _prepare_ready_report(
        client,
        token,
        dns_resolver,
        engine,
        db_session,
        "del-send.example",
        recipients=["alpha@example.com"],
        monkeypatch=monkeypatch,
        mail_enabled=True,
    )
    intent = process_one_delivery_intent(factory, settings=get_settings())
    row = _outbox(db_session, intent.id)[0]
    ciphertext = bytes(row.encrypted_secret)
    provider = FakeEmailProvider()
    caplog.set_level("INFO")
    sent = process_one_report_delivery_email(
        factory, provider=provider, settings=get_settings()
    )
    assert sent is not None
    assert len(provider.requests) == 1
    request = provider.requests[0]
    assert request.idempotency_key == str(row.id)
    assert request.to_email == "alpha@example.com"
    assert "/share/" in request.text_body
    assert "#" in request.text_body
    db_session.expire_all()
    fresh = db_session.get(AssessmentReportDeliveryOutbox, row.id)
    assert fresh.status == "delivered"
    assert fresh.encrypted_secret is None
    assert fresh.encrypted_secret_nonce is None
    logs = caplog.text
    assert "alpha@example.com" not in logs
    assert bytes(ciphertext).hex() not in logs
    events = list(
        db_session.scalars(select(AuditEvent).where(AuditEvent.organization_id.is_not(None)))
    )
    dumped = json.dumps([event.event_metadata for event in events])
    assert "alpha@example.com" not in dumped
    assert "encrypted_secret" not in dumped
    assert ciphertext.hex() not in dumped
    sent_again = process_one_report_delivery_email(
        factory, provider=provider, settings=get_settings()
    )
    assert sent_again is None
    assert len(provider.requests) == 1


def test_disable_auto_deliver_before_materialization_skips(
    client, make_token, seed_user_a, dns_resolver, engine, db_session, monkeypatch
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    target_id, _, _, factory = _prepare_ready_report(
        client,
        token,
        dns_resolver,
        engine,
        db_session,
        "del-disable.example",
        recipients=["alpha@example.com"],
        monkeypatch=monkeypatch,
        mail_enabled=True,
    )
    _configure_delivery(client, token, target_id, auto_deliver=False, recipients=None)
    intent = process_one_delivery_intent(factory, settings=get_settings())
    assert intent is not None
    assert intent.status == "skipped"
    db_session.expire_all()
    assert db_session.scalar(select(func.count()).select_from(AssessmentReportShare)) == 0


def test_expiry_starts_at_share_materialization(
    client, make_token, seed_user_a, dns_resolver, engine, db_session, monkeypatch
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    _, operation_id, _, factory = _prepare_ready_report(
        client,
        token,
        dns_resolver,
        engine,
        db_session,
        "del-exp.example",
        recipients=["alpha@example.com"],
        monkeypatch=monkeypatch,
        mail_enabled=True,
    )
    intent = _intent(db_session, operation_id)
    assert intent.created_at is not None
    intent.created_at = datetime.now(UTC) - timedelta(days=3)
    db_session.commit()
    materialized = process_one_delivery_intent(factory, settings=get_settings())
    assert materialized is not None
    share = db_session.scalars(select(AssessmentReportShare)).first()
    assert share is not None
    delta = share.expires_at - share.created_at
    assert timedelta(days=6, hours=23) < delta < timedelta(days=7, hours=1)
    assert share.created_at > intent.created_at


def test_admin_sees_recipients_member_sees_count_only(
    client, make_token, seed_user_a, fake_clerk, dns_resolver, engine, db_session, monkeypatch
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    target_id, _, report, factory = _prepare_ready_report(
        client,
        token,
        dns_resolver,
        engine,
        db_session,
        "del-priv.example",
        recipients=["alpha@example.com"],
        monkeypatch=monkeypatch,
        mail_enabled=True,
    )
    admin = client.get(f"/v1/targets/{target_id}/monitoring", headers=_auth(token)).json()
    assert admin["recipients"] == ["alpha@example.com"]
    assert admin["recipient_count"] == 1
    clerk_member = f"user_{uuid4().hex}"
    fake_clerk.users[clerk_member] = ClerkUserInfo(
        clerk_user_id=clerk_member,
        email="member@example.com",
        name="Member",
        email_verified=True,
    )
    fake_clerk.memberships[clerk_member] = [
        ClerkOrgMembership(clerk_org_id=org_id, org_name="Org A", role="org:member")
    ]
    member_token = make_token(sub=clerk_member, org_id=org_id, org_role="org:member")
    member = client.get(
        f"/v1/targets/{target_id}/monitoring", headers=_auth(member_token)
    ).json()
    assert member["recipient_count"] == 1
    assert member["auto_deliver_reports"] is True
    assert member["recipients"] is None
    process_one_delivery_intent(factory, settings=get_settings())
    detail = client.get(f"/v1/reports/{report.id}", headers=_auth(member_token)).json()
    assert detail["automatic_delivery"]["frozen_recipient_count"] == 1
    assert "alpha@example.com" not in json.dumps(detail)


def test_legacy_monitoring_put_preserves_auto_deliver(
    client, make_token, seed_user_a, dns_resolver
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    target_id = _create_verified_target(client, token, "del-legacy.example", dns_resolver)
    enabled = _configure_delivery(
        client, token, target_id, recipients=["alpha@example.com"]
    )
    assert enabled["auto_deliver_reports"] is True
    legacy = client.put(
        f"/v1/targets/{target_id}/monitoring",
        headers=_auth(token),
        json={"enabled": True, "frequency": "weekly"},
    )
    assert legacy.status_code == 200
    body = legacy.json()
    assert body["auto_deliver_reports"] is True
    assert body["recipients"] == ["alpha@example.com"]
    assert body["auto_deliver_expires_in"] == "7d"


def test_encrypt_roundtrip_and_empty_key():
    key = parse_report_delivery_key("aa" * 32)
    encrypted = encrypt_share_secret("abc", key=key)
    assert decrypt_share_secret(
        nonce=encrypted.nonce, ciphertext=encrypted.ciphertext, key=key
    ) == "abc"
    assert parse_report_delivery_key("") is None
    assert parse_report_delivery_key("zz") is None
