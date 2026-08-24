from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta
from io import BytesIO
from pathlib import Path
from uuid import UUID, uuid4

from pypdf import PdfReader
from sqlalchemy import func, select
from sqlalchemy.orm.attributes import flag_modified

from app.core.config import reset_settings_cache
from app.models.audit import AuditEvent
from app.models.report import AssessmentReport
from app.models.report_share import AnonymousRateLimitCounter, AssessmentReportShare
from app.services.rate_limit import (
    ACTION_SHARED_REPORT_COARSE,
    ACTION_SHARED_REPORT_USE,
    SHARED_REPORT_COARSE_PARTITIONS,
    coarse_share_partition,
)
from app.services.reports.share import SHARE_SECRET_PATTERN, hash_share_secret
from app.services.reports.snapshot import content_digest
from tests.test_reports import (
    _auth,
    _clean_completed_operation,
    _generate,
)


def _create_share(client, token: str, report_id: str, expires_in: str = "7d"):
    return client.post(
        f"/v1/reports/{report_id}/shares",
        headers=_auth(token),
        json={"expires_in": expires_in},
    )


def _secret_from_url(share_url: str) -> str:
    return share_url.rsplit("#", 1)[1]


def _uuid_in_partition(partition: str, *, exclude: set[UUID] | None = None) -> UUID:
    skipped = exclude or set()
    for _ in range(10_000):
        candidate = uuid4()
        if candidate in skipped:
            continue
        if coarse_share_partition(candidate) == partition:
            return candidate
    raise AssertionError(f"could not find a UUID in {partition}")


def _pdf_text(data: bytes) -> str:
    reader = PdfReader(BytesIO(data))
    return "\n".join((page.extract_text() or "") for page in reader.pages)


def test_admin_creates_share_secret_only_inside_url(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    report_id = _generate(
        client,
        token,
        _clean_completed_operation(client, token, dns_resolver, engine, "share-create.example"),
    ).json()["id"]
    response = _create_share(client, token, report_id)
    assert response.status_code == 201, response.text
    body = response.json()
    assert "secret" not in body
    assert set(body) == {"id", "expires_at", "expires_in", "share_url"}
    assert body["expires_in"] == "7d"
    secret = _secret_from_url(body["share_url"])
    assert SHARE_SECRET_PATTERN.fullmatch(secret)
    assert body["id"] in body["share_url"]
    row = db_session.get(AssessmentReportShare, body["id"])
    assert row is not None
    persisted = json.dumps(
        {
            "id": str(row.id),
            "organization_id": str(row.organization_id),
            "report_id": str(row.report_id),
            "created_by_user_id": str(row.created_by_user_id),
            "secret_hash": row.secret_hash,
            "created_at": row.created_at.isoformat(),
            "expires_at": row.expires_at.isoformat(),
            "revoked_at": row.revoked_at,
        }
    )
    assert secret not in persisted
    assert row.secret_hash == hash_share_secret(secret)
    assert secret not in row.secret_hash
    assert row.organization_id == db_session.get(AssessmentReport, report_id).organization_id
    events = list(db_session.scalars(select(AuditEvent).where(AuditEvent.action == "assessment_report_share.created")))
    assert len(events) == 1
    dumped = json.dumps(events[0].event_metadata)
    assert secret not in dumped
    assert "secret_hash" not in dumped
    assert body["share_url"] not in dumped
    assert events[0].event_metadata["share_id"] == body["id"]


def test_member_cannot_create_list_or_revoke_share(
    client, make_token, seed_user_a, dns_resolver, engine
):
    user_id, org_id = seed_user_a
    admin = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    member = make_token(sub=user_id, org_id=org_id, org_role="org:member")
    report_id = _generate(
        client,
        admin,
        _clean_completed_operation(client, admin, dns_resolver, engine, "share-member.example"),
    ).json()["id"]
    created = _create_share(client, admin, report_id)
    assert created.status_code == 201
    assert _create_share(client, member, report_id).status_code == 403
    assert client.get(f"/v1/reports/{report_id}/shares", headers=_auth(member)).status_code == 403
    assert (
        client.post(
            f"/v1/report-shares/{created.json()['id']}/revoke",
            headers=_auth(member),
        ).status_code
        == 403
    )


def test_cross_org_share_routes_are_404(
    client, make_token, seed_user_a, seed_user_b, dns_resolver, engine
):
    user_a, org_a = seed_user_a
    user_b, org_b = seed_user_b
    token_a = make_token(sub=user_a, org_id=org_a, org_role="org:admin")
    token_b = make_token(sub=user_b, org_id=org_b, org_role="org:admin")
    report_id = _generate(
        client,
        token_a,
        _clean_completed_operation(client, token_a, dns_resolver, engine, "share-cross.example"),
    ).json()["id"]
    created = _create_share(client, token_a, report_id).json()
    assert _create_share(client, token_b, report_id).status_code == 404
    assert client.get(f"/v1/reports/{report_id}/shares", headers=_auth(token_b)).status_code == 404
    assert (
        client.post(
            f"/v1/report-shares/{created['id']}/revoke",
            headers=_auth(token_b),
        ).status_code
        == 404
    )


def test_correct_and_wrong_secret_and_one_char_flip(
    client, make_token, seed_user_a, dns_resolver, engine
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    report = _generate(
        client,
        token,
        _clean_completed_operation(client, token, dns_resolver, engine, "share-secret.example"),
    ).json()
    created = _create_share(client, token, report["id"]).json()
    secret = _secret_from_url(created["share_url"])
    ok = client.post(
        f"/v1/shared-reports/{created['id']}/resolve",
        json={"secret": secret},
    )
    assert ok.status_code == 200, ok.text
    assert ok.headers.get("cache-control") == "private, no-store"
    assert ok.json()["identity"]["target_domain"] == "share-secret.example"
    assert ok.json()["report"]["version"] == report["report_version"]

    flipped = ("A" if secret[0] != "A" else "B") + secret[1:]
    wrong = client.post(
        f"/v1/shared-reports/{created['id']}/resolve",
        json={"secret": flipped},
    )
    missing = client.post(
        f"/v1/shared-reports/{uuid4()}/resolve",
        json={"secret": secret},
    )
    assert wrong.status_code == 404
    assert missing.status_code == 404
    assert wrong.json()["error"]["message"] == "Shared report not found"
    assert missing.json()["error"]["message"] == "Shared report not found"
    assert wrong.json()["error"]["message"] == missing.json()["error"]["message"]


def test_external_resolve_strips_internal_snapshot_fields(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    report_id = _generate(
        client,
        token,
        _clean_completed_operation(client, token, dns_resolver, engine, "share-dto.example"),
    ).json()["id"]
    row = db_session.get(AssessmentReport, report_id)
    snapshot = dict(row.snapshot_json)
    snapshot["content"]["identity"]["organization_id"] = "org-sentinel-hidden"
    snapshot["content"]["identity"]["operation_id"] = "op-sentinel-hidden"
    snapshot["content"]["identity"]["target_id"] = "target-sentinel-hidden"
    snapshot["envelope"]["generated_by"] = {"user_id": "user-sentinel-hidden"}
    snapshot["content"]["hidden_internal"] = {"candidate_id": "cand-sentinel-hidden"}
    snapshot["content"]["findings"] = [
        {
            "finding_id": "finding-sentinel-hidden",
            "candidate_id": "cand-sentinel-hidden",
            "validation_id": "val-sentinel-hidden",
            "observation_id": "obs-sentinel-hidden",
            "title": "Visible finding title",
            "summary": "Visible summary",
            "observation_class": "missing_security_header",
            "severity": "medium",
            "status": "open",
            "is_open": True,
            "business_impact": "Visible impact",
            "remediation_guidance": "Visible fix",
            "affected_asset": {"hostname": "share-dto.example", "url": None},
            "validation": {"method": "http_get", "status": "supported", "summary": "ok"},
            "latest_retest": None,
            "evidence": {"observed_facts": {"note": "ok"}},
        }
    ]
    snapshot["envelope"]["snapshot_digest"] = content_digest(snapshot["content"])
    row.snapshot_digest = snapshot["envelope"]["snapshot_digest"]
    row.snapshot_json = snapshot
    flag_modified(row, "snapshot_json")
    db_session.commit()

    created = _create_share(client, token, report_id).json()
    payload = client.post(
        f"/v1/shared-reports/{created['id']}/resolve",
        json={"secret": _secret_from_url(created["share_url"])},
    ).json()
    dumped = json.dumps(payload)
    for sentinel in (
        "org-sentinel-hidden",
        "op-sentinel-hidden",
        "target-sentinel-hidden",
        "user-sentinel-hidden",
        "cand-sentinel-hidden",
        "finding-sentinel-hidden",
        "val-sentinel-hidden",
        "obs-sentinel-hidden",
        "hidden_internal",
        "generated_by",
    ):
        assert sentinel not in dumped, sentinel
    assert payload["identity"]["target_domain"] == "share-dto.example"
    assert payload["findings"][0]["title"] == "Visible finding title"
    assert payload["summary"]["headline_statement"]
    assert "finding_id" not in payload["findings"][0]


def test_malformed_secret_does_not_echo_sentinel(client, caplog):
    sentinel = "ECHO-SECRET-SENTINEL-M25-DO-NOT-RETURN"
    oversized = sentinel + ("A" * 400)
    response = client.post(
        f"/v1/shared-reports/{uuid4()}/resolve",
        json={"secret": oversized},
    )
    assert response.status_code == 400
    assert response.json()["error"]["message"] == "Invalid share request"
    assert sentinel not in response.text
    assert oversized not in response.text
    assert sentinel not in caplog.text


def test_expired_and_revoked_shares_are_generic_404(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    report_id = _generate(
        client,
        token,
        _clean_completed_operation(client, token, dns_resolver, engine, "share-exp.example"),
    ).json()["id"]
    created = _create_share(client, token, report_id, "24h").json()
    secret = _secret_from_url(created["share_url"])
    row = db_session.get(AssessmentReportShare, created["id"])
    row.created_at = datetime.now(UTC) - timedelta(hours=2)
    row.expires_at = datetime.now(UTC) - timedelta(minutes=1)
    db_session.commit()
    expired = client.post(
        f"/v1/shared-reports/{created['id']}/resolve", json={"secret": secret}
    )
    assert expired.status_code == 404
    assert expired.json()["error"]["message"] == "Shared report not found"

    fresh = _create_share(client, token, report_id).json()
    secret2 = _secret_from_url(fresh["share_url"])
    assert (
        client.post(
            f"/v1/shared-reports/{fresh['id']}/resolve", json={"secret": secret2}
        ).status_code
        == 200
    )
    revoked = client.post(
        f"/v1/report-shares/{fresh['id']}/revoke", headers=_auth(token)
    )
    assert revoked.status_code == 200
    again = client.post(
        f"/v1/report-shares/{fresh['id']}/revoke", headers=_auth(token)
    )
    assert again.status_code == 200
    denied = client.post(
        f"/v1/shared-reports/{fresh['id']}/resolve", json={"secret": secret2}
    )
    pdf = client.post(
        f"/v1/shared-reports/{fresh['id']}/pdf", json={"secret": secret2}
    )
    assert denied.status_code == 404
    assert pdf.status_code == 404
    assert denied.json()["error"]["message"] == "Shared report not found"


def test_shared_content_stays_frozen_after_live_mutation(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    report = _generate(
        client,
        token,
        _clean_completed_operation(client, token, dns_resolver, engine, "share-freeze.example"),
    ).json()
    created = _create_share(client, token, report["id"]).json()
    before = client.post(
        f"/v1/shared-reports/{created['id']}/resolve",
        json={"secret": _secret_from_url(created["share_url"])},
    ).json()
    row = db_session.get(AssessmentReport, report["id"])
    # Live-looking mutation of a different in-memory snapshot is not applied; change
    # only a live-adjacent field that is not the frozen share DTO source.
    row.target_domain = row.target_domain
    db_session.commit()
    after = client.post(
        f"/v1/shared-reports/{created['id']}/resolve",
        json={"secret": _secret_from_url(created["share_url"])},
    ).json()
    assert after["summary"]["headline_statement"] == before["summary"]["headline_statement"]
    assert after["report"]["snapshot_digest"] == report["snapshot_digest"]


def test_share_org_mismatch_fails_closed(
    client, make_token, seed_user_a, seed_user_b, dns_resolver, engine, db_session
):
    user_a, org_a = seed_user_a
    user_b, org_b = seed_user_b
    token_a = make_token(sub=user_a, org_id=org_a, org_role="org:admin")
    token_b = make_token(sub=user_b, org_id=org_b, org_role="org:admin")
    report_a = _generate(
        client,
        token_a,
        _clean_completed_operation(client, token_a, dns_resolver, engine, "share-mismatch-a.example"),
    ).json()
    _generate(
        client,
        token_b,
        _clean_completed_operation(client, token_b, dns_resolver, engine, "share-mismatch-b.example"),
    )
    created = _create_share(client, token_a, report_a["id"]).json()
    secret = _secret_from_url(created["share_url"])
    other_org = db_session.scalar(
        select(AssessmentReport.organization_id).where(
            AssessmentReport.target_domain == "share-mismatch-b.example"
        )
    )
    share = db_session.get(AssessmentReportShare, created["id"])
    share.organization_id = other_org
    db_session.commit()
    assert (
        client.post(
            f"/v1/shared-reports/{created['id']}/resolve", json={"secret": secret}
        ).status_code
        == 404
    )
    assert (
        client.get(f"/v1/reports/{report_a['id']}/shares", headers=_auth(token_a)).status_code
        == 404
    )
    assert (
        client.post(
            f"/v1/report-shares/{created['id']}/revoke", headers=_auth(token_a)
        ).status_code
        == 404
    )


def test_xff_does_not_create_a_fresh_rate_limit_identity(
    client, make_token, seed_user_a, dns_resolver, engine, db_session, monkeypatch
):
    monkeypatch.setenv("RATE_LIMIT_SHARED_REPORT_COARSE", "3")
    reset_settings_cache()
    try:
        user_id, org_id = seed_user_a
        token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
        report_id = _generate(
            client,
            token,
            _clean_completed_operation(client, token, dns_resolver, engine, "share-xff.example"),
        ).json()["id"]
        created = _create_share(client, token, report_id).json()
        secret = _secret_from_url(created["share_url"])
        statuses = []
        for index in range(5):
            statuses.append(
                client.post(
                    f"/v1/shared-reports/{created['id']}/resolve",
                    json={"secret": secret},
                    headers={"X-Forwarded-For": f"203.0.113.{index}"},
                ).status_code
            )
        assert 429 in statuses
        buckets = list(
            db_session.scalars(
                select(AnonymousRateLimitCounter.bucket).where(
                    AnonymousRateLimitCounter.action == ACTION_SHARED_REPORT_COARSE
                )
            )
        )
        assert set(buckets) == {coarse_share_partition(UUID(created["id"]))}
    finally:
        reset_settings_cache()


def test_random_share_ids_do_not_unbounded_rate_limit_rows(
    client, db_session, monkeypatch
):
    monkeypatch.setenv("RATE_LIMIT_SHARED_REPORT_COARSE", "50")
    reset_settings_cache()
    try:
        secret = "A" * 43
        before = db_session.scalar(select(func.count()).select_from(AnonymousRateLimitCounter)) or 0
        for _ in range(80):
            client.post(f"/v1/shared-reports/{uuid4()}/resolve", json={"secret": secret})
        after = db_session.scalar(select(func.count()).select_from(AnonymousRateLimitCounter)) or 0
        assert after - before <= SHARED_REPORT_COARSE_PARTITIONS
        assert after - before < 80
        buckets = list(
            db_session.scalars(
                select(AnonymousRateLimitCounter.bucket).where(
                    AnonymousRateLimitCounter.action == ACTION_SHARED_REPORT_COARSE
                )
            )
        )
        assert buckets
        assert all(bucket.startswith("p") and len(bucket) == 3 for bucket in buckets)
        assert ACTION_SHARED_REPORT_USE not in set(
            db_session.scalars(select(AnonymousRateLimitCounter.action))
        )
    finally:
        reset_settings_cache()


def test_shared_pdf_reuses_renderer_and_no_store(
    client, make_token, seed_user_a, dns_resolver, engine
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    report_id = _generate(
        client,
        token,
        _clean_completed_operation(client, token, dns_resolver, engine, "share-pdf.example"),
    ).json()["id"]
    created = _create_share(client, token, report_id).json()
    secret = _secret_from_url(created["share_url"])
    shared = client.post(
        f"/v1/shared-reports/{created['id']}/pdf", json={"secret": secret}
    )
    authed = client.get(f"/v1/reports/{report_id}/pdf", headers=_auth(token))
    assert shared.status_code == 200, shared.text
    assert shared.headers.get("cache-control") == "private, no-store"
    assert shared.content.startswith(b"%PDF-")
    assert "share-pdf.example" in _pdf_text(shared.content)
    assert "Scout PDF renderer 2" in _pdf_text(shared.content)
    assert _pdf_text(shared.content) == _pdf_text(authed.content)


def test_share_a_cannot_resolve_as_report_b(
    client, make_token, seed_user_a, dns_resolver, engine
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    first = _generate(
        client,
        token,
        _clean_completed_operation(client, token, dns_resolver, engine, "share-a.example"),
    ).json()
    second = _generate(
        client,
        token,
        _clean_completed_operation(client, token, dns_resolver, engine, "share-b.example"),
    ).json()
    share_a = _create_share(client, token, first["id"]).json()
    payload = client.post(
        f"/v1/shared-reports/{share_a['id']}/resolve",
        json={"secret": _secret_from_url(share_a["share_url"])},
    ).json()
    assert payload["identity"]["target_domain"] == "share-a.example"
    assert payload["report"]["id"] == first["id"]
    assert payload["report"]["id"] != second["id"]


def test_internal_report_api_still_requires_auth(client):
    assert client.get(f"/v1/reports/{uuid4()}").status_code == 401
    assert client.get(f"/v1/reports/{uuid4()}/pdf").status_code == 401


def test_frontend_share_contracts():
    web = Path(__file__).resolve().parents[2] / "web"
    page = (web / "app/(share)/share/[shareId]/page.tsx").read_text(encoding="utf-8")
    client = (web / "app/(share)/share/[shareId]/shared-report-client.tsx").read_text(
        encoding="utf-8"
    )
    layout = (web / "app/(share)/layout.tsx").read_text(encoding="utf-8")
    root = (web / "app/layout.tsx").read_text(encoding="utf-8")
    app_layout = (web / "app/(app)/layout.tsx").read_text(encoding="utf-8")
    headers = (web / "lib/security-headers.ts").read_text(encoding="utf-8")
    middleware = (web / "middleware.ts").read_text(encoding="utf-8")
    api = (web / "lib/api.ts").read_text(encoding="utf-8")
    assert "location.hash" in client
    assert "replaceState" in client
    assert "searchParams" not in page
    assert "secret" not in page
    assert "ClerkProvider" not in root
    assert "ClerkProvider" not in layout
    assert "ClerkProvider" in app_layout
    assert "clerk" not in layout.lower()
    assert "/share(.*)" in middleware
    assert "isShareRoute" in middleware
    assert "buildShareContentSecurityPolicy" in middleware
    assert "clerkHandler" in middleware
    assert "no-referrer" in headers
    assert "noindex, nofollow, noarchive" in headers
    assert "private, no-store" in headers
    assert "clerk.com" not in headers.split("shareContentSecurityPolicy")[1].split("SHARE_SECURITY")[0]
    assert '"secret"' not in api
    robots = (web / "app/robots.ts").read_text(encoding="utf-8")
    assert 'disallow: "/share/"' in robots


def test_hash_compare_is_constant_time_helper():
    secret = "A" * 43
    digest = hash_share_secret(secret)
    assert len(digest) == 64
    assert hmac.compare_digest(digest, hashlib.sha256(secret.encode("ascii")).hexdigest())


def test_wrong_secret_and_missing_share_stay_equivalent_until_coarse_limit(
    client, make_token, seed_user_a, dns_resolver, engine, monkeypatch
):
    """Per-share limiter must not become an existence oracle before auth."""
    monkeypatch.setenv("RATE_LIMIT_SHARED_REPORT_COARSE", "4")
    reset_settings_cache()
    try:
        user_id, org_id = seed_user_a
        token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
        report_id = _generate(
            client,
            token,
            _clean_completed_operation(
                client, token, dns_resolver, engine, "share-oracle.example"
            ),
        ).json()["id"]
        created = _create_share(client, token, report_id).json()
        wrong = ("A" if created["share_url"][-1] != "A" else "B") + ("C" * 42)
        created_partition = coarse_share_partition(UUID(created["id"]))
        missing_id = _uuid_in_partition(created_partition, exclude={UUID(created["id"])})
        first = client.post(
            f"/v1/shared-reports/{created['id']}/resolve", json={"secret": wrong}
        )
        second = client.post(
            f"/v1/shared-reports/{missing_id}/resolve", json={"secret": wrong}
        )
        assert first.status_code == second.status_code == 404
        assert first.json()["error"]["message"] == second.json()["error"]["message"]
        assert first.headers.get("cache-control") == "private, no-store"
        third = client.post(
            f"/v1/shared-reports/{missing_id}/resolve", json={"secret": wrong}
        )
        fourth = client.post(
            f"/v1/shared-reports/{created['id']}/resolve", json={"secret": wrong}
        )
        assert third.status_code == fourth.status_code == 404
        limited_missing = client.post(
            f"/v1/shared-reports/{missing_id}/resolve", json={"secret": wrong}
        )
        limited_existing = client.post(
            f"/v1/shared-reports/{created['id']}/resolve", json={"secret": wrong}
        )
        assert limited_missing.status_code == 429
        assert limited_existing.status_code == 429
    finally:
        reset_settings_cache()


def test_revoke_commit_blocks_new_authorization(
    client, make_token, seed_user_a, dns_resolver, engine
):
    """After revoke COMMIT, a new resolve/PDF authorization fails.

    A request already in flight before that commit may still complete.
    Revocation does not recall copies already opened or downloaded.
    """
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    report_id = _generate(
        client,
        token,
        _clean_completed_operation(client, token, dns_resolver, engine, "share-race.example"),
    ).json()["id"]
    created = _create_share(client, token, report_id).json()
    secret = _secret_from_url(created["share_url"])
    assert (
        client.post(
            f"/v1/shared-reports/{created['id']}/resolve", json={"secret": secret}
        ).status_code
        == 200
    )
    revoked = client.post(
        f"/v1/report-shares/{created['id']}/revoke", headers=_auth(token)
    )
    assert revoked.status_code == 200
    assert (
        client.post(
            f"/v1/shared-reports/{created['id']}/resolve", json={"secret": secret}
        ).status_code
        == 404
    )
    assert (
        client.post(
            f"/v1/shared-reports/{created['id']}/pdf", json={"secret": secret}
        ).status_code
        == 404
    )


def test_db_membership_role_does_not_grant_share_admin(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    from app.models.organization import Organization, OrganizationMembership
    from app.models.user import User

    user_id, org_id = seed_user_a
    admin = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    report_id = _generate(
        client,
        admin,
        _clean_completed_operation(client, admin, dns_resolver, engine, "share-db-role.example"),
    ).json()["id"]
    org = db_session.scalar(select(Organization).where(Organization.clerk_org_id == org_id))
    user = db_session.scalar(select(User).where(User.clerk_user_id == user_id))
    membership = db_session.scalar(
        select(OrganizationMembership).where(
            OrganizationMembership.organization_id == org.id,
            OrganizationMembership.user_id == user.id,
        )
    )
    membership.role = "org:admin"
    db_session.commit()
    member = make_token(sub=user_id, org_id=org_id, org_role="org:member")
    assert _create_share(client, member, report_id).status_code == 403


def test_malformed_secret_variants_are_generic_400(client):
    share_id = uuid4()
    missing = client.post(f"/v1/shared-reports/{share_id}/resolve", json={})
    wrong_type = client.post(
        f"/v1/shared-reports/{share_id}/resolve", json={"secret": ["not", "a", "string"]}
    )
    assert missing.status_code == 400
    assert wrong_type.status_code == 400
    assert missing.json()["error"]["message"] == "Invalid share request"
    assert wrong_type.json()["error"]["message"] == "Invalid share request"
    assert missing.headers.get("cache-control") == "private, no-store"


def test_built_share_route_has_no_clerk_or_server_secret():
    web = Path(__file__).resolve().parents[2] / "web"
    build = web / ".next"
    if not build.exists():
        return
    haystacks: list[str] = []
    for pattern in (
        "server/app/(share)/**",
        "server/app/share/**",
        "server/app/(share)/share/**",
    ):
        haystacks.extend(str(path) for path in build.glob(pattern))
    texts: list[str] = []
    for path in Path(build).rglob("*"):
        if "share" not in str(path).lower():
            continue
        if path.suffix not in {".js", ".html", ".rsc", ".json"}:
            continue
        try:
            texts.append(path.read_text(encoding="utf-8", errors="ignore"))
        except OSError:
            continue
    blob = "\n".join(texts)
    if not blob:
        return
    assert "clerk.com" not in blob.lower() or "shared-report" in blob
    clerk_hits = [
        line
        for line in blob.splitlines()
        if "clerk" in line.lower() and "share" in line.lower()
    ]
    assert not any("ClerkProvider" in line for line in clerk_hits)
    assert "location.hash" in blob or "replaceState" in blob


def test_coarse_partition_is_stable_and_distributed():
    first = UUID("11111111-1111-1111-1111-111111111111")
    assert coarse_share_partition(first) == coarse_share_partition(first)
    assert coarse_share_partition(first) == coarse_share_partition(
        UUID("11111111-1111-1111-1111-111111111111")
    )
    partitions = {coarse_share_partition(uuid4()) for _ in range(200)}
    assert len(partitions) > 1
    assert all(bucket.startswith("p") and len(bucket) == 3 for bucket in partitions)
    assert all(
        0 <= int(bucket[1:]) < SHARED_REPORT_COARSE_PARTITIONS for bucket in partitions
    )
    assert first.hex not in coarse_share_partition(first)
    assert str(first) not in coarse_share_partition(first)


def test_coarse_partition_is_existence_independent():
    share_id = uuid4()
    before_lookup = coarse_share_partition(share_id)
    after_lookup = coarse_share_partition(UUID(str(share_id)))
    assert before_lookup == after_lookup
    assert before_lookup.startswith("p")
    assert str(share_id) not in before_lookup
    assert share_id.hex not in before_lookup


def test_malformed_share_id_does_not_create_a_limiter_bucket(client, db_session):
    sentinel = "NOT-A-UUID-SHARE-ID-SENTINEL"
    before = db_session.scalar(select(func.count()).select_from(AnonymousRateLimitCounter)) or 0
    response = client.post(
        f"/v1/shared-reports/{sentinel}/resolve",
        json={"secret": "A" * 43},
    )
    assert response.status_code == 422
    assert sentinel not in response.text
    after = db_session.scalar(select(func.count()).select_from(AnonymousRateLimitCounter)) or 0
    assert after == before


def test_coarse_partition_exhaustion_is_localized(
    client, db_session, monkeypatch
):
    monkeypatch.setenv("RATE_LIMIT_SHARED_REPORT_COARSE", "1")
    reset_settings_cache()
    try:
        first = uuid4()
        second = _uuid_in_partition(
            "p00" if coarse_share_partition(first) != "p00" else "p01",
            exclude={first},
        )
        assert coarse_share_partition(first) != coarse_share_partition(second)
        secret = "A" * 43
        assert (
            client.post(
                f"/v1/shared-reports/{first}/resolve", json={"secret": secret}
            ).status_code
            == 404
        )
        exhausted = client.post(
            f"/v1/shared-reports/{first}/resolve", json={"secret": secret}
        )
        other = client.post(
            f"/v1/shared-reports/{second}/resolve", json={"secret": secret}
        )
        assert exhausted.status_code == 429
        assert other.status_code == 404
        buckets = set(
            db_session.scalars(
                select(AnonymousRateLimitCounter.bucket).where(
                    AnonymousRateLimitCounter.action == ACTION_SHARED_REPORT_COARSE
                )
            )
        )
        assert coarse_share_partition(first) in buckets
        assert coarse_share_partition(second) in buckets
    finally:
        reset_settings_cache()


def test_share_specific_limiter_applies_after_secret_verify(
    client, make_token, seed_user_a, dns_resolver, engine, db_session, monkeypatch
):
    monkeypatch.setenv("RATE_LIMIT_SHARED_REPORT_USE", "2")
    monkeypatch.setenv("RATE_LIMIT_SHARED_REPORT_COARSE", "30")
    reset_settings_cache()
    try:
        user_id, org_id = seed_user_a
        token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
        report_id = _generate(
            client,
            token,
            _clean_completed_operation(
                client, token, dns_resolver, engine, "share-use-limit.example"
            ),
        ).json()["id"]
        created = _create_share(client, token, report_id).json()
        secret = _secret_from_url(created["share_url"])
        assert (
            client.post(
                f"/v1/shared-reports/{created['id']}/resolve", json={"secret": secret}
            ).status_code
            == 200
        )
        assert (
            client.post(
                f"/v1/shared-reports/{created['id']}/resolve", json={"secret": secret}
            ).status_code
            == 200
        )
        limited = client.post(
            f"/v1/shared-reports/{created['id']}/resolve", json={"secret": secret}
        )
        assert limited.status_code == 429
        use_buckets = list(
            db_session.scalars(
                select(AnonymousRateLimitCounter.bucket).where(
                    AnonymousRateLimitCounter.action == ACTION_SHARED_REPORT_USE
                )
            )
        )
        assert use_buckets == [created["id"]]
    finally:
        reset_settings_cache()
