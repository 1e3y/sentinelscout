from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import event, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from app.capabilities.manifest import UNSUPPORTED_CLASSES
from app.models.audit import AuditEvent
from app.models.coverage import OperationCoverageSummary
from app.models.finding import Finding
from app.models.operation import Operation
from app.models.report import AssessmentReport
from app.models.validation import ValidationAttempt
from app.services.coverage import freeze_operation_coverage
from app.services.discovery.runner import FakeDiscoveryTools, ProbeResult
from app.services.reports import generate as generate_mod
from app.services.reports import summary as reports_summary
from app.services.reports.redaction import (
    ReportRedactionError,
    finding_report_evidence,
    guard_evidence_subtree,
    missing_security_headers,
)
from app.services.reports.snapshot import canonical_json, content_digest
from app.services.reports.summary import (
    HEADLINE_ACTION_REQUIRED,
    HEADLINE_ASSESSMENT_INCOMPLETE,
    HEADLINE_ATTENTION_RECOMMENDED,
    HEADLINE_NO_OPEN_SUPPORTED_FINDINGS,
    NO_OPEN_FINDINGS_DISCLAIMER,
    classify_headline,
    compute_coverage_limitations,
)
from app.services.validation_engine.http import FakeSafeHttpClient
from app.services.validation_engine.types import SafeHttpObservation
from app.services.validation_runtime import process_one_validation
from app.services.worker_runtime import process_one_operation

BANNED_PHRASES = (
    "is secure",
    "no vulnerabilities",
    "penetration test",
    "pen test",
    "compliant",
    "breach-proof",
    "fully tested",
    "guarantee",
)


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _create_verified_target(client, token: str, domain: str, dns_resolver) -> str:
    created = client.post("/v1/targets", headers=_auth(token), json={"domain": domain})
    assert created.status_code == 201, created.text
    target_id = created.json()["id"]
    started = client.post(f"/v1/targets/{target_id}/verification", headers=_auth(token))
    authz = started.json()["authorization"]
    dns_resolver.set(authz["txt_name"], [authz["txt_value"]])
    assert client.post(f"/v1/targets/{target_id}/verify", headers=_auth(token)).json()[
        "verified"
    ]
    assert (
        client.put(
            f"/v1/targets/{target_id}/scope",
            headers=_auth(token),
            json={"include_subdomains": True, "exclusions": []},
        ).status_code
        == 200
    )
    return target_id


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


def _run_operation(client, token, engine, target_id, hosts_by_domain, probes_by_host) -> str:
    operation_id = client.post(
        "/v1/operations", headers=_auth(token), json={"target_id": target_id}
    ).json()["id"]
    tools = FakeDiscoveryTools(
        hosts_by_domain=hosts_by_domain, probes_by_host=probes_by_host
    )
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    assert process_one_operation(factory, tools=tools).status == "completed"
    return operation_id


def _clean_completed_operation(client, token, dns_resolver, engine, domain: str) -> str:
    """Full coverage with no gaps: the apex is always in scope, so it must be probed."""
    target_id = _create_verified_target(client, token, domain, dns_resolver)
    return _run_operation(
        client,
        token,
        engine,
        target_id,
        {domain: []},
        {domain: _clean_probe(domain)},
    )


def _operation_with_open_finding(
    client, token, dns_resolver, engine, domain: str
) -> tuple[str, str, str]:
    """Completed operation carrying one open medium-severity finding."""
    target_id = _create_verified_target(client, token, domain, dns_resolver)
    host = f"staging.{domain}"
    operation_id = _run_operation(
        client,
        token,
        engine,
        target_id,
        {domain: [host]},
        {
            host: ProbeResult(
                url=f"https://{host}",
                status_code=200,
                title="Staging",
                headers_observed=True,
                headers={"strict-transport-security": "max-age=31536000"},
                headers_present=("strict-transport-security",),
                content_type="text/html",
                requested_url=f"https://{host}",
                final_url=f"https://{host}",
                scheme="https",
            )
        },
    )
    candidates = client.get(
        f"/v1/operations/{operation_id}/candidates", headers=_auth(token)
    ).json()
    candidate_id = next(
        row["id"] for row in candidates if row["candidate_type"] == "staging_dev_exposed"
    )
    assert (
        client.post(
            f"/v1/candidates/{candidate_id}/validate", headers=_auth(token)
        ).status_code
        == 202
    )
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    http = FakeSafeHttpClient(
        by_host={
            host: SafeHttpObservation(
                url=f"https://{host}",
                status_code=200,
                title="Staging",
                headers={},
                reachable=True,
            )
        }
    )
    assert process_one_validation(factory, http_client=http).status == "supported"
    promoted = client.post(f"/v1/candidates/{candidate_id}/promote", headers=_auth(token))
    assert promoted.status_code in (200, 201), promoted.text
    return target_id, operation_id, promoted.json()["id"]


def _generate(client, token, operation_id):
    return client.post(f"/v1/operations/{operation_id}/report", headers=_auth(token))


# ---------------------------------------------------------------- unit: summary


def test_classify_headline_priority_order():
    medium = [{"severity": "medium"}]
    low = [{"severity": "low"}]
    # Incomplete outranks everything, including elevated open findings.
    assert (
        classify_headline(
            assessment_completeness="incomplete",
            open_findings=medium,
            coverage_limitation_count=3,
            regression_count=2,
        )
        == HEADLINE_ASSESSMENT_INCOMPLETE
    )
    assert (
        classify_headline(
            assessment_completeness="complete",
            open_findings=medium,
            coverage_limitation_count=0,
            regression_count=0,
        )
        == HEADLINE_ACTION_REQUIRED
    )
    assert (
        classify_headline(
            assessment_completeness="complete",
            open_findings=low,
            coverage_limitation_count=0,
            regression_count=0,
        )
        == HEADLINE_ATTENTION_RECOMMENDED
    )
    assert (
        classify_headline(
            assessment_completeness="complete",
            open_findings=[],
            coverage_limitation_count=1,
            regression_count=0,
        )
        == HEADLINE_ATTENTION_RECOMMENDED
    )
    assert (
        classify_headline(
            assessment_completeness="complete",
            open_findings=[],
            coverage_limitation_count=0,
            regression_count=1,
        )
        == HEADLINE_ATTENTION_RECOMMENDED
    )
    assert (
        classify_headline(
            assessment_completeness="complete",
            open_findings=[],
            coverage_limitation_count=0,
            regression_count=0,
        )
        == HEADLINE_NO_OPEN_SUPPORTED_FINDINGS
    )


def test_coverage_limitation_count_ignores_unsupported_capabilities():
    """Generic methodology limits must never force Attention Recommended."""
    clean = compute_coverage_limitations(
        surface={"http_observation_not_obtained": 0, "incomplete": 0},
        http_evidence={
            "header_evidence_unavailable": 0,
            "redirect_header_evidence_unusable": 0,
        },
        scope_boundaries={
            "gaps": [
                # Authorized-scope exclusions and unsupported classes are not gaps.
                {"reason_code": "authorization_scope_excluded", "count": 12},
                {"reason_code": "capability_not_supported", "count": len(UNSUPPORTED_CLASSES)},
            ]
        },
        follow_up={"gaps": []},
    )
    assert clean == []

    concrete = compute_coverage_limitations(
        surface={"http_observation_not_obtained": 2, "incomplete": 1},
        http_evidence={
            "header_evidence_unavailable": 3,
            "redirect_header_evidence_unusable": 0,
        },
        scope_boundaries={"gaps": [{"reason_code": "discovery_truncated", "count": 1}]},
        follow_up={"gaps": [{"reason_code": "validation_not_attempted", "count": 4}]},
    )
    reason_codes = [item["reason_code"] for item in concrete]
    assert reason_codes == sorted(reason_codes)
    assert set(reason_codes) == {
        "discovery_truncated",
        "header_evidence_unavailable",
        "http_observation_not_obtained",
        "observation_incomplete",
        "validation_not_attempted",
    }
    assert all(item["explanation"] for item in concrete)


# -------------------------------------------------------------- unit: redaction


def test_guard_rejects_forbidden_evidence_keys_and_values():
    for payload in (
        {"Authorization": "Bearer abc"},
        {"Set-Cookie": "a=b"},
        {"session_id": "x"},
        {"nested": [{"api_key": "k"}]},
        {"response_body": "<html>"},
        {"user_password": "hunter2"},
        {"refresh_token": "r"},
    ):
        with pytest.raises(ReportRedactionError):
            guard_evidence_subtree(payload)

    with pytest.raises(ReportRedactionError):
        guard_evidence_subtree({"note": "Bearer eyJhbGciOi.abc"})
    with pytest.raises(ReportRedactionError):
        guard_evidence_subtree({"note": "-----BEGIN PRIVATE KEY-----"})


def test_guard_does_not_false_positive_on_safe_typed_report_fields():
    """Correction 1: the report's own canonical schema must survive the guard."""
    safe = {
        "target_authorization_status": "verified",
        "target_authorization_id": str(uuid4()),
        "authorization_role": "admin",
        "authorization_basis": "verified_active_org_role",
        "headers_captured": 4,
        "headers_observed": True,
        "headers_present": ["strict-transport-security"],
        "header_evidence_unavailable": 0,
        "redirect_header_evidence_unusable": 0,
        "missing_security_headers": [
            {"header_name": "strict-transport-security", "observed": False}
        ],
        "hsts_present": False,
        "sessions_discovered": 0,
        "content_type": "text/html",
        "final_url": "https://staging.example",
    }
    assert guard_evidence_subtree(safe) is safe


def test_observed_header_is_serialized_as_name_only():
    """Correction 2: no arbitrary header names or any header value reaches a report."""
    typed = missing_security_headers(
        {
            "still_missing": ["Strict-Transport-Security", "x-frame-options"],
            "observed_header": "content-security-policy",
        }
    )
    assert typed == [
        {"header_name": "content-security-policy", "observed": False},
        {"header_name": "strict-transport-security", "observed": False},
        {"header_name": "x-frame-options", "observed": False},
    ]
    # Unsafe or unknown header names are dropped entirely.
    assert missing_security_headers(
        {"still_missing": ["authorization", "set-cookie", "x-internal-token"]}
    ) == []
    # No value is ever carried, even for allowlisted names.
    for entry in typed:
        assert set(entry) == {"header_name", "observed"}


def test_finding_evidence_allowlist_drops_unknown_and_unsafe_keys():
    evidence = finding_report_evidence(
        {
            "candidate_type": "staging_dev_exposed",
            "candidate_evidence": {
                "reasons": ["DNS label 'staging'"],
                "signals": ["strong: DNS label 'staging'"],
                "why": "Staging naming evidence",
                "cookie": "a=b",
            },
            "validation": {
                "method": "staging_indicator_confirmation",
                "status": "supported",
                "summary": "reconfirmed",
                "evidence": {
                    "method": "staging_indicator_confirmation",
                    "reachable": True,
                    "status_code": 200,
                    "hostname": "staging.example",
                    "staging_markers": ["staging"],
                    "title": "Staging <secret in title>",
                    "observed_header_names": ["x-weird-header"],
                    "Authorization": "Bearer nope",
                    "set-cookie": "sid=1",
                    "observation_ids": [str(uuid4())],
                    "asset_id": str(uuid4()),
                },
            },
            "provenance": {"candidate_id": str(uuid4())},
        }
    )
    blob = json.dumps(evidence)
    for leaked in ("Bearer nope", "sid=1", "x-weird-header", "secret in title"):
        assert leaked not in blob
    assert "title" not in evidence.get("observed_facts", {})
    assert "cookie" not in evidence.get("deterministic_signals", {})
    assert evidence["observed_facts"]["hostname"] == "staging.example"
    assert evidence["deterministic_signals"]["why"] == "Staging naming evidence"


# ---------------------------------------------------------- generation lifecycle


def test_completed_operation_generates_report_with_frozen_sections(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    _, operation_id, finding_id = _operation_with_open_finding(
        client, token, dns_resolver, engine, "rep-basic.example"
    )

    created = _generate(client, token, operation_id)
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["report_version"] == 1
    assert body["assessment_completeness"] == "complete"
    assert body["headline_status"] == HEADLINE_ACTION_REQUIRED
    assert body["findings_total"] == 1
    assert body["findings_open"] == 1
    assert body["severity_counts"] == {"medium": 1}
    assert body["target_domain"] == "rep-basic.example"

    snapshot = body["snapshot"]
    assert set(snapshot) == {"report_schema_version", "envelope", "content"}
    content = snapshot["content"]
    assert set(content) == {
        "report_schema_version",
        "identity",
        "scope",
        "coverage",
        "findings",
        "not_promoted",
        "change_context",
        "summary",
        "methodology",
    }
    assert content["identity"]["target_authorization_status"] == "verified"
    assert content["scope"]["source"] == "operation_control_snapshot"
    assert content["coverage"]["frozen_operation_coverage"]["operation_status_at_freeze"] == (
        "completed"
    )
    assert content["coverage"]["follow_up_frozen_for_report"]["source"] == (
        "computed_at_report_generation"
    )
    assert content["findings"][0]["finding_id"] == finding_id
    assert content["findings"][0]["status"] == "open"
    assert len(content["methodology"]["unsupported_classes"]) == len(UNSUPPORTED_CLASSES)
    assert content_digest(content) == body["snapshot_digest"]


def test_running_and_queued_operations_are_not_reportable(
    client, make_token, seed_user_a, dns_resolver
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    target_id = _create_verified_target(client, token, "rep-queued.example", dns_resolver)
    operation_id = client.post(
        "/v1/operations", headers=_auth(token), json={"target_id": target_id}
    ).json()["id"]

    response = _generate(client, token, operation_id)
    assert response.status_code == 409, response.text
    assert "reportable state" in response.json()["error"]["message"]


def test_missing_frozen_coverage_snapshot_fails_closed(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    operation_id = _clean_completed_operation(
        client, token, dns_resolver, engine, "rep-nocov.example"
    )
    row = db_session.scalar(
        select(OperationCoverageSummary).where(
            OperationCoverageSummary.operation_id == operation_id
        )
    )
    assert row is not None
    db_session.delete(row)
    db_session.commit()

    response = _generate(client, token, operation_id)
    assert response.status_code == 409, response.text
    assert response.json()["error"]["message"] == (
        "Operation coverage snapshot is not available"
    )
    assert db_session.scalars(select(AssessmentReport)).all() == []


def test_stopped_operation_is_always_labelled_incomplete(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    """Correction 10: incomplete outranks a zero-finding clean-looking result."""
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    target_id = _create_verified_target(client, token, "rep-stopped.example", dns_resolver)
    operation_id = client.post(
        "/v1/operations", headers=_auth(token), json={"target_id": target_id}
    ).json()["id"]
    stopped = client.post(f"/v1/operations/{operation_id}/stop", headers=_auth(token))
    assert stopped.status_code == 200
    assert stopped.json()["status"] == "stopped"

    response = _generate(client, token, operation_id)
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["findings_total"] == 0
    assert body["assessment_completeness"] == "incomplete"
    assert body["headline_status"] == HEADLINE_ASSESSMENT_INCOMPLETE
    content = body["snapshot"]["content"]
    assert content["identity"]["assessment_completeness"] == "incomplete"
    assert content["identity"]["operation_status"] == "stopped"
    assert content["summary"]["assessment_completeness"] == "incomplete"
    assert "did not run to completion" in content["summary"]["headline_statement"]
    assert NO_OPEN_FINDINGS_DISCLAIMER not in json.dumps(content)


def test_failed_operation_is_always_labelled_incomplete(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    target_id = _create_verified_target(client, token, "rep-failed.example", dns_resolver)
    operation_id = client.post(
        "/v1/operations", headers=_auth(token), json={"target_id": target_id}
    ).json()["id"]
    operation = db_session.get(Operation, operation_id)
    operation.status = "failed"
    operation.failed_at = datetime.now(UTC)
    operation.error_code = "discovery_failed"
    db_session.flush()
    freeze_operation_coverage(db_session, operation, source="frozen", actor_type="worker")
    db_session.commit()

    body = _generate(client, token, operation_id).json()
    assert body["assessment_completeness"] == "incomplete"
    assert body["headline_status"] == HEADLINE_ASSESSMENT_INCOMPLETE
    assert body["operation_status_at_generation"] == "failed"


def test_clean_completed_operation_carries_mandatory_disclaimer(
    client, make_token, seed_user_a, dns_resolver, engine
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    operation_id = _clean_completed_operation(
        client, token, dns_resolver, engine, "rep-clean.example"
    )
    body = _generate(client, token, operation_id).json()
    assert body["findings_total"] == 0
    assert body["coverage_limitation_count"] == 0
    assert body["headline_status"] == HEADLINE_NO_OPEN_SUPPORTED_FINDINGS
    content = body["snapshot"]["content"]
    assert content["summary"]["headline_statement"] == NO_OPEN_FINDINGS_DISCLAIMER
    # Unsupported capability classes stay visible regardless of headline.
    assert len(content["methodology"]["unsupported_classes"]) == len(UNSUPPORTED_CLASSES)


def test_report_module_text_makes_no_security_claims():
    package = Path(reports_summary.__file__).parent
    for source in sorted(package.glob("*.py")):
        text = source.read_text(encoding="utf-8").lower()
        for phrase in BANNED_PHRASES:
            assert phrase not in text, (source.name, phrase)


def _report_authored_strings(content: dict) -> list[str]:
    """Text the report itself asserts, excluding inherited M17/M18 headlines."""
    authored = [
        content["summary"]["headline_statement"],
        content["summary"]["headline_label"],
        content["scope"]["explanation"],
        content["coverage"]["limitations"]["explanation"],
        content["coverage"]["follow_up_frozen_for_report"]["explanation"],
        content["coverage"]["frozen_operation_coverage"]["explanation"],
        content["not_promoted"]["explanation"],
        *content["methodology"]["safety_controls"],
    ]
    for finding in content["findings"]:
        authored.extend([finding["business_impact"], finding["remediation_guidance"]])
    return authored


def test_report_authored_language_avoids_security_overclaims(
    client, make_token, seed_user_a, dns_resolver, engine
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    operation_id = _clean_completed_operation(
        client, token, dns_resolver, engine, "rep-lang.example"
    )
    content = _generate(client, token, operation_id).json()["snapshot"]["content"]
    for text in _report_authored_strings(content):
        lowered = text.lower()
        for phrase in BANNED_PHRASES:
            assert phrase not in lowered, (phrase, text)


# ------------------------------------------------------ idempotency / versioning


def test_identical_inputs_return_existing_report_without_new_version(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    operation_id = _clean_completed_operation(
        client, token, dns_resolver, engine, "rep-idem.example"
    )
    first = _generate(client, token, operation_id)
    assert first.status_code == 201
    second = _generate(client, token, operation_id)
    assert second.status_code == 200
    assert second.json()["id"] == first.json()["id"]
    assert second.json()["snapshot_digest"] == first.json()["snapshot_digest"]
    assert len(db_session.scalars(select(AssessmentReport)).all()) == 1


def test_live_target_scope_change_alone_does_not_create_a_new_version(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    """Correction 8: scope comes from the operation control snapshot, not the target."""
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    target_id, operation_id, _ = _operation_with_open_finding(
        client, token, dns_resolver, engine, "rep-scope.example"
    )
    first = _generate(client, token, operation_id).json()

    changed = client.put(
        f"/v1/targets/{target_id}/scope",
        headers=_auth(token),
        json={"include_subdomains": False, "exclusions": ["excluded.rep-scope.example"]},
    )
    assert changed.status_code == 200
    assert changed.json()["exclusions"] == ["excluded.rep-scope.example"]

    again = _generate(client, token, operation_id)
    assert again.status_code == 200
    assert again.json()["id"] == first["id"]
    assert again.json()["snapshot_digest"] == first["snapshot_digest"]
    assert len(db_session.scalars(select(AssessmentReport)).all()) == 1
    # The original report still describes the scope the operation actually tested.
    scope = again.json()["snapshot"]["content"]["scope"]
    assert scope["include_subdomains"] is True
    assert scope["exclusions"] == []


def test_finding_state_change_creates_v2_and_leaves_v1_untouched(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    _, operation_id, finding_id = _operation_with_open_finding(
        client, token, dns_resolver, engine, "rep-v2.example"
    )
    v1 = _generate(client, token, operation_id).json()
    assert v1["report_version"] == 1
    assert v1["findings_open"] == 1

    assert (
        client.post(
            f"/v1/findings/{finding_id}/start-remediation", headers=_auth(token)
        ).status_code
        == 200
    )
    assert (
        client.post(
            f"/v1/findings/{finding_id}/ready-for-retest", headers=_auth(token)
        ).status_code
        == 200
    )

    v2 = _generate(client, token, operation_id)
    assert v2.status_code == 201
    v2_body = v2.json()
    assert v2_body["report_version"] == 2
    assert v2_body["snapshot_digest"] != v1["snapshot_digest"]
    assert v2_body["snapshot"]["content"]["findings"][0]["status"] == "ready_for_retest"

    refetched_v1 = client.get(f"/v1/reports/{v1['id']}", headers=_auth(token)).json()
    assert refetched_v1["snapshot"] == v1["snapshot"]
    assert refetched_v1["snapshot_digest"] == v1["snapshot_digest"]
    assert refetched_v1["snapshot"]["content"]["findings"][0]["status"] == "open"


def test_generation_is_deterministic_across_generation_timestamps(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    """Correction 6: digested content holds no generation-time volatility."""
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    _, operation_id, _ = _operation_with_open_finding(
        client, token, dns_resolver, engine, "rep-det.example"
    )
    first = _generate(client, token, operation_id).json()

    row = db_session.scalar(select(AssessmentReport))
    db_session.delete(row)
    db_session.commit()

    second = _generate(client, token, operation_id).json()
    assert second["id"] != first["id"]
    assert second["snapshot"]["envelope"]["generated_at"] != (
        first["snapshot"]["envelope"]["generated_at"]
    )
    assert canonical_json(second["snapshot"]["content"]) == canonical_json(
        first["snapshot"]["content"]
    )
    assert second["snapshot_digest"] == first["snapshot_digest"]


def test_version_race_never_returns_a_mismatched_digest(
    client, make_token, seed_user_a, dns_resolver, engine, db_session, monkeypatch
):
    """Correction 7: bounded retry reuses the built content and checks the digest."""
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    operation_id = _clean_completed_operation(
        client, token, dns_resolver, engine, "rep-race.example"
    )
    operation = db_session.get(Operation, operation_id)

    competing = AssessmentReport(
        organization_id=operation.organization_id,
        target_id=operation.target_id,
        operation_id=operation.id,
        created_by_user_id=operation.created_by_user_id,
        target_domain="rep-race.example",
        report_version=1,
        schema_version=1,
        snapshot_digest="0" * 64,
        snapshot_json={"content": {"stale": True}},
        operation_status_at_generation="completed",
        assessment_completeness="complete",
        headline_status=HEADLINE_ATTENTION_RECOMMENDED,
    )
    db_session.add(competing)
    db_session.commit()

    real_insert = generate_mod._insert_report
    attempts = {"count": 0}

    def flaky_insert(db, **kwargs):
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise IntegrityError("INSERT", {}, Exception("duplicate key"))
        return real_insert(db, **kwargs)

    monkeypatch.setattr(generate_mod, "_insert_report", flaky_insert)

    response = _generate(client, token, operation_id)
    assert response.status_code == 201, response.text
    body = response.json()
    assert attempts["count"] == 2
    assert body["report_version"] == 2
    assert body["snapshot_digest"] != "0" * 64
    assert content_digest(body["snapshot"]["content"]) == body["snapshot_digest"]


# ------------------------------------------------------------------- immutability


def test_reading_a_report_performs_no_live_evidence_joins(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    """Correction 17: historical snapshots are never re-derived at view time."""
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    _, operation_id, _ = _operation_with_open_finding(
        client, token, dns_resolver, engine, "rep-join.example"
    )
    report_id = _generate(client, token, operation_id).json()["id"]

    statements: list[str] = []

    def _capture(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement.lower())

    event.listen(engine, "before_cursor_execute", _capture)
    try:
        fetched = client.get(f"/v1/reports/{report_id}", headers=_auth(token))
    finally:
        event.remove(engine, "before_cursor_execute", _capture)

    assert fetched.status_code == 200
    forbidden_tables = (
        "findings",
        "retest_attempts",
        "validation_attempts",
        "security_candidates",
        "operation_coverage_summaries",
        "operation_diff_summaries",
        "discovery_observations",
        "operations",
    )
    joined = " ".join(statements)
    for table in forbidden_tables:
        referenced = re.search(rf"\b(from|join)\s+{table}\b", joined)
        assert referenced is None, table
    assert re.search(r"\bfrom\s+assessment_reports\b", joined) is not None


def test_report_write_verbs_are_not_exposed(
    client, make_token, seed_user_a, dns_resolver, engine
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    operation_id = _clean_completed_operation(
        client, token, dns_resolver, engine, "rep-verbs.example"
    )
    report_id = _generate(client, token, operation_id).json()["id"]
    for method in ("put", "patch", "delete"):
        response = getattr(client, method)(
            f"/v1/reports/{report_id}", headers=_auth(token)
        )
        assert response.status_code == 405, (method, response.status_code)


# -------------------------------------------------------- data minimization / RBAC


def test_snapshot_omits_actor_email_and_internal_row_identifiers(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    """Correction 3: no login email and no gratuitous database identifiers."""
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    _, operation_id, _ = _operation_with_open_finding(
        client, token, dns_resolver, engine, "rep-min.example"
    )
    body = _generate(client, token, operation_id).json()
    snapshot = body["snapshot"]

    assert snapshot["envelope"]["generated_by"] == {"user_id": str(db_session.scalar(
        select(AssessmentReport.created_by_user_id)
    ))}
    blob = json.dumps(snapshot)
    assert "alice@example.com" not in blob

    finding = snapshot["content"]["findings"][0]
    for internal in (
        "candidate_id",
        "validation_attempt_id",
        "asset_id",
        "observation_ids",
        "target_authorization_id",
        "resolving_retest_id",
    ):
        assert internal not in json.dumps(finding), internal

    candidate_ids = {
        str(row) for row in db_session.scalars(select(ValidationAttempt.id)).all()
    }
    for value in candidate_ids:
        assert value not in blob


def test_member_cannot_generate_but_can_read_reports(
    client, make_token, seed_user_a, dns_resolver, engine, fake_clerk
):
    user_id, org_id = seed_user_a
    admin_token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    operation_id = _clean_completed_operation(
        client, admin_token, dns_resolver, engine, "rep-rbac.example"
    )
    report_id = _generate(client, admin_token, operation_id).json()["id"]

    member_token = make_token(sub=user_id, org_id=org_id, org_role="org:member")
    denied = _generate(client, member_token, operation_id)
    assert denied.status_code == 403, denied.text
    assert denied.json()["error"]["message"] == "Organization admin required"

    assert client.get(f"/v1/reports/{report_id}", headers=_auth(member_token)).status_code == (
        200
    )
    listed = client.get("/v1/reports", headers=_auth(member_token))
    assert listed.status_code == 200
    assert [row["id"] for row in listed.json()] == [report_id]
    history = client.get(
        f"/v1/operations/{operation_id}/reports", headers=_auth(member_token)
    )
    assert [row["report_version"] for row in history.json()] == [1]


def test_missing_role_claim_cannot_generate(
    client, make_token, seed_user_a, dns_resolver, engine
):
    user_id, org_id = seed_user_a
    admin_token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    operation_id = _clean_completed_operation(
        client, admin_token, dns_resolver, engine, "rep-norole.example"
    )
    no_role = make_token(sub=user_id, org_id=org_id, omit_org_role=True)
    denied = _generate(client, no_role, operation_id)
    assert denied.status_code == 403
    assert denied.json()["error"]["message"] == "Verified organization role is required"


def test_cross_org_reports_are_not_reachable(
    client, make_token, seed_user_a, seed_user_b, dns_resolver, engine
):
    user_a, org_a = seed_user_a
    user_b, org_b = seed_user_b
    token_a = make_token(sub=user_a, org_id=org_a, org_role="org:admin")
    token_b = make_token(sub=user_b, org_id=org_b, org_role="org:admin")
    operation_id = _clean_completed_operation(
        client, token_a, dns_resolver, engine, "rep-cross.example"
    )
    report_id = _generate(client, token_a, operation_id).json()["id"]

    assert _generate(client, token_b, operation_id).status_code == 404
    assert client.get(f"/v1/reports/{report_id}", headers=_auth(token_b)).status_code == 404
    assert (
        client.get(
            f"/v1/operations/{operation_id}/reports", headers=_auth(token_b)
        ).status_code
        == 404
    )
    assert client.get("/v1/reports", headers=_auth(token_b)).json() == []


def test_direct_service_call_refuses_member_and_wrong_org_actors(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    from fastapi import HTTPException

    from app.services.authorization import explicit_org_actor

    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    operation_id = _clean_completed_operation(
        client, token, dns_resolver, engine, "rep-direct.example"
    )
    operation = db_session.get(Operation, operation_id)

    member = explicit_org_actor(
        user_id=operation.created_by_user_id,
        organization_id=operation.organization_id,
        normalized_role="member",
    )
    with pytest.raises(HTTPException) as member_exc:
        generate_mod.generate_assessment_report(
            db_session, operation_id=operation.id, actor=member
        )
    assert member_exc.value.status_code == 403

    wrong_org = explicit_org_actor(
        user_id=operation.created_by_user_id,
        organization_id=uuid4(),
        normalized_role="admin",
    )
    with pytest.raises(HTTPException) as org_exc:
        generate_mod.generate_assessment_report(
            db_session, operation_id=operation.id, actor=wrong_org
        )
    assert org_exc.value.status_code == 404
    assert db_session.scalars(select(AssessmentReport)).all() == []


# -------------------------------------------------------------------------- audit


def test_generated_report_audit_metadata_survives_the_allowlist(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    """Correction 12: assert the persisted metadata, not just the call."""
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    _, operation_id, _ = _operation_with_open_finding(
        client, token, dns_resolver, engine, "rep-audit.example"
    )
    body = _generate(client, token, operation_id).json()

    event_row = db_session.scalar(
        select(AuditEvent).where(AuditEvent.action == "assessment_report.generated")
    )
    assert event_row is not None
    assert event_row.resource_type == "assessment_report"
    assert str(event_row.resource_id) == body["id"]
    metadata = dict(event_row.event_metadata or {})
    assert metadata["report_id"] == body["id"]
    assert metadata["report_version"] == 1
    assert metadata["schema_version"] == 1
    assert metadata["snapshot_digest"] == body["snapshot_digest"]
    assert metadata["operation_id"] == operation_id
    assert metadata["target_id"] == body["target_id"]
    assert metadata["operation_status"] == "completed"
    assert metadata["headline_status"] == HEADLINE_ACTION_REQUIRED
    assert metadata["assessment_completeness"] == "complete"
    assert metadata["findings_total"] == 1
    assert metadata["findings_open"] == 1
    assert metadata["authorization_role"] == "admin"
    assert metadata["authorization_basis"] == "verified_active_org_role"
    assert "snapshot_json" not in metadata
    assert "snapshot" not in metadata


def test_forbidden_evidence_seeded_into_live_rows_never_reaches_the_report(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    _, operation_id, finding_id = _operation_with_open_finding(
        client, token, dns_resolver, engine, "rep-leak.example"
    )

    sentinel = "SENTINEL-LEAK-VALUE"
    finding = db_session.get(Finding, finding_id)
    evidence = dict(finding.evidence or {})
    validation = dict(evidence.get("validation") or {})
    inner = dict(validation.get("evidence") or {})
    inner.update(
        {
            "Authorization": f"Bearer {sentinel}",
            "Cookie": f"session={sentinel}",
            "Set-Cookie": f"sid={sentinel}",
            "token": sentinel,
            "password": sentinel,
            "response_body": f"<html>{sentinel}</html>",
            "raw_headers": {"authorization": sentinel},
        }
    )
    validation["evidence"] = inner
    evidence["validation"] = validation
    evidence["candidate_evidence"] = {
        **(evidence.get("candidate_evidence") or {}),
        "api_key": sentinel,
        "reasons": ["DNS label 'staging'"],
    }
    finding.evidence = evidence

    attempt = db_session.scalar(select(ValidationAttempt))
    attempt_evidence = dict(attempt.evidence or {})
    attempt_evidence["set-cookie"] = f"sid={sentinel}"
    attempt.evidence = attempt_evidence
    db_session.commit()

    body = _generate(client, token, operation_id)
    assert body.status_code == 201, body.text
    blob = json.dumps(body.json()["snapshot"])
    assert sentinel not in blob
    for key in ("Authorization", "Cookie", "Set-Cookie", "response_body", "raw_headers"):
        assert f'"{key}"' not in blob


def test_digested_content_excludes_generation_time_volatility(
    client, make_token, seed_user_a, dns_resolver, engine
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    operation_id = _clean_completed_operation(
        client, token, dns_resolver, engine, "rep-volatile.example"
    )
    body = _generate(client, token, operation_id).json()
    envelope = body["snapshot"]["envelope"]
    content = body["snapshot"]["content"]
    content_blob = canonical_json(content)
    assert envelope["report_id"] not in content_blob
    assert envelope["generated_at"] not in content_blob
    assert '"generated_at"' not in content_blob
    assert "report_id" not in content
    assert "report_version" not in content
    assert content_digest(content) == body["snapshot_digest"]


def test_incomplete_report_ui_contract_is_unmissable():
    """Correction 10: incomplete markers exist in the dedicated report view and print CSS."""
    web_root = Path(__file__).resolve().parents[2] / "web"
    view = (web_root / "app/dashboard/reports/[reportId]/report-view.tsx").read_text(
        encoding="utf-8"
    )
    css = (web_root / "app/globals.css").read_text(encoding="utf-8")
    for marker in (
        'data-testid="assessment-incomplete-banner"',
        'data-testid="executive-incomplete-marker"',
        'data-testid="scope-incomplete-marker"',
        "Assessment Incomplete",
        "report-incomplete",
        "HEADLINE_TONE",
        "assessment_incomplete",
    ):
        assert marker in view, marker
    assert "No Open Supported Findings" not in view.split("HEADLINE_TONE")[0]
    assert ".report-incomplete" in css
    assert "@media print" in css
    # Incomplete never shares the clean-status visual.
    tone_block = view.split("const HEADLINE_TONE")[1].split("};")[0]
    assert "assessment_incomplete" in tone_block
    assert "no_open_supported_findings" in tone_block
    incomplete_class = next(
        line for line in tone_block.splitlines() if "assessment_incomplete" in line
    )
    clean_class = next(
        line for line in tone_block.splitlines() if "no_open_supported_findings" in line
    )
    assert incomplete_class != clean_class
