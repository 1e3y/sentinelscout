from __future__ import annotations

import ast
import copy
import hashlib
import inspect
import json
import re
import unicodedata
from io import BytesIO
from pathlib import Path
from uuid import uuid4

import pytest
from pypdf import PdfReader
from sqlalchemy import event, select
from sqlalchemy.orm.attributes import flag_modified

from app.core.config import reset_settings_cache
from app.models.audit import AuditEvent
from app.models.report import AssessmentReport
from app.services.rate_limit import ACTION_REPORT_PDF_EXPORT
from app.services.reports.pdf import (
    FONT_FILE,
    FONT_SOURCE_FILE,
    MAX_FINDINGS,
    MAX_SNAPSHOT_BYTES,
    PDF_RENDERER_VERSION,
    PdfRendererUnavailable,
    expected_font_sha256,
    is_supported_pdf_char,
    normalize_pdf_text,
    plain_pdf_text,
    sanitize_pdf_filename,
    snapshot_utf8_size,
)
from app.services.reports.snapshot import content_digest
from tests.test_reports import (
    _auth,
    _clean_completed_operation,
    _create_verified_target,
    _generate,
    _operation_with_open_finding,
)


@pytest.fixture(autouse=True)
def _reset_settings_around_pdf_tests():
    reset_settings_cache()
    yield
    reset_settings_cache()


INJECTION_STRINGS = (
    "<script>alert(1)</script>",
    "<img src='https://evil.example/x'>",
    "<link href='file:///etc/passwd'>x</link>",
    "url(https://evil.example/x)",
)


def _pdf(client, token: str, report_id: str):
    return client.get(f"/v1/reports/{report_id}/pdf", headers=_auth(token))


def _pdf_text(data: bytes) -> str:
    reader = PdfReader(BytesIO(data))
    return "\n".join((page.extract_text() or "") for page in reader.pages)


def _pdf_page_count(data: bytes) -> int:
    return len(PdfReader(BytesIO(data)).pages)


def _load_report(db_session, report_id: str) -> AssessmentReport:
    db_session.expire_all()
    row = db_session.get(AssessmentReport, report_id)
    assert row is not None
    return row


def _replace_snapshot(db_session, report_id: str, snapshot: dict, *, update_digest: bool) -> None:
    row = _load_report(db_session, report_id)
    if update_digest:
        digest = content_digest(snapshot["content"])
        snapshot = copy.deepcopy(snapshot)
        snapshot["envelope"]["snapshot_digest"] = digest
        row.snapshot_digest = digest
    row.snapshot_json = snapshot
    flag_modified(row, "snapshot_json")
    db_session.commit()


def _mutate_content(db_session, report_id: str, mutator, *, update_digest: bool) -> None:
    row = _load_report(db_session, report_id)
    snapshot = copy.deepcopy(dict(row.snapshot_json))
    mutator(snapshot)
    _replace_snapshot(db_session, report_id, snapshot, update_digest=update_digest)


# ---------------------------------------------------------------- unit helpers


def test_vendored_font_matches_source_metadata():
    assert FONT_FILE.is_file()
    assert FONT_SOURCE_FILE.is_file()
    actual = hashlib.sha256(FONT_FILE.read_bytes()).hexdigest()
    assert actual == expected_font_sha256()
    assert FONT_FILE.stat().st_size == 10_415_420
    assert actual == "9e1d729e7e2b36f9ef439da102f8c134c10aabe46f1c843bf0aca5c043b86f76"


def test_m24_support_boundary_is_explicit():
    assert is_supported_pdf_char("A")
    assert is_supported_pdf_char("é")
    assert is_supported_pdf_char("–")
    assert is_supported_pdf_char("—")
    assert is_supported_pdf_char("테")
    assert not is_supported_pdf_char("\u0301")
    assert not is_supported_pdf_char("中")
    assert not is_supported_pdf_char("漢")
    assert not is_supported_pdf_char("ا")
    assert not is_supported_pdf_char("प")
    assert not is_supported_pdf_char("😀")
    assert not is_supported_pdf_char("\x01")


def test_nfc_normalization_is_display_only():
    assert normalize_pdf_text("Cafe\u0301") == "Café"
    assert normalize_pdf_text(unicodedata.normalize("NFD", "테스트")) == "테스트"
    assert normalize_pdf_text("x\u0301") == "x\u0301"
    assert "&eacute;" not in plain_pdf_text("Café")


def test_plain_pdf_text_is_the_only_escape_path():
    assert "&amp;" in plain_pdf_text("a & b")
    assert "&lt;script&gt;" in plain_pdf_text("<script>alert(1)</script>")
    assert "&lt;img" in plain_pdf_text("<img src='https://evil.example/x'>")
    assert "&#39;" in plain_pdf_text("<img src='https://evil.example/x'>")
    assert "&lt;link" in plain_pdf_text("<link href='file:///etc/passwd'>x</link>")
    assert "url(https://evil.example/x)" in plain_pdf_text("url(https://evil.example/x)")
    assert "<br/>" in plain_pdf_text("line1\nline2")
    assert "&lt;br/&gt;" in plain_pdf_text("<br/>")


def test_sanitize_pdf_filename_is_strict():
    assert sanitize_pdf_filename("Acme.Example", 2) == "scout-acme.example-report-v2.pdf"
    assert ".." not in sanitize_pdf_filename("../etc/passwd", 1)
    assert "/" not in sanitize_pdf_filename("a/b\\c", 1)
    assert "\\" not in sanitize_pdf_filename("a\\b", 1)
    assert "\n" not in sanitize_pdf_filename("bad\r\nname", 1)
    assert not sanitize_pdf_filename("...hidden.example", 1).startswith(".")
    assert sanitize_pdf_filename("", 1) == "scout-report-report-v1.pdf"


def test_snapshot_size_is_utf8_bytes_not_characters():
    payload = {"pad": "테스트" * 100}
    char_count = len(json.dumps(payload, ensure_ascii=False))
    byte_count = snapshot_utf8_size(payload)
    assert byte_count > char_count


def test_pdf_route_module_does_not_import_reportlab():
    source = (
        Path(__file__).resolve().parents[1] / "app/api/routes/reports.py"
    ).read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert all(not alias.name.startswith("reportlab") for alias in node.names)
        if isinstance(node, ast.ImportFrom):
            assert not (node.module or "").startswith("reportlab")


def test_pdf_endpoint_is_sync_for_threadpool_offload():
    from app.api.routes.reports import export_report_pdf_endpoint

    assert not inspect.iscoroutinefunction(export_report_pdf_endpoint)


def test_pdf_module_does_not_claim_an_in_process_timeout():
    source = (Path(__file__).resolve().parents[1] / "app/services/reports/pdf.py").read_text(
        encoding="utf-8"
    )
    assert "wait_for" not in source
    assert "15 second" not in source.lower()
    assert "15-second" not in source.lower()


def test_ready_route_does_not_check_pdf_renderer():
    source = (Path(__file__).resolve().parents[1] / "app/api/routes/health.py").read_text(
        encoding="utf-8"
    )
    assert "pdf" not in source.lower()
    assert "reportlab" not in source.lower()


# ------------------------------------------------------------- HTTP / RBAC


def test_member_can_export_pdf_without_active_org_switch(
    client, make_token, seed_user_a, dns_resolver, engine
):
    user_id, org_id = seed_user_a
    admin_token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    operation_id = _clean_completed_operation(
        client, admin_token, dns_resolver, engine, "pdf-member.example"
    )
    report = _generate(client, admin_token, operation_id).json()
    member_token = make_token(sub=user_id, org_id=org_id, org_role="org:member")
    response = _pdf(client, member_token, report["id"])
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("application/pdf")
    assert response.content.startswith(b"%PDF-")
    filename = f'attachment; filename="scout-pdf-member.example-report-v{report["report_version"]}.pdf"'
    assert response.headers["content-disposition"] == filename
    text = _pdf_text(response.content)
    assert "pdf-member.example" in text
    assert f"v{report['report_version']}" in text
    assert report["snapshot"]["envelope"]["generated_at"] in text
    assert "Scout PDF renderer 2" in text
    assert "Assessment Incomplete" not in text


def test_unauthenticated_pdf_is_401(client):
    response = client.get(f"/v1/reports/{uuid4()}/pdf")
    assert response.status_code == 401
    assert not response.content.startswith(b"%PDF-")


def test_cross_org_pdf_is_404(
    client, make_token, seed_user_a, seed_user_b, dns_resolver, engine
):
    user_a, org_a = seed_user_a
    user_b, org_b = seed_user_b
    token_a = make_token(sub=user_a, org_id=org_a, org_role="org:admin")
    token_b = make_token(sub=user_b, org_id=org_b, org_role="org:admin")
    operation_id = _clean_completed_operation(
        client, token_a, dns_resolver, engine, "pdf-cross.example"
    )
    report_id = _generate(client, token_a, operation_id).json()["id"]
    response = _pdf(client, token_b, report_id)
    assert response.status_code == 404
    assert response.json()["error"]["message"] == "Assessment report not found"
    assert not response.content.startswith(b"%PDF-")


def test_pdf_rate_limit_does_not_disclose_cross_org_ids(
    client, make_token, seed_user_a, seed_user_b, dns_resolver, engine, monkeypatch
):
    monkeypatch.setenv("RATE_LIMIT_REPORT_PDF_EXPORT", "1")
    reset_settings_cache()

    user_a, org_a = seed_user_a
    user_b, org_b = seed_user_b
    token_a = make_token(sub=user_a, org_id=org_a, org_role="org:admin")
    token_b = make_token(sub=user_b, org_id=org_b, org_role="org:admin")
    report_a = _generate(
        client,
        token_a,
        _clean_completed_operation(client, token_a, dns_resolver, engine, "pdf-rl-a.example"),
    ).json()["id"]
    report_b = _generate(
        client,
        token_b,
        _clean_completed_operation(client, token_b, dns_resolver, engine, "pdf-rl-b.example"),
    ).json()["id"]

    for _ in range(3):
        leaked = _pdf(client, token_b, report_a)
        assert leaked.status_code == 404, leaked.text
        assert leaked.json()["error"]["code"] != "rate_limited"

    allowed = _pdf(client, token_b, report_b)
    assert allowed.status_code == 200, allowed.text
    limited = _pdf(client, token_b, report_b)
    assert limited.status_code == 429


# ------------------------------------------------------------- integrity


def test_tampered_snapshot_without_digest_change_is_409(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    operation_id = _clean_completed_operation(
        client, token, dns_resolver, engine, "pdf-tamper.example"
    )
    report_id = _generate(client, token, operation_id).json()["id"]

    def _tamper(snapshot):
        snapshot["content"]["summary"]["headline_statement"] = "TAMPERED CLEAN BILL"

    _mutate_content(db_session, report_id, _tamper, update_digest=False)
    row = _load_report(db_session, report_id)
    assert content_digest(row.snapshot_json["content"]) != row.snapshot_digest

    response = _pdf(client, token, report_id)
    assert response.status_code == 409
    assert response.json()["error"]["message"] == "Report snapshot integrity check failed"
    assert not response.content.startswith(b"%PDF-")
    assert b"%PDF-" not in response.content


def test_envelope_mismatch_is_409(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    report = _generate(
        client,
        token,
        _clean_completed_operation(client, token, dns_resolver, engine, "pdf-env.example"),
    ).json()

    def _tamper(snapshot):
        snapshot["envelope"]["report_id"] = str(uuid4())

    _mutate_content(db_session, report["id"], _tamper, update_digest=False)
    response = _pdf(client, token, report["id"])
    assert response.status_code == 409
    assert "integrity" in response.json()["error"]["message"].lower()
    assert not response.content.startswith(b"%PDF-")


def test_target_domain_disagreement_is_409(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    report_id = _generate(
        client,
        token,
        _clean_completed_operation(client, token, dns_resolver, engine, "pdf-domain.example"),
    ).json()["id"]
    row = _load_report(db_session, report_id)
    row.target_domain = "other-header.example"
    db_session.commit()
    response = _pdf(client, token, report_id)
    assert response.status_code == 409
    assert not response.content.startswith(b"%PDF-")


def test_unsupported_schema_version_is_409(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    report_id = _generate(
        client,
        token,
        _clean_completed_operation(client, token, dns_resolver, engine, "pdf-schema.example"),
    ).json()["id"]
    row = _load_report(db_session, report_id)
    row.schema_version = 99
    db_session.commit()
    response = _pdf(client, token, report_id)
    assert response.status_code == 409
    assert response.json()["error"]["message"] == "Unsupported report schema version"
    assert not response.content.startswith(b"%PDF-")


def test_oversized_snapshot_is_413_before_render(
    client, make_token, seed_user_a, dns_resolver, engine, db_session, monkeypatch
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    report_id = _generate(
        client,
        token,
        _clean_completed_operation(client, token, dns_resolver, engine, "pdf-size.example"),
    ).json()["id"]

    def _pad(snapshot):
        snapshot["content"]["export_padding"] = "x" * (MAX_SNAPSHOT_BYTES + 64)

    _mutate_content(db_session, report_id, _pad, update_digest=True)
    row = _load_report(db_session, report_id)
    assert snapshot_utf8_size(row.snapshot_json) > MAX_SNAPSHOT_BYTES

    rendered = {"called": False}

    def _banned(snapshot):
        rendered["called"] = True
        raise AssertionError("renderer must not start for an oversized snapshot")

    monkeypatch.setattr("app.services.reports.pdf.render_pdf_bytes", _banned)
    response = _pdf(client, token, report_id)
    assert response.status_code == 413
    assert "size limit" in response.json()["error"]["message"]
    assert "export_padding" not in response.text
    assert not response.content.startswith(b"%PDF-")
    assert rendered["called"] is False


def test_too_many_findings_is_413(
    client, make_token, seed_user_a, dns_resolver, engine, db_session, monkeypatch
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    _, operation_id, _ = _operation_with_open_finding(
        client, token, dns_resolver, engine, "pdf-findings.example"
    )
    report_id = _generate(client, token, operation_id).json()["id"]

    def _inflate(snapshot):
        template = snapshot["content"]["findings"][0]
        snapshot["content"]["findings"] = [copy.deepcopy(template) for _ in range(MAX_FINDINGS + 1)]

    _mutate_content(db_session, report_id, _inflate, update_digest=True)
    rendered = {"called": False}
    monkeypatch.setattr(
        "app.services.reports.pdf.render_pdf_bytes",
        lambda snapshot: rendered.update(called=True) or b"%PDF-fake",
    )
    response = _pdf(client, token, report_id)
    assert response.status_code == 413
    assert rendered["called"] is False
    assert not response.content.startswith(b"%PDF-")


# ------------------------------------------------------------- unicode / markup


def test_supported_unicode_and_nfc_forms_export(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    report_id = _generate(
        client,
        token,
        _clean_completed_operation(client, token, dns_resolver, engine, "pdf-unicode.example"),
    ).json()["id"]

    def _latin(snapshot):
        snapshot["content"]["identity"]["organization_name"] = "Café – résumé"

    _mutate_content(db_session, report_id, _latin, update_digest=True)
    latin = _pdf(client, token, report_id)
    assert latin.status_code == 200, latin.text
    assert "Café – résumé" in _pdf_text(latin.content)

    def _hangul(snapshot):
        snapshot["content"]["identity"]["organization_name"] = "테스트"

    _mutate_content(db_session, report_id, _hangul, update_digest=True)
    hangul = _pdf(client, token, report_id)
    assert hangul.status_code == 200, hangul.text
    assert "테스트" in _pdf_text(hangul.content)

    def _mixed(snapshot):
        snapshot["content"]["identity"]["organization_name"] = "Scout 테스트 — Café"

    _mutate_content(db_session, report_id, _mixed, update_digest=True)
    mixed = _pdf(client, token, report_id)
    assert mixed.status_code == 200, mixed.text
    assert "Scout 테스트 — Café" in _pdf_text(mixed.content)


def _pdf_with_org_name(client, token, db_session, report_id: str, value: str):
    def _inject(snapshot, name=value):
        snapshot["content"]["identity"]["organization_name"] = name

    _mutate_content(db_session, report_id, _inject, update_digest=True)
    return _pdf(client, token, report_id)


def test_decomposed_latin_accent_exports_after_nfc(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    report_id = _generate(
        client,
        token,
        _clean_completed_operation(client, token, dns_resolver, engine, "pdf-nfc-latin.example"),
    ).json()["id"]
    stored_form = "Cafe\u0301"
    assert stored_form != unicodedata.normalize("NFC", stored_form)
    response = _pdf_with_org_name(client, token, db_session, report_id, stored_form)
    row = _load_report(db_session, report_id)
    assert row.snapshot_json["content"]["identity"]["organization_name"] == stored_form
    assert response.status_code == 200, response.text
    extracted = unicodedata.normalize("NFC", _pdf_text(response.content))
    assert "Café" in extracted


def test_decomposed_hangul_exports_after_nfc(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    report_id = _generate(
        client,
        token,
        _clean_completed_operation(client, token, dns_resolver, engine, "pdf-nfc-hangul.example"),
    ).json()["id"]
    stored_form = unicodedata.normalize("NFD", "테스트")
    assert stored_form != "테스트"
    assert unicodedata.normalize("NFC", stored_form) == "테스트"
    response = _pdf_with_org_name(client, token, db_session, report_id, stored_form)
    row = _load_report(db_session, report_id)
    assert row.snapshot_json["content"]["identity"]["organization_name"] == stored_form
    assert response.status_code == 200, response.text
    extracted = unicodedata.normalize("NFC", _pdf_text(response.content))
    assert "테스트" in extracted


def test_remaining_combining_mark_after_nfc_is_409(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    report_id = _generate(
        client,
        token,
        _clean_completed_operation(client, token, dns_resolver, engine, "pdf-nfc-mark.example"),
    ).json()["id"]
    leftover = "x\u0301"
    assert unicodedata.normalize("NFC", leftover) == leftover
    assert any(unicodedata.category(char) == "Mn" for char in leftover)
    response = _pdf_with_org_name(client, token, db_session, report_id, leftover)
    assert response.status_code == 409, response.text
    assert (
        response.json()["error"]["message"]
        == "Report contains characters that cannot be exported"
    )
    assert not response.content.startswith(b"%PDF-")
    assert b"%PDF-" not in response.content


def _embedded_truetype_stream_sizes(data: bytes) -> list[int]:
    reader = PdfReader(BytesIO(data))
    sizes: list[int] = []

    def _walk(obj, seen: set[int]) -> None:
        if hasattr(obj, "get_object"):
            ident = id(obj)
            if ident in seen:
                return
            seen.add(ident)
            obj = obj.get_object()
        if isinstance(obj, dict):
            if "/FontFile2" in obj:
                stream = obj["/FontFile2"]
                if hasattr(stream, "get_object"):
                    stream = stream.get_object()
                payload = stream.get_data() if hasattr(stream, "get_data") else bytes(stream)
                sizes.append(len(payload))
            for value in obj.values():
                _walk(value, seen)
        elif isinstance(obj, list):
            for value in obj:
                _walk(value, seen)

    for page in reader.pages:
        _walk(page.get("/Resources"), set())
    return sizes


def test_pdf_embeds_subset_of_vendored_font(
    client, make_token, seed_user_a, dns_resolver, engine
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    report_id = _generate(
        client,
        token,
        _clean_completed_operation(client, token, dns_resolver, engine, "pdf-embed.example"),
    ).json()["id"]
    response = _pdf(client, token, report_id)
    assert response.status_code == 200, response.text
    assert b"/FontFile2" in response.content
    sizes = _embedded_truetype_stream_sizes(response.content)
    assert sizes
    assert max(sizes) < FONT_FILE.stat().st_size // 4
    assert max(sizes) < 1_500_000


def test_unsupported_scripts_fail_closed(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    report_id = _generate(
        client,
        token,
        _clean_completed_operation(client, token, dns_resolver, engine, "pdf-reject.example"),
    ).json()["id"]
    samples = ("😀", "السلام", "परीक्षण", "中")
    for sample in samples:
        def _inject(snapshot, value=sample):
            snapshot["content"]["identity"]["organization_name"] = value

        _mutate_content(db_session, report_id, _inject, update_digest=True)
        response = _pdf(client, token, report_id)
        assert response.status_code == 409, (sample, response.text)
        assert (
            response.json()["error"]["message"]
            == "Report contains characters that cannot be exported"
        )
        assert not response.content.startswith(b"%PDF-")
        assert b"%PDF-" not in response.content


def test_reportlab_markup_is_literal_text_and_causes_no_network(
    client, make_token, seed_user_a, dns_resolver, engine, db_session, monkeypatch
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    _, operation_id, _ = _operation_with_open_finding(
        client, token, dns_resolver, engine, "pdf-xss.example"
    )
    report_id = _generate(client, token, operation_id).json()["id"]

    def _inject(snapshot):
        finding = snapshot["content"]["findings"][0]
        finding["title"] = INJECTION_STRINGS[0]
        finding["summary"] = INJECTION_STRINGS[1]
        finding["business_impact"] = INJECTION_STRINGS[2]
        finding["remediation_guidance"] = INJECTION_STRINGS[3]
        finding["evidence"] = {
            "observed_facts": {"note": INJECTION_STRINGS[0]},
            "missing_security_headers": [],
            "deterministic_signals": {},
        }

    _mutate_content(db_session, report_id, _inject, update_digest=True)

    attempted: list[str] = []

    def _block(*args, **kwargs):
        attempted.append(repr((args, kwargs)))
        raise AssertionError("outbound network during PDF export")

    monkeypatch.setattr("urllib.request.urlopen", _block)
    monkeypatch.setattr("urllib.request.OpenerDirector.open", _block)
    try:
        import reportlab.lib.utils as rl_utils

        monkeypatch.setattr(rl_utils, "open_for_read", _block)
    except Exception:
        pass

    response = _pdf(client, token, report_id)
    assert response.status_code == 200, response.text
    assert attempted == []
    text = _pdf_text(response.content)
    for marker in INJECTION_STRINGS:
        assert marker in text, marker


# ------------------------------------------------------------- layout / incomplete / versions


def test_long_finding_spans_pages_without_layout_error(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    _, operation_id, _ = _operation_with_open_finding(
        client, token, dns_resolver, engine, "pdf-long.example"
    )
    report_id = _generate(client, token, operation_id).json()["id"]
    marker = "LONG-FINDING-MARKER-M23"

    def _lengthen(snapshot):
        finding = snapshot["content"]["findings"][0]
        finding["title"] = "Oversized finding remains exportable"
        finding["business_impact"] = marker + "\n" + ("impact-line " * 40 + "\n") * 80
        finding["remediation_guidance"] = ("remediation-line " * 40 + "\n") * 80

    _mutate_content(db_session, report_id, _lengthen, update_digest=True)
    response = _pdf(client, token, report_id)
    assert response.status_code == 200, response.text
    assert response.content.startswith(b"%PDF-")
    assert _pdf_page_count(response.content) >= 2
    text = _pdf_text(response.content)
    assert marker in text
    assert "Oversized finding remains exportable" in text


def test_incomplete_report_pdf_never_looks_clean(
    client, make_token, seed_user_a, dns_resolver
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    target_id = _create_verified_target(client, token, "pdf-stopped.example", dns_resolver)
    operation_id = client.post(
        "/v1/operations", headers=_auth(token), json={"target_id": target_id}
    ).json()["id"]
    assert client.post(f"/v1/operations/{operation_id}/stop", headers=_auth(token)).json()[
        "status"
    ] == "stopped"
    report = _generate(client, token, operation_id).json()
    assert report["assessment_completeness"] == "incomplete"
    response = _pdf(client, token, report["id"])
    assert response.status_code == 200, response.text
    text = _pdf_text(response.content)
    assert text.count("Assessment Incomplete") >= 2
    assert "did not run to completion" in text
    assert "No Open Supported Findings" not in text


def test_v1_pdf_stays_frozen_after_v2(
    client, make_token, seed_user_a, dns_resolver, engine
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    _, operation_id, finding_id = _operation_with_open_finding(
        client, token, dns_resolver, engine, "pdf-v2.example"
    )
    v1 = _generate(client, token, operation_id).json()
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
    v2 = _generate(client, token, operation_id).json()
    assert v2["report_version"] == 2

    pdf_v1 = _pdf(client, token, v1["id"])
    pdf_v2 = _pdf(client, token, v2["id"])
    assert pdf_v1.status_code == 200
    assert pdf_v2.status_code == 200
    text_v1 = _pdf_text(pdf_v1.content)
    text_v2 = _pdf_text(pdf_v2.content)
    assert "v1" in text_v1
    assert "v2" in text_v2
    assert v1["snapshot"]["content"]["findings"][0]["status"] == "open"
    assert "open" in text_v1.lower()
    assert "ready_for_retest" in text_v2 or "ready for retest" in text_v2.lower()
    assert pdf_v1.headers["content-disposition"] == (
        'attachment; filename="scout-pdf-v2.example-report-v1.pdf"'
    )
    assert pdf_v2.headers["content-disposition"] == (
        'attachment; filename="scout-pdf-v2.example-report-v2.pdf"'
    )


# ------------------------------------------------------------- isolation / availability


def test_pdf_export_performs_no_live_assessment_joins(
    client, make_token, seed_user_a, dns_resolver, engine
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    _, operation_id, _ = _operation_with_open_finding(
        client, token, dns_resolver, engine, "pdf-join.example"
    )
    report_id = _generate(client, token, operation_id).json()["id"]
    statements: list[str] = []

    def _capture(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement.lower())

    event.listen(engine, "before_cursor_execute", _capture)
    try:
        response = _pdf(client, token, report_id)
    finally:
        event.remove(engine, "before_cursor_execute", _capture)

    assert response.status_code == 200, response.text
    joined = " ".join(statements)
    for table in (
        "findings",
        "retest_attempts",
        "validation_attempts",
        "security_candidates",
        "operation_coverage_summaries",
        "operation_diff_summaries",
        "discovery_observations",
        "operations",
    ):
        assert re.search(rf"\b(from|join)\s+{table}\b", joined) is None, table
    assert re.search(r"\bfrom\s+assessment_reports\b", joined) is not None


def test_pdf_export_does_not_write_a_download_audit_event(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    report_id = _generate(
        client,
        token,
        _clean_completed_operation(client, token, dns_resolver, engine, "pdf-audit.example"),
    ).json()["id"]
    before = list(db_session.scalars(select(AuditEvent.action)).all())
    assert _pdf(client, token, report_id).status_code == 200
    db_session.expire_all()
    after = list(db_session.scalars(select(AuditEvent.action)).all())
    assert after == before
    assert "assessment_report.pdf_exported" not in after
    assert after.count("assessment_report.generated") == 1


def test_renderer_unavailable_is_503_and_core_api_stays_up(
    client, make_token, seed_user_a, dns_resolver, engine, monkeypatch
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    report_id = _generate(
        client,
        token,
        _clean_completed_operation(client, token, dns_resolver, engine, "pdf-503.example"),
    ).json()["id"]

    def _unavailable():
        raise PdfRendererUnavailable("ReportLab is not available")

    monkeypatch.setattr("app.services.reports.pdf._load_reportlab", _unavailable)
    response = _pdf(client, token, report_id)
    assert response.status_code == 503
    assert response.json()["error"]["message"] == "PDF export is unavailable"
    assert not response.content.startswith(b"%PDF-")
    assert client.get("/ready").status_code == 200
    assert client.get("/ready").json()["status"] == "ready"
    assert client.get(f"/v1/reports/{report_id}", headers=_auth(token)).status_code == 200
    assert client.get("/v1/operations", headers=_auth(token)).status_code == 200


def test_font_checksum_mismatch_is_503_only_on_pdf(
    client, make_token, seed_user_a, dns_resolver, engine, monkeypatch
):
    import app.services.reports.pdf as pdf_mod

    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    report_id = _generate(
        client,
        token,
        _clean_completed_operation(client, token, dns_resolver, engine, "pdf-hash.example"),
    ).json()["id"]
    pdf_mod._FONTS_REGISTERED = False
    monkeypatch.setattr(pdf_mod, "expected_font_sha256", lambda: "0" * 64)
    response = _pdf(client, token, report_id)
    assert response.status_code == 503
    assert response.json()["error"]["message"] == "PDF export is unavailable"
    assert not response.content.startswith(b"%PDF-")
    assert client.get("/ready").json()["status"] == "ready"
    pdf_mod._FONTS_REGISTERED = False


def test_render_exception_cannot_return_a_partial_pdf(
    client, make_token, seed_user_a, dns_resolver, engine, monkeypatch
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    report_id = _generate(
        client,
        token,
        _clean_completed_operation(client, token, dns_resolver, engine, "pdf-fail.example"),
    ).json()["id"]

    def _explode(snapshot):
        raise RuntimeError("forced renderer failure after validation")

    monkeypatch.setattr("app.services.reports.pdf.render_pdf_bytes", _explode)
    response = _pdf(client, token, report_id)
    assert response.status_code == 500
    assert response.headers["content-type"].startswith("application/json")
    assert not response.content.startswith(b"%PDF-")
    assert b"%PDF-" not in response.content
    assert "forced renderer" not in response.text


def test_pdf_write_verbs_are_not_exposed(
    client, make_token, seed_user_a, dns_resolver, engine
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, org_role="org:admin")
    report_id = _generate(
        client,
        token,
        _clean_completed_operation(client, token, dns_resolver, engine, "pdf-verbs.example"),
    ).json()["id"]
    for method in ("put", "patch", "delete", "post"):
        response = getattr(client, method)(
            f"/v1/reports/{report_id}/pdf", headers=_auth(token)
        )
        assert response.status_code == 405, (method, response.status_code)


def test_renderer_version_and_action_constants():
    assert PDF_RENDERER_VERSION == 2
    assert ACTION_REPORT_PDF_EXPORT == "report.pdf_export"


def test_frontend_surfaces_safe_unsupported_pdf_message():
    web_root = Path(__file__).resolve().parents[2] / "web"
    api = (web_root / "lib/api.ts").read_text(encoding="utf-8")
    button = (
        web_root / "app/(app)/dashboard/reports/[reportId]/export-pdf-button.tsx"
    ).read_text(encoding="utf-8")
    assert "This report contains characters that the PDF exporter cannot render yet." in api
    assert "This report cannot be exported." in api
    assert "PDF export is unavailable" in api
    assert "exportAssessmentReportPdf" in button
    assert "NotoSansKR" not in api
    assert "reportlab" not in api.lower()
    assert "U+" not in api
