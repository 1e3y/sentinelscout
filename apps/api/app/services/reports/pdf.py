"""On-demand PDF export from an immutable AssessmentReport snapshot.

ReportLab is imported lazily so a missing renderer cannot prevent API startup.
Visible assessment content is taken only from snapshot_json after integrity checks.

There is no application-level renderer timeout. ReportLab work is in-process CPU
bound; a hard kill would require an isolated render process, which Milestone 23
does not introduce. Bounds are snapshot UTF-8 size, findings count, export rate
limit, FastAPI sync-threadpool offload, and infrastructure request timeouts.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from io import BytesIO
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from fastapi import HTTPException, status

from app.models.report import REPORT_SCHEMA_VERSION, AssessmentReport
from app.services.reports.snapshot import canonical_json, content_digest
from app.services.reports.summary import HEADLINE_LABELS

PDF_RENDERER_VERSION = 3
SUPPORTED_REPORT_SCHEMA_VERSION = REPORT_SCHEMA_VERSION
MAX_SNAPSHOT_BYTES = 2 * 1024 * 1024
MAX_FINDINGS = 200
MAX_FILENAME_STEM = 80

_FONT_DIR = Path(__file__).resolve().parents[2] / "assets" / "fonts"
FONT_FILE = _FONT_DIR / "NotoSansKR-VF.ttf"
FONT_SOURCE_FILE = _FONT_DIR / "SOURCE.txt"
_FONT_NAME = "ScoutNotoKR"

_PDF_MAGIC = b"%PDF-"
_ALLOWED_WHITESPACE = frozenset("\t\n\r ")
_COMMON_PUNCTUATION = frozenset(
    {
        "\u2010",  # hyphen
        "\u2011",  # non-breaking hyphen
        "\u2012",  # figure dash
        "\u2013",  # en dash
        "\u2014",  # em dash
        "\u2018",
        "\u2019",
        "\u201c",
        "\u201d",
        "\u2026",
    }
)
_FORBIDDEN_FORMAT_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn"})
_COMBINING_CATEGORIES = frozenset({"Mn", "Mc", "Me"})

_FILENAME_SAFE = re.compile(r"[^a-z0-9._-]+")


class PdfRendererUnavailable(RuntimeError):
    """ReportLab is not importable in this process."""


class PdfSnapshotError(ValueError):
    """Snapshot failed a fail-closed export check."""

    def __init__(self, detail: str, *, status_code: int) -> None:
        super().__init__(detail)
        self.detail = detail
        self.status_code = status_code


def normalize_pdf_text(value: Any) -> str:
    """NFC normalize for rendering only. Never write this back to the snapshot."""
    return unicodedata.normalize("NFC", "" if value is None else str(value))


def is_supported_pdf_char(char: str) -> bool:
    """Explicit M24 rendering boundary. Glyph presence is checked separately.

    Combining marks are not a supported family. NFC may compose them away
    first; any mark that remains after NFC is rejected.
    """
    if unicodedata.category(char) in _COMBINING_CATEGORIES:
        return False
    if char in _ALLOWED_WHITESPACE or char in _COMMON_PUNCTUATION:
        return True
    code = ord(char)
    if 0x20 <= code <= 0x7E:
        return True
    if 0x00A0 <= code <= 0x00FF:
        return True
    if 0x0100 <= code <= 0x017F:
        return True
    if 0x1E00 <= code <= 0x1EFF:
        return True
    if 0xAC00 <= code <= 0xD7A3:
        return True
    return False


def plain_pdf_text(value: Any) -> str:
    """Single escape path for ReportLab Paragraph mini-markup.

    Snapshot strings are data, not markup. Every untrusted string that enters a
    Paragraph must go through this helper. Newlines become trusted ``<br/>``
    only after metacharacters are escaped. NFC is applied for display only.
    """
    text = normalize_pdf_text(value)
    escaped = escape(text, {'"': "&quot;", "'": "&#39;"})
    return escaped.replace("\n", "<br/>")


def snapshot_utf8_size(snapshot: Any) -> int:
    """UTF-8 byte length of the serialized snapshot, not Python character count."""
    if isinstance(snapshot, dict):
        try:
            return len(canonical_json(snapshot).encode("utf-8"))
        except (TypeError, ValueError):
            pass
    return len(
        json.dumps(snapshot, ensure_ascii=False, allow_nan=False, default=str).encode("utf-8")
    )


def sanitize_pdf_filename(domain: str, version: int) -> str:
    raw = str(domain or "report").strip().lower()
    raw = raw.replace("\\", "-").replace("/", "-")
    raw = raw.replace("\r", "-").replace("\n", "-")
    collapsed = _FILENAME_SAFE.sub("-", raw)
    collapsed = re.sub(r"-{2,}", "-", collapsed)
    collapsed = collapsed.lstrip(".")
    collapsed = collapsed.replace("..", "-")
    collapsed = collapsed.strip(".-")
    if not collapsed:
        collapsed = "report"
    collapsed = collapsed[:MAX_FILENAME_STEM].strip(".-") or "report"
    return f"scout-{collapsed}-report-v{int(version)}.pdf"


def _conflict(detail: str) -> PdfSnapshotError:
    return PdfSnapshotError(detail, status_code=status.HTTP_409_CONFLICT)


def _too_large(detail: str) -> PdfSnapshotError:
    return PdfSnapshotError(detail, status_code=status.HTTP_413_CONTENT_TOO_LARGE)


def _load_reportlab() -> dict[str, Any]:
    """Lazy import. Must not run at API import time."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
        from reportlab.platypus import (
            KeepTogether,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except ImportError as exc:
        raise PdfRendererUnavailable("ReportLab is not available") from exc
    return {
        "colors": colors,
        "TA_CENTER": TA_CENTER,
        "TA_LEFT": TA_LEFT,
        "letter": letter,
        "ParagraphStyle": ParagraphStyle,
        "inch": inch,
        "pdfmetrics": pdfmetrics,
        "TTFont": TTFont,
        "KeepTogether": KeepTogether,
        "Paragraph": Paragraph,
        "SimpleDocTemplate": SimpleDocTemplate,
        "Spacer": Spacer,
        "Table": Table,
        "TableStyle": TableStyle,
    }


def expected_font_sha256() -> str:
    if not FONT_SOURCE_FILE.is_file():
        raise PdfRendererUnavailable("PDF font metadata is not available")
    for line in FONT_SOURCE_FILE.read_text(encoding="utf-8").splitlines():
        key, _, value = line.partition(":")
        if key.strip().lower() == "sha256":
            digest = value.strip().lower()
            if len(digest) == 64 and all(part in "0123456789abcdef" for part in digest):
                return digest
    raise PdfRendererUnavailable("PDF font metadata is not available")


_FONTS_REGISTERED = False


def _ensure_fonts(rl: dict[str, Any]) -> None:
    global _FONTS_REGISTERED
    if _FONTS_REGISTERED:
        return
    if not FONT_FILE.is_file():
        raise PdfRendererUnavailable("PDF export font is not available")
    try:
        expected = expected_font_sha256()
        actual = hashlib.sha256(FONT_FILE.read_bytes()).hexdigest()
    except PdfRendererUnavailable:
        raise
    except OSError as exc:
        raise PdfRendererUnavailable("PDF export font is not available") from exc
    if actual != expected:
        raise PdfRendererUnavailable("PDF export font is not available")
    try:
        rl["pdfmetrics"].registerFont(rl["TTFont"](_FONT_NAME, str(FONT_FILE)))
    except Exception as exc:
        raise PdfRendererUnavailable("PDF export font is not available") from exc
    _FONTS_REGISTERED = True


def _glyph_missing(rl: dict[str, Any], char: str) -> bool:
    font = rl["pdfmetrics"].getFont(_FONT_NAME)
    face = getattr(font, "face", None)
    mapping = getattr(face, "charToGlyph", None)
    if mapping is None:
        return True
    glyph = mapping.get(ord(char))
    return glyph in (None, 0)


def _assert_fonts_cover(rl: dict[str, Any], texts: list[str]) -> None:
    """Fail closed unless the character is in the M24 boundary and has a glyph."""
    seen: set[str] = set()
    for text in texts:
        normalized = normalize_pdf_text(text)
        for char in normalized:
            if char in seen:
                continue
            seen.add(char)
            if char in _ALLOWED_WHITESPACE:
                continue
            category = unicodedata.category(char)
            if category in _FORBIDDEN_FORMAT_CATEGORIES or category in _COMBINING_CATEGORIES:
                raise _conflict("Report contains characters that cannot be exported")
            if not is_supported_pdf_char(char) or _glyph_missing(rl, char):
                raise _conflict("Report contains characters that cannot be exported")


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def validate_snapshot_for_export(report: AssessmentReport) -> dict[str, Any]:
    """Integrity + size + schema. Does not query live assessment state."""
    snapshot = report.snapshot_json
    if not isinstance(snapshot, dict):
        raise _conflict("Report snapshot is not readable")

    size = snapshot_utf8_size(snapshot)
    if size > MAX_SNAPSHOT_BYTES:
        raise _too_large("Report snapshot exceeds the export size limit")

    if int(report.schema_version) != SUPPORTED_REPORT_SCHEMA_VERSION:
        raise _conflict("Unsupported report schema version")
    top_schema = snapshot.get("report_schema_version")
    if top_schema != SUPPORTED_REPORT_SCHEMA_VERSION:
        raise _conflict("Unsupported report schema version")

    envelope = _as_dict(snapshot.get("envelope"))
    content = snapshot.get("content")
    if not isinstance(content, dict):
        raise _conflict("Report snapshot is not readable")
    if content.get("report_schema_version") != SUPPORTED_REPORT_SCHEMA_VERSION:
        raise _conflict("Unsupported report schema version")

    if str(envelope.get("report_id") or "") != str(report.id):
        raise _conflict("Report snapshot integrity check failed")
    try:
        envelope_version = int(envelope.get("report_version"))
    except (TypeError, ValueError) as exc:
        raise _conflict("Report snapshot integrity check failed") from exc
    if envelope_version != int(report.report_version):
        raise _conflict("Report snapshot integrity check failed")
    if str(envelope.get("snapshot_digest") or "") != str(report.snapshot_digest):
        raise _conflict("Report snapshot integrity check failed")

    try:
        recomputed = content_digest(content)
    except (TypeError, ValueError) as exc:
        raise _conflict("Report snapshot integrity check failed") from exc
    if recomputed != report.snapshot_digest:
        raise _conflict("Report snapshot integrity check failed")

    identity = _as_dict(content.get("identity"))
    snapshot_domain = str(identity.get("target_domain") or "")
    if not snapshot_domain or snapshot_domain != str(report.target_domain):
        raise _conflict("Report snapshot integrity check failed")

    findings = _as_list(content.get("findings"))
    if len(findings) > MAX_FINDINGS:
        raise _too_large("Report snapshot exceeds the export size limit")

    required_content = (
        "identity",
        "scope",
        "coverage",
        "findings",
        "not_promoted",
        "change_context",
        "summary",
        "methodology",
    )
    if any(key not in content for key in required_content):
        raise _conflict("Report snapshot is not readable")
    return snapshot


def _collect_visible_strings(snapshot: dict[str, Any]) -> list[str]:
    """Plain strings that will be drawn. Used only for glyph coverage."""
    collected: list[str] = []

    def walk(value: Any) -> None:
        if isinstance(value, str):
            collected.append(value)
        elif isinstance(value, dict):
            for item in value.values():
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(snapshot.get("content"))
    envelope = _as_dict(snapshot.get("envelope"))
    collected.append(str(envelope.get("generated_at") or ""))
    return collected


def _styles(rl: dict[str, Any]) -> dict[str, Any]:
    ParagraphStyle = rl["ParagraphStyle"]
    colors = rl["colors"]
    return {
        "kicker": ParagraphStyle(
            "kicker",
            fontName=_FONT_NAME,
            fontSize=8,
            leading=11,
            alignment=rl["TA_LEFT"],
            textColor=colors.HexColor("#52525b"),
            spaceAfter=4,
        ),
        "title": ParagraphStyle(
            "title",
            fontName=_FONT_NAME,
            fontSize=18,
            leading=22,
            textColor=colors.HexColor("#18181b"),
            spaceAfter=10,
        ),
        "h1": ParagraphStyle(
            "h1",
            fontName=_FONT_NAME,
            fontSize=13,
            leading=16,
            spaceBefore=14,
            spaceAfter=6,
            keepWithNext=True,
        ),
        "h2": ParagraphStyle(
            "h2",
            fontName=_FONT_NAME,
            fontSize=11,
            leading=14,
            spaceBefore=8,
            spaceAfter=4,
            keepWithNext=True,
        ),
        "body": ParagraphStyle(
            "body",
            fontName=_FONT_NAME,
            fontSize=9,
            leading=12,
            alignment=rl["TA_LEFT"],
            spaceAfter=6,
        ),
        "small": ParagraphStyle(
            "small",
            fontName=_FONT_NAME,
            fontSize=8,
            leading=11,
            alignment=rl["TA_LEFT"],
            textColor=colors.HexColor("#3f3f46"),
            spaceAfter=4,
        ),
        "banner": ParagraphStyle(
            "banner",
            fontName=_FONT_NAME,
            fontSize=11,
            leading=14,
            alignment=rl["TA_CENTER"],
            textColor=colors.HexColor("#000000"),
        ),
        "banner_body": ParagraphStyle(
            "banner_body",
            fontName=_FONT_NAME,
            fontSize=9,
            leading=12,
            alignment=rl["TA_CENTER"],
        ),
        "label": ParagraphStyle(
            "label",
            fontName=_FONT_NAME,
            fontSize=7,
            leading=9,
            alignment=rl["TA_LEFT"],
            textColor=colors.HexColor("#71717a"),
            spaceAfter=1,
        ),
        "finding_title": ParagraphStyle(
            "finding_title",
            fontName=_FONT_NAME,
            fontSize=10,
            leading=13,
            spaceAfter=4,
            keepWithNext=True,
        ),
        "footer": ParagraphStyle(
            "footer",
            fontName=_FONT_NAME,
            fontSize=7,
            leading=9,
            alignment=rl["TA_LEFT"],
            textColor=colors.HexColor("#52525b"),
        ),
    }


def _p(rl: dict[str, Any], text: Any, style: Any):
    return rl["Paragraph"](plain_pdf_text(text), style)


def _kv(rl: dict[str, Any], styles: dict[str, Any], label: str, value: Any):
    return [
        _p(rl, label.upper(), styles["label"]),
        _p(rl, value if value not in (None, "") else "—", styles["small"]),
    ]


def _incomplete_banner(rl: dict[str, Any], styles: dict[str, Any], content: dict[str, Any]):
    identity = _as_dict(content.get("identity"))
    summary = _as_dict(content.get("summary"))
    if identity.get("assessment_completeness") != "incomplete":
        return None
    colors = rl["colors"]
    inner = [
        _p(rl, "Assessment Incomplete", styles["banner"]),
        rl["Spacer"](1, 6),
        _p(rl, summary.get("headline_statement") or "", styles["banner_body"]),
        _p(
            rl,
            f"Operation status: {identity.get('operation_status')}. "
            "Coverage of the authorized scope is partial.",
            styles["banner_body"],
        ),
    ]
    table = rl["Table"]([[inner]], colWidths=["*"])
    table.setStyle(
        rl["TableStyle"](
            [
                ("BOX", (0, 0), (-1, -1), 2, colors.black),
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fffbeb")),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    return rl["KeepTogether"]([table, rl["Spacer"](1, 10)])


def _join_evidence(evidence: dict[str, Any]) -> list[str]:
    lines: list[str] = []
    observed = _as_dict(evidence.get("observed_facts"))
    for key, value in observed.items():
        if isinstance(value, list):
            lines.append(f"{key}: {', '.join(str(item) for item in value)}")
        else:
            lines.append(f"{key}: {value}")
    headers = _as_list(evidence.get("missing_security_headers"))
    for header in headers:
        if isinstance(header, dict):
            lines.append(
                f"security header {header.get('header_name')}: "
                f"{'present' if header.get('observed') else 'not present'}"
            )
    signals = _as_dict(evidence.get("deterministic_signals"))
    for key, value in signals.items():
        if isinstance(value, list):
            lines.append(f"{key}: {'; '.join(str(item) for item in value)}")
        else:
            lines.append(f"{key}: {value}")
    return lines


def _generation_label(envelope: dict[str, Any], generation_origin: str | None) -> str:
    origin = envelope.get("origin") or generation_origin
    if origin == "scheduled_automatic":
        return "Automatic after scheduled assessment"
    if origin == "manual":
        return "Manual"
    return "Manual"


def _build_story(
    rl: dict[str, Any],
    snapshot: dict[str, Any],
    *,
    generation_origin: str | None = None,
) -> list[Any]:
    styles = _styles(rl)
    envelope = _as_dict(snapshot.get("envelope"))
    content = _as_dict(snapshot.get("content"))
    identity = _as_dict(content.get("identity"))
    scope = _as_dict(content.get("scope"))
    coverage = _as_dict(content.get("coverage"))
    frozen = _as_dict(coverage.get("frozen_operation_coverage"))
    follow_up = _as_dict(coverage.get("follow_up_frozen_for_report"))
    limitations = _as_dict(coverage.get("limitations"))
    summary = _as_dict(content.get("summary"))
    methodology = _as_dict(content.get("methodology"))
    change = _as_dict(content.get("change_context"))
    not_promoted = _as_dict(content.get("not_promoted"))
    findings = [item for item in _as_list(content.get("findings")) if isinstance(item, dict)]

    headline_status = str(summary.get("headline_status") or "")
    headline_label = (
        summary.get("headline_label")
        or HEADLINE_LABELS.get(headline_status, headline_status)
    )
    generated_at = envelope.get("generated_at") or ""

    story: list[Any] = [
        _p(rl, "Sentinel Scout security assessment", styles["kicker"]),
        _p(rl, identity.get("target_domain") or "", styles["title"]),
    ]

    banner = _incomplete_banner(rl, styles, content)
    if banner is not None:
        story.append(banner)
        if headline_status != "assessment_incomplete":
            # Incomplete reports must never present a clean status.
            headline_label = "Assessment Incomplete"

    story.extend(
        [
            _p(rl, headline_label, styles["h2"]),
            _p(rl, summary.get("headline_statement") or "", styles["body"]),
            *_kv(rl, styles, "Organization", identity.get("organization_name")),
            *_kv(rl, styles, "Report generated", generated_at),
            *_kv(rl, styles, "Generation", _generation_label(envelope, generation_origin)),
            *_kv(rl, styles, "Report version", f"v{envelope.get('report_version')}"),
            *_kv(rl, styles, "Report id", envelope.get("report_id")),
            *_kv(rl, styles, "Operation status", identity.get("operation_status")),
            *_kv(rl, styles, "Completeness", identity.get("assessment_completeness")),
            *_kv(rl, styles, "Snapshot digest", envelope.get("snapshot_digest")),
            *_kv(rl, styles, "PDF renderer", f"Scout PDF renderer {PDF_RENDERER_VERSION}"),
            _p(rl, "1. Executive Summary", styles["h1"]),
        ]
    )
    if identity.get("assessment_completeness") == "incomplete":
        story.append(
            _p(
                rl,
                "Assessment Incomplete — this operation did not run to completion and "
                "the results below cover only part of the authorized scope.",
                styles["body"],
            )
        )
    story.extend(
        [
            _p(rl, summary.get("headline_statement") or "", styles["body"]),
            *_kv(rl, styles, "Findings total", summary.get("findings_total")),
            *_kv(rl, styles, "Open findings", summary.get("findings_open")),
            *_kv(rl, styles, "Resolved findings", summary.get("findings_resolved")),
            *_kv(
                rl,
                styles,
                "Coverage limitations",
                summary.get("coverage_limitation_count"),
            ),
            _p(rl, "2. Assessment Scope", styles["h1"]),
        ]
    )
    if identity.get("assessment_completeness") == "incomplete":
        story.append(
            _p(
                rl,
                f"Operation status {identity.get('operation_status')} — Assessment Incomplete.",
                styles["body"],
            )
        )
    story.extend(
        [
            _p(rl, scope.get("explanation") or "", styles["body"]),
            *_kv(rl, styles, "Scope root", scope.get("scope_root")),
            *_kv(
                rl,
                styles,
                "Subdomains",
                "In scope" if scope.get("include_subdomains") else "Root only",
            ),
            *_kv(
                rl,
                styles,
                "Target authorization at launch",
                identity.get("target_authorization_status"),
            ),
            *_kv(rl, styles, "Testing profile", identity.get("testing_profile")),
            *_kv(rl, styles, "Operation source", identity.get("operation_source")),
            *_kv(
                rl,
                styles,
                "Exclusions",
                ", ".join(str(item) for item in _as_list(scope.get("exclusions")))
                or "None configured.",
            ),
            _p(rl, "3. What Scout Tested", styles["h1"]),
            _p(rl, frozen.get("explanation") or "", styles["body"]),
            _p(rl, frozen.get("headline") or "", styles["body"]),
        ]
    )
    for item in _as_list(methodology.get("supported_classes")):
        if isinstance(item, dict):
            story.append(
                _p(
                    rl,
                    f"{item.get('title')} — applies to {item.get('applies_to')}",
                    styles["small"],
                )
            )

    story.extend(
        [
            _p(rl, "4. Coverage & Limitations", styles["h1"]),
            _p(rl, limitations.get("explanation") or "", styles["body"]),
        ]
    )
    coverage_limitations = _as_list(limitations.get("coverage_limitations"))
    if coverage_limitations:
        for item in coverage_limitations:
            if isinstance(item, dict):
                story.append(
                    _p(
                        rl,
                        f"{item.get('reason_code')} · {item.get('count')} — {item.get('explanation')}",
                        styles["small"],
                    )
                )
    else:
        story.append(
            _p(
                rl,
                "No concrete coverage limitation was recorded for this operation.",
                styles["body"],
            )
        )
    story.extend(
        [
            _p(rl, "Frozen operation coverage", styles["h2"]),
            _p(
                rl,
                f"Frozen at {frozen.get('frozen_at')}. Operation status at freeze: "
                f"{frozen.get('operation_status_at_freeze')}. Capability manifest v"
                f"{frozen.get('capability_manifest_version')}.",
                styles["body"],
            ),
            _p(rl, "Follow-up frozen for this report", styles["h2"]),
            _p(rl, follow_up.get("explanation") or "", styles["body"]),
        ]
    )
    for key, value in _as_dict(follow_up.get("counts")).items():
        story.extend(_kv(rl, styles, str(key).replace("_", " "), value))
    story.append(_p(rl, "Test classes Scout does not perform", styles["h2"]))
    for item in _as_list(methodology.get("unsupported_classes")):
        if isinstance(item, dict):
            story.append(
                _p(
                    rl,
                    f"{item.get('title')} — {item.get('explanation')}",
                    styles["small"],
                )
            )

    story.append(_p(rl, "5. Findings", styles["h1"]))
    if not findings:
        story.append(
            _p(
                rl,
                "Scout promoted no supported findings from this operation.",
                styles["body"],
            )
        )
    for finding in findings:
        story.append(
            _p(
                rl,
                f"{finding.get('severity')} · "
                f"{'Open' if finding.get('is_open') else 'Resolved'} · "
                f"{finding.get('status')} · {finding.get('observation_class')}",
                styles["small"],
            )
        )
        story.append(_p(rl, finding.get("title") or "", styles["finding_title"]))
        story.append(_p(rl, finding.get("summary") or "", styles["body"]))
        asset = _as_dict(finding.get("affected_asset"))
        story.extend(
            _kv(
                rl,
                styles,
                "Affected asset",
                asset.get("url") or asset.get("hostname") or "—",
            )
        )
        validation = _as_dict(finding.get("validation"))
        story.extend(
            _kv(
                rl,
                styles,
                "Validation",
                f"{validation.get('status') or '—'} · {validation.get('method') or '—'}",
            )
        )
        story.append(_p(rl, "Business impact", styles["h2"]))
        story.append(_p(rl, finding.get("business_impact") or "", styles["body"]))
        story.append(_p(rl, "Remediation", styles["h2"]))
        story.append(_p(rl, finding.get("remediation_guidance") or "", styles["body"]))
        remediation_record = _as_dict(finding.get("remediation_record"))
        if remediation_record.get("recorded"):
            revision_count = int(remediation_record.get("revision_count") or 0)
            revision_label = "record" if revision_count == 1 else "records"
            story.append(_p(rl, "Customer-recorded remediation", styles["h2"]))
            story.append(
                _p(
                    rl,
                    f"{revision_count} {revision_label}; "
                    f"latest recorded "
                    f"{remediation_record.get('latest_recorded_at') or '—'}.",
                    styles["body"],
                )
            )
            story.append(
                _p(
                    rl,
                    "This records customer-described work and is not verification. "
                    "Only a passing retest confirms the condition is no longer present.",
                    styles["small"],
                )
            )
        else:
            story.append(
                _p(
                    rl,
                    "No customer-recorded remediation existed when this report was generated.",
                    styles["small"],
                )
            )
        latest = finding.get("latest_retest")
        if isinstance(latest, dict):
            story.append(_p(rl, "Latest retest at report generation", styles["h2"]))
            story.append(
                _p(
                    rl,
                    f"{latest.get('status')} · {latest.get('method')} · "
                    f"{latest.get('completed_at')}",
                    styles["body"],
                )
            )
            story.append(_p(rl, latest.get("summary") or "", styles["body"]))
        else:
            story.append(
                _p(
                    rl,
                    "No completed retest existed when this report was generated.",
                    styles["small"],
                )
            )
        story.append(_p(rl, "Evidence Scout observed", styles["h2"]))
        evidence_lines = _join_evidence(_as_dict(finding.get("evidence")))
        if evidence_lines:
            for line in evidence_lines:
                story.append(_p(rl, line, styles["small"]))
        else:
            story.append(
                _p(
                    rl,
                    "No customer-safe structured evidence fields were recorded for this finding.",
                    styles["small"],
                )
            )

    story.extend(
        [
            _p(rl, not_promoted.get("explanation") or "", styles["body"]),
            *_kv(rl, styles, "Candidates generated", not_promoted.get("candidates_generated")),
            *_kv(
                rl,
                styles,
                "Validations conclusive",
                not_promoted.get("validations_conclusive"),
            ),
            *_kv(
                rl,
                styles,
                "Validations inconclusive",
                not_promoted.get("validations_inconclusive"),
            ),
            _p(rl, "6. Remediation Status", styles["h1"]),
        ]
    )
    if findings:
        rows = [
            [
                _p(rl, "Finding", styles["label"]),
                _p(rl, "Severity", styles["label"]),
                _p(rl, "State at generation", styles["label"]),
                _p(rl, "Latest retest", styles["label"]),
            ]
        ]
        for finding in findings:
            latest = finding.get("latest_retest")
            retest_status = (
                latest.get("status") if isinstance(latest, dict) else "none"
            )
            rows.append(
                [
                    _p(rl, finding.get("title") or "", styles["small"]),
                    _p(rl, finding.get("severity") or "", styles["small"]),
                    _p(rl, finding.get("status") or "", styles["small"]),
                    _p(rl, retest_status, styles["small"]),
                ]
            )
        table = rl["Table"](rows, colWidths=["*", 70, 90, 80])
        table.setStyle(
            rl["TableStyle"](
                [
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 2),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                    ("TOPPADDING", (0, 0), (-1, -1), 3),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                    ("LINEBELOW", (0, 0), (-1, 0), 0.5, rl["colors"].HexColor("#d4d4d8")),
                ]
            )
        )
        story.append(table)
    else:
        story.append(
            _p(
                rl,
                "No findings were promoted, so there is no remediation state to report.",
                styles["body"],
            )
        )

    story.append(_p(rl, "7. Changes Since Previous Assessment", styles["h1"]))
    if change.get("available"):
        story.extend(
            [
                *_kv(rl, styles, "Comparability", change.get("comparability")),
                *_kv(rl, styles, "Baseline operation", change.get("baseline_operation_id")),
                _p(rl, change.get("diff_headline") or "", styles["body"]),
            ]
        )
        if change.get("security_signal_comparison_suppressed"):
            story.append(
                _p(
                    rl,
                    "Security-signal comparison was suppressed: "
                    f"{change.get('security_signal_suppression_reason') or 'not stated'}.",
                    styles["body"],
                )
            )
        for title, key in (
            ("Security regressions", "security_regressions"),
            ("Coverage degradations", "coverage_degradations"),
            ("Resolved conditions reappeared", "resolved_conditions_reappeared"),
        ):
            items = _as_list(change.get(key))
            if not items:
                continue
            story.append(_p(rl, title, styles["h2"]))
            for item in items:
                if isinstance(item, dict):
                    story.append(
                        _p(
                            rl,
                            f"{item.get('change_type') or ''} · {item.get('match_key') or ''} "
                            f"— {item.get('explanation') or ''}",
                            styles["small"],
                        )
                    )
    else:
        story.append(_p(rl, change.get("explanation") or "", styles["body"]))

    story.extend(
        [
            _p(rl, "8. Methodology & Safety Controls", styles["h1"]),
            _p(
                rl,
                f"Testing profile {methodology.get('testing_profile')}, capability manifest v"
                f"{methodology.get('capability_manifest_version')}.",
                styles["body"],
            ),
        ]
    )
    for control in _as_list(methodology.get("safety_controls")):
        story.append(_p(rl, control, styles["small"]))
    story.append(
        _p(
            rl,
            f"This PDF is derived only from the immutable snapshot recorded at generation. "
            f"Report identity {envelope.get('report_id')}, schema v"
            f"{content.get('report_schema_version')}, renderer {PDF_RENDERER_VERSION}.",
            styles["small"],
        )
    )
    return story


def _page_footer(rl: dict[str, Any], snapshot: dict[str, Any]):
    envelope = _as_dict(snapshot.get("envelope"))
    identity = _as_dict(_as_dict(snapshot.get("content")).get("identity"))
    styles = _styles(rl)

    def _draw(canvas, doc) -> None:
        canvas.saveState()
        footer = (
            f"{identity.get('target_domain') or ''}  ·  "
            f"v{envelope.get('report_version')}  ·  "
            f"Page {doc.page}  ·  Scout PDF renderer {PDF_RENDERER_VERSION}"
        )
        paragraph = rl["Paragraph"](plain_pdf_text(footer), styles["footer"])
        paragraph.wrap(doc.width, 24)
        paragraph.drawOn(canvas, doc.leftMargin, 36)
        canvas.restoreState()

    return _draw


def render_pdf_bytes(
    snapshot: dict[str, Any], *, generation_origin: str | None = None
) -> bytes:
    rl = _load_reportlab()
    _ensure_fonts(rl)
    _assert_fonts_cover(rl, _collect_visible_strings(snapshot))

    buffer = BytesIO()
    identity = _as_dict(_as_dict(snapshot.get("content")).get("identity"))
    domain = str(identity.get("target_domain") or "target")
    doc = rl["SimpleDocTemplate"](
        buffer,
        pagesize=rl["letter"],
        leftMargin=rl["inch"] * 0.75,
        rightMargin=rl["inch"] * 0.75,
        topMargin=rl["inch"] * 0.7,
        bottomMargin=rl["inch"] * 0.7,
        title=f"Scout Assessment Report — {domain}",
        subject="Security assessment report",
        creator="Scout",
        producer="Scout",
        author="",
    )
    footer = _page_footer(rl, snapshot)
    doc.build(
        _build_story(rl, snapshot, generation_origin=generation_origin),
        onFirstPage=footer,
        onLaterPages=footer,
    )
    data = buffer.getvalue()
    if not data.startswith(_PDF_MAGIC):
        raise RuntimeError("PDF renderer produced invalid output")
    return data


def export_assessment_report_pdf(report: AssessmentReport) -> tuple[bytes, str]:
    """Validate, render entirely in memory, then return completed PDF bytes."""
    snapshot = validate_snapshot_for_export(report)
    try:
        pdf_bytes = render_pdf_bytes(
            snapshot, generation_origin=getattr(report, "generation_origin", None)
        )
    except PdfRendererUnavailable:
        raise
    except PdfSnapshotError:
        raise
    except Exception as exc:
        raise RuntimeError("PDF rendering failed") from exc

    identity = _as_dict(_as_dict(snapshot.get("content")).get("identity"))
    filename = sanitize_pdf_filename(
        str(identity.get("target_domain") or report.target_domain),
        int(report.report_version),
    )
    return pdf_bytes, filename


def pdf_http_error(exc: PdfSnapshotError) -> HTTPException:
    return HTTPException(status_code=exc.status_code, detail=exc.detail)
