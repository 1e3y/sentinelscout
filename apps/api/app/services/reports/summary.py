"""Deterministic, rule-based report summary. No numeric score, no security claims."""

from __future__ import annotations

from typing import Any

from app.services.coverage import (
    REASON_DISCOVERY_TRUNCATED,
    REASON_HEADER_EVIDENCE_UNAVAILABLE,
    REASON_HOST_NOT_REACHABLE,
    REASON_OBSERVATION_INCOMPLETE,
    REASON_OPERATION_FAILED,
    REASON_OPERATION_STOPPED,
    REASON_PROBE_FAILED,
    REASON_PROBE_NO_RESULT,
    REASON_PROBE_TIMEOUT,
    REASON_REDIRECT_HEADER_UNUSABLE,
    REASON_VALIDATION_FAILED,
    REASON_VALIDATION_INCONCLUSIVE,
    REASON_VALIDATION_NOT_ATTEMPTED,
    explanation_for,
)

SEVERITY_ORDER: dict[str, int] = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
ACTION_REQUIRED_MIN_RANK = SEVERITY_ORDER["medium"]

OPEN_FINDING_STATUSES = frozenset({"open", "in_progress", "ready_for_retest"})
RESOLVED_FINDING_STATUSES = frozenset({"resolved"})

REASON_HTTP_OBSERVATION_NOT_OBTAINED = "http_observation_not_obtained"

_LOCAL_EXPLANATIONS = {
    REASON_HTTP_OBSERVATION_NOT_OBTAINED: (
        "In-scope hostnames produced no usable HTTP observation, so Scout has no "
        "response evidence for them."
    ),
}

# Concrete, per-operation coverage gaps only. Scout's generic unsupported
# capability classes and methodology disclaimers are prominently reported but
# never counted here, otherwise no assessment could ever reach
# "No Open Supported Findings".
COVERAGE_LIMITATION_REASON_CODES = frozenset(
    {
        REASON_HTTP_OBSERVATION_NOT_OBTAINED,
        REASON_PROBE_NO_RESULT,
        REASON_HOST_NOT_REACHABLE,
        REASON_PROBE_FAILED,
        REASON_PROBE_TIMEOUT,
        REASON_OPERATION_STOPPED,
        REASON_OPERATION_FAILED,
        REASON_OBSERVATION_INCOMPLETE,
        REASON_DISCOVERY_TRUNCATED,
        REASON_HEADER_EVIDENCE_UNAVAILABLE,
        REASON_REDIRECT_HEADER_UNUSABLE,
        REASON_VALIDATION_NOT_ATTEMPTED,
        REASON_VALIDATION_INCONCLUSIVE,
        REASON_VALIDATION_FAILED,
    }
)

HEADLINE_ASSESSMENT_INCOMPLETE = "assessment_incomplete"
HEADLINE_ACTION_REQUIRED = "action_required"
HEADLINE_ATTENTION_RECOMMENDED = "attention_recommended"
HEADLINE_NO_OPEN_SUPPORTED_FINDINGS = "no_open_supported_findings"

HEADLINE_LABELS = {
    HEADLINE_ASSESSMENT_INCOMPLETE: "Assessment Incomplete",
    HEADLINE_ACTION_REQUIRED: "Action Required",
    HEADLINE_ATTENTION_RECOMMENDED: "Attention Recommended",
    HEADLINE_NO_OPEN_SUPPORTED_FINDINGS: "No Open Supported Findings",
}

NO_OPEN_FINDINGS_DISCLAIMER = (
    "Within the tested scope and the evidence available to Scout, no open supported "
    "findings were observed. This is not a statement that the target is free of "
    "security weaknesses; see Coverage & Limitations for what Scout did not test."
)

INCOMPLETE_STATEMENT = (
    "This operation did not run to completion. Scout's coverage of the authorized "
    "scope is partial and the results below must not be read as a full assessment "
    "of the tested scope."
)


def severity_rank(severity: str | None) -> int:
    return SEVERITY_ORDER.get(str(severity or "").lower(), 0)


def _entry(reason_code: str, count: int, source: str) -> dict[str, Any]:
    return {
        "reason_code": reason_code,
        "count": int(count),
        "explanation": _LOCAL_EXPLANATIONS.get(reason_code) or explanation_for(reason_code),
        "source": source,
    }


def _int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def compute_coverage_limitations(
    *,
    surface: dict[str, Any],
    http_evidence: dict[str, Any],
    scope_boundaries: dict[str, Any],
    follow_up: dict[str, Any],
) -> list[dict[str, Any]]:
    """Concrete operation coverage limitations, deduped by reason code.

    Derived only from frozen M17 coverage facts plus the report-frozen follow-up
    gaps. Capability manifest `unsupported` entries never contribute.
    """
    entries: list[dict[str, Any]] = []

    not_obtained = _int(surface.get("http_observation_not_obtained"))
    if not_obtained:
        entries.append(
            _entry(REASON_HTTP_OBSERVATION_NOT_OBTAINED, not_obtained, "surface")
        )
    incomplete = _int(surface.get("incomplete"))
    if incomplete:
        entries.append(_entry(REASON_OBSERVATION_INCOMPLETE, incomplete, "surface"))

    header_unavailable = _int(http_evidence.get("header_evidence_unavailable"))
    if header_unavailable:
        entries.append(
            _entry(REASON_HEADER_EVIDENCE_UNAVAILABLE, header_unavailable, "http_evidence")
        )
    redirect_unusable = _int(http_evidence.get("redirect_header_evidence_unusable"))
    if redirect_unusable:
        entries.append(
            _entry(REASON_REDIRECT_HEADER_UNUSABLE, redirect_unusable, "http_evidence")
        )

    for source_name, gaps in (
        ("scope_boundaries", scope_boundaries.get("gaps")),
        ("follow_up", follow_up.get("gaps")),
    ):
        if not isinstance(gaps, list):
            continue
        for gap in gaps:
            if not isinstance(gap, dict):
                continue
            reason_code = str(gap.get("reason_code") or "")
            count = _int(gap.get("count"))
            if reason_code in COVERAGE_LIMITATION_REASON_CODES and count > 0:
                entries.append(_entry(reason_code, count, source_name))

    deduped: dict[str, dict[str, Any]] = {}
    for entry in entries:
        current = deduped.get(entry["reason_code"])
        if current is None or entry["count"] > current["count"]:
            deduped[entry["reason_code"]] = entry
    return [deduped[key] for key in sorted(deduped)]


def classify_headline(
    *,
    assessment_completeness: str,
    open_findings: list[dict[str, Any]],
    coverage_limitation_count: int,
    regression_count: int,
) -> str:
    """Approved priority order. Incomplete outranks findings and severity."""
    if assessment_completeness == "incomplete":
        return HEADLINE_ASSESSMENT_INCOMPLETE
    if any(
        severity_rank(item.get("severity")) >= ACTION_REQUIRED_MIN_RANK
        for item in open_findings
    ):
        return HEADLINE_ACTION_REQUIRED
    if open_findings or coverage_limitation_count > 0 or regression_count > 0:
        return HEADLINE_ATTENTION_RECOMMENDED
    return HEADLINE_NO_OPEN_SUPPORTED_FINDINGS


def headline_statement(
    *,
    headline_status: str,
    open_count: int,
    elevated_count: int,
    coverage_limitation_count: int,
    regression_count: int,
) -> str:
    if headline_status == HEADLINE_ASSESSMENT_INCOMPLETE:
        return INCOMPLETE_STATEMENT
    if headline_status == HEADLINE_ACTION_REQUIRED:
        return (
            f"Scout observed {open_count} open supported finding(s) within the tested "
            f"scope, including {elevated_count} at medium severity or above."
        )
    if headline_status == HEADLINE_ATTENTION_RECOMMENDED:
        return (
            f"Scout observed {open_count} open supported finding(s), "
            f"{regression_count} change-based regression signal(s), and "
            f"{coverage_limitation_count} concrete coverage limitation(s) within the "
            "tested scope."
        )
    return NO_OPEN_FINDINGS_DISCLAIMER
