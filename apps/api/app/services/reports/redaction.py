"""Report evidence minimization.

Two layers, applied only at untrusted source boundaries:

A. Positive allowlists copy named fields out of semi-structured source JSON
   (candidate / validation / retest / finding evidence). Unknown keys are
   dropped, never passed through because the name looks harmless.
B. ``guard_evidence_subtree`` is a structural fail-closed net run on the
   copied evidence subtrees only. The report's own typed schema is not
   evidence and is never scanned, so safe canonical fields such as
   ``target_authorization_status`` cannot be falsely rejected.
"""

from __future__ import annotations

import re
from typing import Any

from app.services.http_evidence import HEADER_PRESENCE_ONLY, HEADER_VALUE_ALLOWLIST
from app.services.validation_engine.methods import COMMON_SECURITY_HEADERS

MAX_EVIDENCE_STRING_CHARS = 300
MAX_EVIDENCE_LIST_ITEMS = 20

# Header names Scout is already willing to persist. Values are never copied
# into a report; only the name and the present/absent fact are.
SAFE_SECURITY_HEADER_NAMES = frozenset(
    {name.lower() for name in HEADER_VALUE_ALLOWLIST}
    | {name.lower() for name in HEADER_PRESENCE_ONLY}
    | {name.lower() for name in COMMON_SECURITY_HEADERS}
)

# Candidate-derived facts (SecurityCandidate.evidence / finding candidate_evidence).
CANDIDATE_EVIDENCE_ALLOWLIST = frozenset({"reasons", "signals", "why"})

# Validation-derived facts. Deliberately excludes `title` (arbitrary page text),
# `observed_header_names` / `expected_missing` / `present_headers` (arbitrary
# header-name lists) and every internal row identifier.
VALIDATION_EVIDENCE_ALLOWLIST = frozenset(
    {
        "method",
        "reachable",
        "status_code",
        "final_url",
        "hostname",
        "headers_observed",
        "redirected",
        "staging_markers",
        "admin_signals",
        "auth_signals",
        "sensitive_markers",
    }
)

# Retest-derived facts, from the already-filtered `recheck` subset.
RETEST_RECHECK_ALLOWLIST = frozenset(
    {
        "reachable",
        "status_code",
        "final_url",
        "hostname",
        "staging_markers",
        "admin_signals",
        "auth_signals",
        "sensitive_markers",
    }
)

# Exact normalized key names that must never appear in evidence.
FORBIDDEN_EVIDENCE_KEYS = frozenset(
    {
        "authorization",
        "proxy_authorization",
        "www_authenticate",
        "proxy_authenticate",
        "cookie",
        "set_cookie",
        "password",
        "passwd",
        "secret",
        "credential",
        "credentials",
        "api_key",
        "apikey",
        "access_token",
        "refresh_token",
        "bearer",
        "session",
        "session_id",
        "response_body",
        "request_body",
        "raw_body",
        "raw_headers",
        "token",
        "body",
    }
)

# Conservative substring patterns for the token/secret family only. These are
# intentionally narrow so that safe compound names (authorization_status,
# headers_captured, header_evidence_unavailable, ...) never match.
FORBIDDEN_EVIDENCE_KEY_PATTERNS = (
    "_token",
    "token_",
    "_secret",
    "secret_",
    "password",
    "passwd",
    "api_key",
    "apikey",
    "credential",
    "private_key",
)

_JWT_RE = re.compile(r"^ey[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.")
_BEARER_RE = re.compile(r"^\s*bearer\s+\S+", re.IGNORECASE)
_PEM_MARKER = "-----BEGIN"


class ReportRedactionError(RuntimeError):
    """Raised when evidence reaching a report still contains forbidden content."""


def normalize_key(key: Any) -> str:
    return str(key).strip().lower().replace("-", "_").replace(" ", "_")


def is_forbidden_evidence_key(key: Any) -> bool:
    normalized = normalize_key(key)
    if normalized in FORBIDDEN_EVIDENCE_KEYS:
        return True
    return any(pattern in normalized for pattern in FORBIDDEN_EVIDENCE_KEY_PATTERNS)


def is_forbidden_evidence_value(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    if _PEM_MARKER in value:
        return True
    if _BEARER_RE.match(value):
        return True
    return bool(_JWT_RE.match(value.strip()))


def guard_evidence_subtree(payload: Any, *, path: str = "evidence") -> Any:
    """Fail closed if a forbidden key or credential-shaped value survived layer A."""
    if isinstance(payload, dict):
        for key, value in payload.items():
            if is_forbidden_evidence_key(key):
                raise ReportRedactionError(
                    f"forbidden evidence key at {path}: {normalize_key(key)}"
                )
            guard_evidence_subtree(value, path=f"{path}.{normalize_key(key)}")
        return payload
    if isinstance(payload, (list, tuple)):
        for index, item in enumerate(payload):
            guard_evidence_subtree(item, path=f"{path}[{index}]")
        return payload
    if is_forbidden_evidence_value(payload):
        raise ReportRedactionError(f"forbidden evidence value shape at {path}")
    return payload


def _clean_scalar(value: Any) -> Any:
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, (int, float)):
        return value
    return str(value)[:MAX_EVIDENCE_STRING_CHARS]


def _clean_string_list(value: Any) -> list[str]:
    if not isinstance(value, (list, tuple)):
        return []
    items = [
        str(item)[:MAX_EVIDENCE_STRING_CHARS]
        for item in value
        if isinstance(item, (str, int, float, bool))
    ]
    return sorted(dict.fromkeys(items))[:MAX_EVIDENCE_LIST_ITEMS]


def _copy_allowlisted(source: Any, allowlist: frozenset[str]) -> dict[str, Any]:
    if not isinstance(source, dict):
        return {}
    clean: dict[str, Any] = {}
    for key in sorted(allowlist):
        if key not in source:
            continue
        value = source[key]
        if is_forbidden_evidence_key(key):
            continue
        if isinstance(value, (list, tuple)):
            cleaned = _clean_string_list(value)
            if cleaned:
                clean[key] = cleaned
            continue
        if isinstance(value, dict):
            continue
        cleaned_scalar = _clean_scalar(value)
        if is_forbidden_evidence_value(cleaned_scalar):
            continue
        clean[key] = cleaned_scalar
    return clean


def missing_security_headers(source: Any) -> list[dict[str, Any]]:
    """Typed, name-only security-header facts.

    ``observed_header`` and ``still_missing`` hold header *names* drawn from
    Scout's own security-header set. No header value is ever copied, and names
    outside the persisted-safe allowlist are dropped.
    """
    if not isinstance(source, dict):
        return []
    names: list[str] = []
    raw_missing = source.get("still_missing")
    if isinstance(raw_missing, (list, tuple)):
        names.extend(str(item) for item in raw_missing)
    single = source.get("observed_header")
    if isinstance(single, str):
        names.append(single)

    entries: dict[str, dict[str, Any]] = {}
    for raw_name in names:
        name = normalize_key(raw_name).replace("_", "-")
        if name not in SAFE_SECURITY_HEADER_NAMES:
            continue
        entries[name] = {"header_name": name, "observed": False}
    return [entries[name] for name in sorted(entries)]


def finding_report_evidence(finding_evidence: Any) -> dict[str, Any]:
    """Build the customer-facing evidence block for one finding."""
    source = finding_evidence if isinstance(finding_evidence, dict) else {}
    validation_block = source.get("validation")
    validation_inner = (
        validation_block.get("evidence") if isinstance(validation_block, dict) else None
    )

    evidence: dict[str, Any] = {}

    observed = _copy_allowlisted(validation_inner, VALIDATION_EVIDENCE_ALLOWLIST)
    if observed:
        evidence["observed_facts"] = observed

    headers = missing_security_headers(validation_inner)
    if headers:
        evidence["missing_security_headers"] = headers

    candidate = _copy_allowlisted(
        source.get("candidate_evidence"), CANDIDATE_EVIDENCE_ALLOWLIST
    )
    if candidate:
        evidence["deterministic_signals"] = candidate

    return guard_evidence_subtree(evidence, path="finding.evidence")


def retest_report_evidence(retest_evidence: Any) -> dict[str, Any]:
    source = retest_evidence if isinstance(retest_evidence, dict) else {}
    recheck = _copy_allowlisted(source.get("recheck"), RETEST_RECHECK_ALLOWLIST)
    headers = missing_security_headers(source.get("recheck"))
    evidence: dict[str, Any] = {}
    if recheck:
        evidence["observed_facts"] = recheck
    if headers:
        evidence["missing_security_headers"] = headers
    return guard_evidence_subtree(evidence, path="retest.evidence")
