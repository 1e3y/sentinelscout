"""Load explicit ground-truth YAML for a fixture pack."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from app.benchmark.paths import fixtures_root


@dataclass(frozen=True)
class SiteSpec:
    hostname: str
    path: str
    html: str
    content_type: str = "text/html; charset=utf-8"
    response_headers: tuple[tuple[str, str], ...] = ()
    redirect_to: str | None = None
    capture_headers: bool = True


@dataclass(frozen=True)
class AssetSpec:
    hostname: str
    reachable: bool
    probe_outcome: str


@dataclass(frozen=True)
class CoverageExpectation:
    in_scope_discovered: int | None = None
    submitted_for_http_observation: int | None = None
    http_observation_obtained: int | None = None
    http_observation_not_obtained: int | None = None
    probe_no_result: int | None = None
    host_not_reachable: int | None = None
    headers_captured: int | None = None
    header_evidence_unavailable: int | None = None
    discarded_out_of_scope: int | None = None
    configured_exclusions: tuple[str, ...] = ()
    validations_inconclusive: int | None = None
    findings: int | None = None
    validation_force_redirect: tuple[str, ...] = ()


@dataclass(frozen=True)
class CandidateSpec:
    id: str
    hostname: str
    candidate_type: str
    expected: str
    desirable: bool
    validation: str | None


@dataclass(frozen=True)
class RetestSpec:
    candidate_id: str
    hostname: str
    candidate_type: str
    after: str
    expected_retest_status: str


@dataclass(frozen=True)
class GroundTruth:
    schema_version: int
    fixture_id: str
    root: str
    include_subdomains: bool
    exclusions: list[str]
    sites: tuple[SiteSpec, ...]
    assets: tuple[AssetSpec, ...]
    candidates: tuple[CandidateSpec, ...]
    not_candidates: tuple[tuple[str, str], ...]
    overlaps: tuple[tuple[str, tuple[str, ...]], ...]
    known_misses: tuple[dict[str, Any], ...]
    retests: tuple[RetestSpec, ...]
    raw: dict[str, Any] = field(repr=False)
    coverage: CoverageExpectation | None = None

    @property
    def hostnames(self) -> list[str]:
        from_sites = [site.hostname for site in self.sites]
        from_assets = [row.hostname for row in self.assets]
        return list(dict.fromkeys([*from_sites, *from_assets]))

    @property
    def expected_reachable_hosts(self) -> list[str]:
        return [row.hostname for row in self.assets if row.reachable]


def _opt_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    return int(value)


def ground_truth_path(fixture_id: str) -> Path:
    return fixtures_root() / fixture_id / "ground-truth.yaml"


def _header_map(raw: Any) -> dict[str, str]:
    if not isinstance(raw, dict):
        return {}
    return {str(key): str(value) for key, value in raw.items()}


def _parse_site(row: dict[str, Any], *, default_headers: dict[str, str]) -> SiteSpec:
    replace = bool(row.get("replace_headers") or row.get("skip_default_headers"))
    site_headers = _header_map(row.get("response_headers") or {})
    headers = dict(site_headers) if replace else {**default_headers, **site_headers}
    redirect = row.get("redirect_to")
    return SiteSpec(
        hostname=str(row["hostname"]).lower().rstrip("."),
        path=str(row.get("path") or "/"),
        html=str(row["html"]),
        content_type=str(row.get("content_type") or "text/html; charset=utf-8"),
        response_headers=tuple(headers.items()),
        redirect_to=str(redirect) if redirect else None,
        capture_headers=bool(row.get("capture_headers", True)),
    )


def load_ground_truth(fixture_id: str) -> GroundTruth:
    path = ground_truth_path(fixture_id)
    if not path.is_file():
        raise FileNotFoundError(f"Missing ground truth: {path}")
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise TypeError(f"Ground truth must be a mapping: {path}")
    scope = raw.get("scope") or {}
    default_headers = _header_map(raw.get("default_response_headers") or {})
    sites = tuple(
        _parse_site(row, default_headers=default_headers)
        for row in raw.get("sites") or []
    )
    assets = tuple(
        AssetSpec(
            hostname=str(row["hostname"]).lower().rstrip("."),
            reachable=bool(row.get("reachable", True)),
            probe_outcome=str(
                row.get("probe_outcome")
                or ("observed" if row.get("reachable", True) else "no_result")
            ),
        )
        for row in raw.get("assets") or []
    )
    candidates = tuple(
        CandidateSpec(
            id=str(row["id"]),
            hostname=str(row["hostname"]).lower().rstrip("."),
            candidate_type=str(row["candidate_type"]),
            expected=str(row.get("expected") or "present"),
            desirable=bool(row.get("desirable", False)),
            validation=str(row["validation"]) if row.get("validation") else None,
        )
        for row in raw.get("candidates") or []
    )
    not_candidates = tuple(
        (
            str(row["hostname"]).lower().rstrip("."),
            str(row["candidate_type"]),
        )
        for row in raw.get("not_candidates") or []
    )
    overlaps = tuple(
        (
            str(row["hostname"]).lower().rstrip("."),
            tuple(str(item) for item in (row.get("candidate_types") or [])),
        )
        for row in raw.get("overlaps") or []
    )
    retests = tuple(
        RetestSpec(
            candidate_id=str(row["candidate_id"]),
            hostname=str(row["hostname"]).lower().rstrip("."),
            candidate_type=str(row["candidate_type"]),
            after=str(row.get("after") or ""),
            expected_retest_status=str(row["expected_retest_status"]),
        )
        for row in raw.get("retest") or []
    )
    coverage_raw = raw.get("coverage") or None
    coverage = None
    if isinstance(coverage_raw, dict):
        coverage = CoverageExpectation(
            in_scope_discovered=_opt_int(coverage_raw.get("in_scope_discovered")),
            submitted_for_http_observation=_opt_int(
                coverage_raw.get("submitted_for_http_observation")
            ),
            http_observation_obtained=_opt_int(
                coverage_raw.get("http_observation_obtained")
            ),
            http_observation_not_obtained=_opt_int(
                coverage_raw.get("http_observation_not_obtained")
            ),
            probe_no_result=_opt_int(coverage_raw.get("probe_no_result")),
            host_not_reachable=_opt_int(coverage_raw.get("host_not_reachable")),
            headers_captured=_opt_int(coverage_raw.get("headers_captured")),
            header_evidence_unavailable=_opt_int(
                coverage_raw.get("header_evidence_unavailable")
            ),
            discarded_out_of_scope=_opt_int(coverage_raw.get("discarded_out_of_scope")),
            configured_exclusions=tuple(
                str(item).lower().rstrip(".")
                for item in (coverage_raw.get("configured_exclusions") or [])
            ),
            validations_inconclusive=_opt_int(
                coverage_raw.get("validations_inconclusive")
            ),
            findings=_opt_int(coverage_raw.get("findings")),
            validation_force_redirect=tuple(
                str(item).lower().rstrip(".")
                for item in (coverage_raw.get("validation_force_redirect") or [])
            ),
        )
    return GroundTruth(
        schema_version=int(raw.get("schema_version") or 1),
        fixture_id=str(raw["fixture_id"]),
        root=str(scope.get("root") or "bench.example").lower().rstrip("."),
        include_subdomains=bool(scope.get("include_subdomains", True)),
        exclusions=[str(item) for item in (scope.get("exclusions") or [])],
        sites=sites,
        assets=assets,
        candidates=candidates,
        not_candidates=not_candidates,
        overlaps=overlaps,
        known_misses=tuple(raw.get("known_misses") or []),
        retests=retests,
        coverage=coverage,
        raw=raw,
    )
