"""Report-only baseline comparison. Metric diffs do not fail CI."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.benchmark.paths import ALL_FIXTURES, DEFAULT_CI_FIXTURES, baselines_root, results_root
from app.benchmark.schema import validate_result

COMPARE_PATHS = (
    ("pipeline_assets", "pipeline_asset_precision"),
    ("pipeline_assets", "pipeline_asset_recall"),
    ("pipeline_assets", "expected"),
    ("pipeline_assets", "found"),
    ("pipeline_assets", "missing"),
    ("pipeline_assets", "extra"),
    ("candidates", "expected_present"),
    ("candidates", "emitted"),
    ("candidates", "recall"),
    ("candidates", "precision_rule_faithful"),
    ("candidates", "precision_desirable"),
    ("candidates", "unexpected"),
    ("candidates", "false_positives_vs_not_candidates"),
    ("candidates", "misses"),
    ("overlaps",),
    ("known_misses",),
    ("validation", "expected_supported"),
    ("validation", "supported"),
    ("validation", "support_rate"),
    ("validation", "disagreements"),
    ("retest",),
    ("coverage", "all_correct"),
    ("live_discovery", "live_discovery_asset_recall"),
    ("live_discovery", "used_httpx_binary"),
    ("live_discovery", "subfinder_public_host_count"),
)


def _load_json(path: Path) -> dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"result file is not an object: {path}")
    validate_result(raw)
    return raw


def _get(obj: Any, path: tuple[str, ...]) -> Any:
    current = obj
    for key in path:
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]
    return current


def _normalize(value: Any) -> Any:
    if isinstance(value, list):
        return sorted(value, key=lambda item: json.dumps(item, sort_keys=True, default=str))
    return value


def diff_results(baseline: dict[str, Any], current: dict[str, Any]) -> list[dict[str, Any]]:
    diffs: list[dict[str, Any]] = []
    for path in COMPARE_PATHS:
        left = _normalize(_get(baseline, path))
        right = _normalize(_get(current, path))
        if left != right:
            diffs.append(
                {
                    "path": ".".join(path),
                    "baseline": left,
                    "current": right,
                }
            )
    return diffs


def compare_file(current_path: Path, baseline_path: Path) -> dict[str, Any]:
    report: dict[str, Any] = {
        "policy": "report_only",
        "fails_ci": False,
        "current_path": str(current_path),
        "baseline_path": str(baseline_path),
        "status": "unchanged",
        "diffs": [],
        "notes": [],
    }
    if not current_path.is_file():
        report["status"] = "missing_current"
        report["notes"].append(f"current result missing: {current_path}")
        return report
    if not baseline_path.is_file():
        current = _load_json(current_path)
        report["fixture_id"] = current["fixture_id"]
        report["mode"] = current["mode"]
        report["status"] = "missing_baseline"
        report["notes"].append(f"baseline missing: {baseline_path}")
        return report

    current = _load_json(current_path)
    baseline = _load_json(baseline_path)
    report["fixture_id"] = current["fixture_id"]
    report["mode"] = current["mode"]
    diffs = diff_results(baseline, current)
    report["diffs"] = diffs
    report["status"] = "changed" if diffs else "unchanged"
    if diffs:
        report["notes"].append(
            "REPORT-ONLY: metric differences are printed and do not fail CI. "
            "Selected regressions become hard gates only after baselines are trusted."
        )
    return report


def compare_pack(
    *,
    results_dir: Path | None = None,
    baselines_dir: Path | None = None,
    fixture_ids: tuple[str, ...] | None = None,
    mode: str = "offline",
) -> dict[str, Any]:
    results_dir = results_dir or results_root()
    baselines_dir = baselines_dir or baselines_root()
    fixture_ids = fixture_ids or DEFAULT_CI_FIXTURES
    reports = []
    for fixture_id in fixture_ids:
        if fixture_id not in ALL_FIXTURES:
            raise ValueError(f"unknown fixture: {fixture_id}")
        name = f"{fixture_id}-{mode}.json"
        reports.append(compare_file(results_dir / name, baselines_dir / name))
    return {
        "policy": "report_only",
        "fails_ci": False,
        "mode": mode,
        "reports": reports,
        "changed_count": sum(1 for item in reports if item["status"] == "changed"),
        "note": (
            "REPORT-ONLY baseline comparison. CI fails on crash/schema/test failure, "
            "not because pipeline or candidate metrics differ from the committed baseline."
        ),
    }


def format_compare(pack: dict[str, Any]) -> str:
    lines = [
        "=== benchmark baseline compare (REPORT-ONLY) ===",
        pack["note"],
        f"changed_count={pack['changed_count']} fails_ci={pack['fails_ci']}",
    ]
    for report in pack["reports"]:
        label = report.get("fixture_id") or report["current_path"]
        lines.append(f"- {label} ({report.get('mode', '?')}): {report['status']}")
        for note in report.get("notes") or []:
            lines.append(f"    {note}")
        for diff in report.get("diffs") or []:
            lines.append(
                f"    {diff['path']}: baseline={diff['baseline']!r} current={diff['current']!r}"
            )
    return "\n".join(lines)
