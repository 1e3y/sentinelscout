"""Score Scout artifacts against explicit ground truth. No blended accuracy."""

from __future__ import annotations

from typing import Any

from app.benchmark.ground_truth import GroundTruth


def _ratio(num: int, den: int) -> float | None:
    if den <= 0:
        return None
    return round(num / den, 4)


def score(
    *,
    truth: GroundTruth,
    mode: str,
    found_hosts: set[str],
    emitted: set[tuple[str, str]],
    supported: set[tuple[str, str]],
    retest_actual: dict[str, str],
    duration_ms: int,
    warnings: list[str],
    live_probed_hosts: list[str] | None = None,
    subfinder_hosts: list[str] | None = None,
    used_httpx_binary: bool | None = None,
    git_sha: str | None = None,
    operation_id: str | None = None,
) -> dict[str, Any]:
    expected_hosts = set(truth.expected_reachable_hosts)
    expected_present = {
        (row.hostname, row.candidate_type)
        for row in truth.candidates
        if row.expected == "present"
    }
    desirable = {
        (row.hostname, row.candidate_type) for row in truth.candidates if row.desirable
    }
    expected_absent = set(truth.not_candidates)
    expected_supported = {
        (row.hostname, row.candidate_type)
        for row in truth.candidates
        if row.expected == "present" and row.validation == "supported"
    }

    true_hosts = expected_hosts & found_hosts
    extra_hosts = sorted(found_hosts - expected_hosts)
    missing_hosts = sorted(expected_hosts - found_hosts)

    matched = emitted & expected_present
    unexpected = sorted(
        f"{host}/{ctype}"
        for host, ctype in sorted(emitted - expected_present)
    )
    false_positives = sorted(
        f"{host}/{ctype}" for host, ctype in sorted(emitted & expected_absent)
    )
    misses = sorted(
        f"{host}/{ctype}" for host, ctype in sorted(expected_present - emitted)
    )
    overlap_report = []
    for hostname, types in truth.overlaps:
        present = [ctype for ctype in types if (hostname, ctype) in emitted]
        overlap_report.append(
            {
                "hostname": hostname,
                "expected_types": list(types),
                "emitted_types": present,
                "complete": set(types).issubset({t for h, t in emitted if h == hostname}),
            }
        )

    pipeline_precision = _ratio(len(true_hosts), len(found_hosts))
    pipeline_recall = _ratio(len(true_hosts), len(expected_hosts))

    result: dict[str, Any] = {
        "schema_version": 1,
        "fixture_id": truth.fixture_id,
        "mode": mode,
        "git_sha": git_sha,
        "operation_id": operation_id,
        "duration_ms": duration_ms,
        "pipeline_assets": {
            "note": (
                "Offline/local seeded-host pipeline: whether Scout scoped, probed, "
                "persisted, and processed hosts it was handed. Not internet discovery recall."
            ),
            "expected": len(expected_hosts),
            "found": len(found_hosts),
            "pipeline_asset_precision": pipeline_precision,
            "pipeline_asset_recall": pipeline_recall,
            "missing": missing_hosts,
            "extra": extra_hosts,
        },
        "live_discovery": None,
        "candidates": {
            "expected_present": len(expected_present),
            "emitted": len(emitted),
            "recall": _ratio(len(matched), len(expected_present)),
            "precision_rule_faithful": _ratio(len(matched), len(emitted)),
            "precision_desirable": _ratio(len(emitted & desirable), len(emitted)),
            "unexpected": unexpected,
            "false_positives_vs_not_candidates": false_positives,
            "misses": misses,
        },
        "overlaps": overlap_report,
        "known_misses": [
            {
                "id": row.get("id"),
                "hostname": row.get("hostname"),
                "class": row.get("class"),
                "reason": row.get("reason"),
                "count_in_recall": bool(row.get("count_in_recall", False)),
            }
            for row in truth.known_misses
        ],
        "validation": {
            "expected_supported": len(expected_supported),
            "supported": len(supported & expected_supported),
            "support_rate": _ratio(
                len(supported & expected_supported), len(expected_supported)
            ),
            "disagreements": sorted(
                f"{host}/{ctype}"
                for host, ctype in sorted(expected_supported - supported)
            ),
        },
        "retest": None,
        "warnings": list(warnings),
    }

    if mode == "local_live":
        probed = {h.lower().rstrip(".") for h in (live_probed_hosts or [])}
        live_hit = expected_hosts & probed
        result["live_discovery"] = {
            "note": (
                "Measures discovery-tool wiring against loopback-mapped fixture hosts, "
                "not internet-wide discovery quality. bench.example is not in public DNS."
            ),
            "used_httpx_binary": bool(used_httpx_binary),
            "live_discovery_asset_recall": (
                _ratio(len(live_hit), len(expected_hosts)) if used_httpx_binary else None
            ),
            "probed_expected": sorted(live_hit),
            "subfinder_public_hosts": list(subfinder_hosts or []),
            "subfinder_public_host_count": len(subfinder_hosts or []),
        }

    if truth.retests:
        rows = []
        all_ok = True
        for spec in truth.retests:
            actual = retest_actual.get(spec.candidate_id)
            ok = actual == spec.expected_retest_status
            all_ok = all_ok and ok
            rows.append(
                {
                    "candidate_id": spec.candidate_id,
                    "expected": spec.expected_retest_status,
                    "actual": actual,
                    "correct": ok,
                }
            )
        result["retest"] = {"all_correct": all_ok, "cases": rows}

    return result
