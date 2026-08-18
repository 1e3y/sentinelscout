"""Stable benchmark result schema. Offline metrics are pipeline, not discovery."""

from __future__ import annotations

from typing import Any

SCHEMA_VERSION = 1

# Offline/local seeded-host runs must use these names. They measure whether Scout
# scoped, probed, persisted, and processed hosts it was handed — not internet discovery.
PIPELINE_ASSET_PRECISION = "pipeline_asset_precision"
PIPELINE_ASSET_RECALL = "pipeline_asset_recall"

# Only local_live may populate this. It measures discovery-tool wiring against
# loopback-mapped fixture hosts, not internet-wide discovery quality.
LIVE_DISCOVERY_ASSET_RECALL = "live_discovery_asset_recall"

FORBIDDEN_METRIC_KEYS = frozenset(
    {
        "scout_asset_recall",
        "scout_discovery_recall",
        "discovery_recall",
        "asset_recall",
        "accuracy",
        "percent_secure",
        "confidence",
    }
)

REQUIRED_TOP_LEVEL = (
    "schema_version",
    "fixture_id",
    "mode",
    "git_sha",
    "operation_id",
    "duration_ms",
    "pipeline_assets",
    "live_discovery",
    "candidates",
    "overlaps",
    "known_misses",
    "validation",
    "retest",
    "warnings",
)

REQUIRED_PIPELINE_ASSETS = (
    "note",
    "expected",
    "found",
    PIPELINE_ASSET_PRECISION,
    PIPELINE_ASSET_RECALL,
    "missing",
    "extra",
)

REQUIRED_CANDIDATES = (
    "expected_present",
    "emitted",
    "recall",
    "precision_rule_faithful",
    "precision_desirable",
    "unexpected",
    "false_positives_vs_not_candidates",
    "misses",
)


def _walk_keys(value: Any) -> list[str]:
    keys: list[str] = []
    if isinstance(value, dict):
        for key, inner in value.items():
            keys.append(str(key))
            keys.extend(_walk_keys(inner))
    elif isinstance(value, list):
        for item in value:
            keys.extend(_walk_keys(item))
    return keys


def validate_result(result: dict[str, Any]) -> None:
    if not isinstance(result, dict):
        raise ValueError("benchmark result must be an object")
    missing = [key for key in REQUIRED_TOP_LEVEL if key not in result]
    if missing:
        raise ValueError(f"benchmark result missing keys: {missing}")
    if int(result["schema_version"]) != SCHEMA_VERSION:
        raise ValueError(f"unsupported schema_version: {result['schema_version']}")
    if result["mode"] not in {"offline", "local_live"}:
        raise ValueError(f"unsupported mode: {result['mode']}")

    pipeline = result["pipeline_assets"]
    if not isinstance(pipeline, dict):
        raise ValueError("pipeline_assets must be an object")
    missing_pipeline = [key for key in REQUIRED_PIPELINE_ASSETS if key not in pipeline]
    if missing_pipeline:
        raise ValueError(f"pipeline_assets missing keys: {missing_pipeline}")

    candidates = result["candidates"]
    if not isinstance(candidates, dict):
        raise ValueError("candidates must be an object")
    missing_candidates = [key for key in REQUIRED_CANDIDATES if key not in candidates]
    if missing_candidates:
        raise ValueError(f"candidates missing keys: {missing_candidates}")

    forbidden = FORBIDDEN_METRIC_KEYS.intersection(_walk_keys(result))
    if forbidden:
        raise ValueError(f"forbidden metric names present: {sorted(forbidden)}")

    if result.get("coverage") is not None and not isinstance(result["coverage"], dict):
        raise ValueError("coverage must be an object when present")
    if result.get("diff") is not None and not isinstance(result["diff"], dict):
        raise ValueError("diff must be an object when present")

    if result["mode"] == "offline" and result.get("live_discovery") is not None:
        raise ValueError("offline results must not include live_discovery metrics")
    if result["mode"] == "local_live":
        live = result.get("live_discovery")
        if not isinstance(live, dict):
            raise ValueError("local_live results must include a live_discovery object")
        if LIVE_DISCOVERY_ASSET_RECALL not in live:
            raise ValueError("local_live live_discovery must include live_discovery_asset_recall")
