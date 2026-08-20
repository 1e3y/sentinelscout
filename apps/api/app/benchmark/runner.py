"""Run one fixture through Scout entry points. Does not claim unrelated jobs."""

from __future__ import annotations

import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.benchmark.discovery import (
    LiveLoopbackDiscoveryTools,
    SeededLoopbackDiscoveryTools,
    invoke_subfinder,
)
from app.benchmark.ground_truth import GroundTruth, load_ground_truth
from app.benchmark.http_loopback import FixtureHttpServer, LoopbackSafeHttpClient
from app.benchmark.paths import (
    ALL_FIXTURES,
    DEFAULT_CI_FIXTURES,
    baselines_root,
    repo_root,
    results_root,
)
from app.benchmark.schema import SCHEMA_VERSION, validate_result
from app.benchmark.scorer import score
from app.benchmark.world import seed_world
from app.models.alert import (
    Alert,
    AlertEpisode,
    AlertGenerationReceipt,
    NotificationOutbox,
)
from app.models.asset import Asset, DiscoveryObservation
from app.models.candidate import SecurityCandidate
from app.models.coverage import OperationCoverageSummary
from app.models.diff import OperationDiffSummary
from app.models.finding import Finding
from app.models.operation import Operation
from app.models.retest import RetestAttempt
from app.models.validation import ValidationAttempt
from app.services.audit import record_audit
from app.services.coverage import (
    coverage_payload_from_snapshot,
    freeze_operation_coverage,
)
from app.services.diff import diff_snapshots, freeze_operation_diff
from app.services.findings import mark_ready_for_retest, promote_candidate_to_finding
from app.services.findings.remediation import start_remediation
from app.services.operations import append_event, create_operation, queue_candidate_validation
from app.services.targets import update_scope
from app.services.retest_runtime import execute_retest_job, queue_finding_retest
from app.services.validation_runtime import execute_validation_job
from app.services.worker_runtime import execute_discovery_job


def git_sha() -> str | None:
    try:
        process = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_root(),
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if process.returncode != 0:
        return None
    sha = process.stdout.strip()
    return sha or None


def result_path(result: dict[str, Any], *, baseline: bool = False) -> Path:
    directory = baselines_root() if baseline else results_root()
    directory.mkdir(parents=True, exist_ok=True)
    return directory / f"{result['fixture_id']}-{result['mode']}.json"


def write_json(result: dict[str, Any], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _start_operation(db: Session, operation_id: UUID) -> Operation:
    operation = db.get(Operation, operation_id)
    if operation is None:
        raise RuntimeError("benchmark operation disappeared before start")
    if operation.status != "queued":
        raise RuntimeError(f"benchmark operation is {operation.status}, expected queued")
    now = datetime.now(timezone.utc)
    operation.status = "running"
    operation.started_at = now
    append_event(
        db,
        operation,
        event_type="operation.started",
        summary="Scout operation started.",
        metadata={"status": "running"},
    )
    record_audit(
        db,
        organization_id=operation.organization_id,
        actor_type="worker",
        actor_user_id=operation.created_by_user_id,
        action="operation.started",
        resource_type="operation",
        resource_id=operation.id,
        summary="Scout operation started by benchmark harness.",
        metadata={
            "operation_id": str(operation.id),
            "target_id": str(operation.target_id),
            "status": "running",
            "source": operation.source,
            "testing_profile": operation.testing_profile,
        },
    )
    db.commit()
    db.refresh(operation)
    return operation


def _pairs_for_operation(db: Session, operation_id: UUID) -> tuple[set[str], set[tuple[str, str]]]:
    http_obs = list(
        db.scalars(
            select(DiscoveryObservation).where(
                DiscoveryObservation.operation_id == operation_id,
                DiscoveryObservation.observation_type == "http_response_observed",
            )
        ).all()
    )
    found_hosts = {
        str((row.observation_metadata or {}).get("hostname") or "").lower().rstrip(".")
        for row in http_obs
    }
    found_hosts.discard("")
    candidates = list(
        db.scalars(
            select(SecurityCandidate).where(SecurityCandidate.operation_id == operation_id)
        ).all()
    )
    emitted: set[tuple[str, str]] = set()
    for candidate in candidates:
        host = str((candidate.evidence or {}).get("asset_hostname") or "").lower().rstrip(".")
        if not host:
            continue
        emitted.add((host, candidate.candidate_type))
    return found_hosts, emitted


def _supported_pairs(db: Session, operation_id: UUID) -> set[tuple[str, str]]:
    attempts = list(
        db.scalars(
            select(ValidationAttempt).where(
                ValidationAttempt.operation_id == operation_id,
                ValidationAttempt.status == "supported",
            )
        ).all()
    )
    supported: set[tuple[str, str]] = set()
    for attempt in attempts:
        candidate = db.get(SecurityCandidate, attempt.candidate_id)
        asset = db.get(Asset, attempt.asset_id)
        if candidate is None or asset is None:
            continue
        supported.add((asset.hostname.lower().rstrip("."), candidate.candidate_type))
    return supported


def _find_candidate(
    db: Session, operation_id: UUID, *, hostname: str, candidate_type: str
) -> SecurityCandidate | None:
    candidates = list(
        db.scalars(
            select(SecurityCandidate).where(SecurityCandidate.operation_id == operation_id)
        ).all()
    )
    for candidate in candidates:
        asset = db.get(Asset, candidate.asset_id)
        if asset is None:
            continue
        if (
            asset.hostname.lower().rstrip(".") == hostname
            and candidate.candidate_type == candidate_type
        ):
            return candidate
    return None


def _run_retests(
    db: Session,
    *,
    truth: GroundTruth,
    user_id: UUID,
    operation_id: UUID,
    http_client: LoopbackSafeHttpClient,
    server: FixtureHttpServer,
) -> dict[str, str]:
    actual: dict[str, str] = {}
    for spec in truth.retests:
        candidate = _find_candidate(
            db,
            operation_id,
            hostname=spec.hostname,
            candidate_type=spec.candidate_type,
        )
        if candidate is None:
            actual[spec.candidate_id] = "missing_candidate"
            continue
        finding = promote_candidate_to_finding(db, candidate_id=candidate.id, user_id=user_id)
        start_remediation(db, finding_id=finding.id, user_id=user_id)
        mark_ready_for_retest(db, finding_id=finding.id, user_id=user_id)
        if spec.after == "staging_down":
            http_client.mark_down(spec.hostname)
            server.mark_down(spec.hostname)
        attempt = queue_finding_retest(db, finding_id=finding.id, user_id=user_id)
        executed = execute_retest_job(db, attempt.id, http_client=http_client)
        actual[spec.candidate_id] = executed.status
        db.expire_all()
        _ = db.get(Finding, finding.id)
        _ = db.get(RetestAttempt, executed.id)
    return actual


def _build_tools(
    *,
    truth: GroundTruth,
    http_client: LoopbackSafeHttpClient,
    mode: str,
    warnings: list[str],
) -> tuple[Any, list[str] | None, bool | None]:
    if mode == "offline":
        return SeededLoopbackDiscoveryTools(truth, http_client), None, None

    subfinder_hosts, note = invoke_subfinder(truth.root)
    if note:
        warnings.append(note)
    if subfinder_hosts:
        warnings.append(
            f"subfinder returned {len(subfinder_hosts)} public host(s) for {truth.root}; "
            "they are recorded only and are not used as the seeded fixture host list."
        )
    used_httpx = shutil.which("httpx") is not None
    if not used_httpx:
        warnings.append(
            "ProjectDiscovery httpx is not on PATH; falling back to python-httpx "
            "loopback probes. live_discovery_asset_recall is omitted."
        )
    tools = LiveLoopbackDiscoveryTools(
        truth,
        http_client,
        subfinder_hosts=subfinder_hosts,
        used_httpx_binary=used_httpx,
        warnings=warnings,
    )
    return tools, subfinder_hosts, used_httpx


def _coverage_payload(db: Session, operation: Operation) -> dict[str, Any]:
    freeze_operation_coverage(db, operation, source="recovered", actor_type="system")
    db.commit()
    row = db.scalar(
        select(OperationCoverageSummary).where(
            OperationCoverageSummary.operation_id == operation.id
        )
    )
    if row is None:
        raise RuntimeError("coverage snapshot missing after freeze")
    return coverage_payload_from_snapshot(db, operation, row)


def _apply_monitoring_run(tools: SeededLoopbackDiscoveryTools, run: dict[str, Any]) -> None:
    hosts = [str(item).lower().rstrip(".") for item in run.get("hosts") or []]
    tools.host_override = hosts
    outcomes = {
        host: "observed" for host in hosts
    }
    for host, outcome in (run.get("probe_outcomes") or {}).items():
        outcomes[str(host).lower().rstrip(".")] = str(outcome)
    tools.probe_outcome_by_host = outcomes
    for host in hosts:
        tools.capture_headers_by_host.setdefault(host, True)
    for host, capture in (run.get("capture_headers") or {}).items():
        tools.capture_headers_by_host[str(host).lower().rstrip(".")] = bool(capture)
    tools.probe_overrides_by_host = {
        str(host).lower().rstrip("."): dict(values)
        for host, values in (run.get("probe_overrides") or {}).items()
    }


def _change_identity(row: dict[str, Any]) -> tuple[str, str]:
    return (str(row.get("change_type") or ""), str(row.get("match_key") or ""))


def _score_monitoring_case(
    *,
    expect: dict[str, Any],
    payload: dict[str, Any],
) -> dict[str, Any]:
    expected_rows = [
        _change_identity(item) for item in (expect.get("changes") or [])
    ]
    actual_rows = [_change_identity(item) for item in (payload.get("changes") or [])]
    expected_set = set(expected_rows)
    actual_set = set(actual_rows)
    missing = sorted(f"{ctype}|{key}" for ctype, key in expected_set - actual_set)
    extra = sorted(f"{ctype}|{key}" for ctype, key in actual_set - expected_set)
    forbidden = [
        str(item)
        for item in (expect.get("forbid_change_types") or [])
        if any(row.get("change_type") == item for row in (payload.get("changes") or []))
    ]
    silent_hits = []
    for key in expect.get("silent_match_keys") or []:
        if any(str(row.get("match_key") or "") == str(key) for row in (payload.get("changes") or [])):
            if str(key).endswith("|exposed_admin_interface"):
                if any(
                    row.get("change_type") in {"candidate_new", "candidate_no_longer_emitted"}
                    and str(row.get("match_key") or "") == str(key)
                    for row in (payload.get("changes") or [])
                ):
                    silent_hits.append(str(key))
            elif any(str(row.get("match_key") or "") == str(key) for row in payload.get("changes") or []):
                # stable hostname may appear only if we incorrectly emit noise for it
                if any(
                    str(row.get("match_key") or "") == str(key)
                    and row.get("change_type")
                    in {
                        "hostname_newly_discovered",
                        "hostname_no_longer_discovered",
                        "http_observation_gained",
                        "http_observation_lost",
                        "response_status_changed",
                        "response_title_changed",
                        "final_url_changed",
                        "candidate_new",
                        "candidate_no_longer_emitted",
                    }
                    for row in (payload.get("changes") or [])
                ):
                    silent_hits.append(str(key))
    lost_reason_ok = True
    expected_reason = expect.get("lost_reason_code")
    if expected_reason:
        lost_reason_ok = any(
            row.get("change_type") == "http_observation_lost"
            and (row.get("after") or {}).get("reason_code") == expected_reason
            for row in (payload.get("changes") or [])
        )
    overall = (
        expect.get("comparability") == payload.get("comparability")
        and (
            "security_signal_baseline_unavailable" not in expect
            or bool(expect.get("security_signal_baseline_unavailable"))
            == bool(payload.get("security_signal_baseline_unavailable"))
        )
        and not missing
        and not extra
        and not forbidden
        and not silent_hits
        and lost_reason_ok
        and "coverage_improved" not in {row.get("change_type") for row in payload.get("changes") or []}
        and "coverage_degraded" not in {row.get("change_type") for row in payload.get("changes") or []}
    )
    expected_directions = dict(expect.get("coverage_directions") or {})
    direction_mismatches: list[str] = []
    for change_type, expected_direction in expected_directions.items():
        matched = [
            row
            for row in (payload.get("changes") or [])
            if row.get("change_type") == change_type
        ]
        actual_direction = (matched[0].get("after") or {}).get("direction") if matched else None
        if not matched or actual_direction != expected_direction:
            direction_mismatches.append(
                f"{change_type}: expected {expected_direction!r} got {actual_direction!r}"
            )
            overall = False
    if len(expected_directions) >= 2:
        unique_dirs = {
            (row.get("after") or {}).get("direction")
            for row in (payload.get("changes") or [])
            if row.get("change_type") in expected_directions
        }
        if unique_dirs <= {"improved"} or unique_dirs <= {"degraded"}:
            direction_mismatches.append(
                f"coverage directions collapsed to {sorted(unique_dirs)}"
            )
            overall = False
    return {
        "comparability": payload.get("comparability"),
        "baseline_operation_id": payload.get("baseline_operation_id"),
        "security_signal_baseline_unavailable": payload.get(
            "security_signal_baseline_unavailable"
        ),
        "expected": [f"{ctype}|{key}" for ctype, key in expected_rows],
        "actual": [f"{ctype}|{key}" for ctype, key in actual_rows],
        "missing": missing,
        "extra": extra,
        "forbidden": forbidden,
        "silent_hits": silent_hits,
        "lost_reason_ok": lost_reason_ok,
        "direction_mismatches": direction_mismatches,
        "correct": overall,
    }


def _mutate_live_candidates(db: Session, *, operation: Operation) -> None:
    snapshot = db.scalar(
        select(OperationDiffSummary).where(
            OperationDiffSummary.operation_id == operation.id
        )
    )
    if snapshot is None:
        raise RuntimeError("cannot mutate live candidates without a frozen snapshot")
    root = str((snapshot.comparison_snapshot or {}).get("contract", {}).get("scope_root") or "")
    asset = db.scalar(
        select(Asset).where(
            Asset.target_id == operation.target_id,
            Asset.hostname == root,
        )
    )
    if asset is None:
        raise RuntimeError("stable hostname asset missing for mutation proof")
    db.add(
        SecurityCandidate(
            organization_id=operation.organization_id,
            operation_id=operation.id,
            asset_id=asset.id,
            candidate_type="staging_dev_exposed",
            title="Mutated live candidate",
            summary="Injected after freeze to prove snapshot-to-snapshot comparison.",
            status="candidate",
            evidence={
                "asset_hostname": asset.hostname,
                "operation_ids": [str(operation.id)],
            },
        )
    )
    db.commit()


def _diff_payload(db: Session, operation: Operation) -> dict[str, Any]:
    freeze_operation_diff(db, operation, source="recovered", actor_type="system")
    db.commit()
    row = db.scalar(
        select(OperationDiffSummary).where(
            OperationDiffSummary.operation_id == operation.id
        )
    )
    if row is None:
        raise RuntimeError("diff snapshot missing after freeze")
    from app.services.diff import diff_payload_from_snapshot

    return diff_payload_from_snapshot(db, operation, row)


def run_monitoring_diff_fixture(
    db: Session,
    truth: GroundTruth,
    *,
    mode: str,
    save: bool,
    save_baseline: bool,
    warnings: list[str],
    started: float,
) -> dict[str, Any]:
    spec = (truth.raw.get("diff") or {}) if isinstance(truth.raw, dict) else {}
    runs = list(spec.get("runs") or [])
    if not runs:
        raise RuntimeError("monitoring-diff fixture is missing diff.runs")
    server = FixtureHttpServer(truth)
    try:
        port = server.start()
        http_client = LoopbackSafeHttpClient(port=port)
        tools = SeededLoopbackDiscoveryTools(truth, http_client)
        user, _org, target, first_operation = seed_world(
            db,
            root=truth.root,
            include_subdomains=truth.include_subdomains,
            exclusions=truth.exclusions,
        )
        cases: dict[str, Any] = {}
        operations: dict[str, Operation] = {}
        previous: Operation | None = None
        for index, run in enumerate(runs):
            run_id = str(run.get("id") or f"run{index}")
            if bool(run.get("mutate_live_before")) and previous is not None:
                _mutate_live_candidates(db, operation=previous)
            exclusions = list(run.get("exclusions") or truth.exclusions)
            if exclusions != list(target.scope.exclusions or []) or bool(
                run.get("exclusions")
            ):
                db.refresh(target)
                update_scope(
                    db,
                    target,
                    include_subdomains=truth.include_subdomains,
                    exclusions=exclusions,
                    actor_user_id=user.id,
                )
                db.refresh(target)
            if index == 0:
                operation = first_operation
            else:
                operation = create_operation(
                    db, user=user, target_id=target.id, source="manual"
                )
            _apply_monitoring_run(tools, run)
            operation = _start_operation(db, operation.id)
            executed = execute_discovery_job(db, operation.id, tools)
            if executed.status != "completed":
                raise RuntimeError(
                    f"{run_id} ended {executed.status}: {executed.error_message or 'unknown'}"
                )
            if bool(run.get("simulate_pre_m18")):
                row = db.scalar(
                    select(OperationDiffSummary).where(
                        OperationDiffSummary.operation_id == executed.id
                    )
                )
                if row is not None:
                    db.delete(row)
                    db.commit()
                # Do not re-freeze: a recovered freeze must not invent
                # a complete emitted-candidate history for a pre-M18 run.
                operations[run_id] = executed
                previous = executed
                continue
            payload = _diff_payload(db, executed)
            expect = dict(run.get("expect") or {})
            if expect:
                cases[run_id] = _score_monitoring_case(expect=expect, payload=payload)
                cases[run_id]["baseline_operation_id"] = payload.get("baseline_operation_id")
                cases[run_id]["operation_id"] = str(executed.id)
            operations[run_id] = executed
            previous = executed

        run2 = operations.get("run2")
        run3 = operations.get("run3")
        capability_case = {"correct": False}
        if run2 is not None and run3 is not None:
            row2 = db.scalar(
                select(OperationDiffSummary).where(
                    OperationDiffSummary.operation_id == run2.id
                )
            )
            row3 = db.scalar(
                select(OperationDiffSummary).where(
                    OperationDiffSummary.operation_id == run3.id
                )
            )
            if row2 is not None and row3 is not None:
                baseline_snap = dict(row2.comparison_snapshot or {})
                contract = dict(baseline_snap.get("contract") or {})
                contract["capability_manifest_version"] = int(
                    contract.get("capability_manifest_version") or 1
                ) + 1
                baseline_snap["contract"] = contract
                current_snap = dict(row3.comparison_snapshot or {})
                changes = diff_snapshots(
                    current=current_snap,
                    baseline=baseline_snap,
                    comparability="partial_capability",
                    include_security_signals=False,
                )
                types = {str(row.get("change_type")) for row in changes}
                capability_case = {
                    "comparability": "partial_capability",
                    "change_types": sorted(types),
                    "has_capability_manifest_changed": "capability_manifest_changed" in types,
                    "has_candidate_signal": bool(
                        types & {"candidate_new", "candidate_no_longer_emitted"}
                    ),
                    "has_resolved_regression": "regression_resolved_condition_reappeared"
                    in types,
                    "correct": (
                        "capability_manifest_changed" in types
                        and "candidate_new" not in types
                        and "candidate_no_longer_emitted" not in types
                        and "regression_resolved_condition_reappeared" not in types
                    ),
                }

        found_hosts, emitted = _pairs_for_operation(db, run2.id if run2 is not None else first_operation.id)
        duration_ms = int((perf_counter() - started) * 1000)
        result = score(
            truth=truth,
            mode=mode,
            found_hosts=found_hosts,
            emitted=emitted,
            supported=set(),
            retest_actual={},
            duration_ms=duration_ms,
            warnings=warnings,
            git_sha=git_sha(),
            operation_id=str(run2.id if run2 is not None else first_operation.id),
            coverage=_coverage_payload(db, run2 if run2 is not None else first_operation),
            frozen_surface=None,
        )
        all_cases_ok = all(case.get("correct") is True for case in cases.values())
        result["diff"] = {
            "note": (
                "Operation-scoped monitoring diff. Independent of candidate precision. "
                "Not a security score."
            ),
            "cases": cases,
            "capability_change": capability_case,
            "all_correct": all_cases_ok and bool(capability_case.get("correct")),
        }
        result["schema_version"] = SCHEMA_VERSION
        validate_result(result)
        if save:
            write_json(result, result_path(result, baseline=False))
        if save_baseline:
            write_json(result, result_path(result, baseline=True))
        return result
    finally:
        server.stop()


def _alert_hostname(row: Alert | AlertEpisode) -> str:
    if isinstance(row, Alert):
        payload = dict(row.evidence or {})
    else:
        payload = dict(row.opening_evidence or {})
    return str(payload.get("hostname") or "")


def _expected_alert_match(expected: dict[str, Any], alert: Alert) -> bool:
    if str(expected.get("alert_type") or "") != alert.alert_type:
        return False
    hostname = expected.get("hostname")
    if hostname is not None and _alert_hostname(alert) != str(hostname):
        return False
    if expected.get("category") and alert.category != expected["category"]:
        return False
    if expected.get("priority") and alert.priority != expected["priority"]:
        return False
    return True


def _score_alerts_case(
    *,
    expect: dict[str, Any],
    db: Session,
    operation: Operation,
    previous_last_seen: dict[str, str],
) -> dict[str, Any]:
    alerts = list(
        db.scalars(select(Alert).where(Alert.operation_id == operation.id)).all()
    )
    episodes = list(
        db.scalars(
            select(AlertEpisode).where(AlertEpisode.target_id == operation.target_id)
        ).all()
    )
    receipt = db.scalar(
        select(AlertGenerationReceipt).where(
            AlertGenerationReceipt.operation_id == operation.id
        )
    )
    outbox_rows: list[NotificationOutbox] = []
    if alerts:
        outbox_rows = list(
            db.scalars(
                select(NotificationOutbox).where(
                    NotificationOutbox.alert_id.in_([item.id for item in alerts])
                )
            ).all()
        )
    expected_new = list(expect.get("new_alerts") or [])
    expected_count = int(expect.get("new_alert_count", len(expected_new)))
    unmatched = list(alerts)
    missing: list[str] = []
    for expected in expected_new:
        found = next(
            (item for item in unmatched if _expected_alert_match(expected, item)),
            None,
        )
        if found is None:
            missing.append(
                f"{expected.get('alert_type')}|{expected.get('hostname') or '-'}"
            )
        else:
            unmatched.remove(found)
    extra = [f"{item.alert_type}|{_alert_hostname(item) or '-'}" for item in unmatched]
    if expected_count != len(alerts):
        extra.append(f"new_alert_count:{len(alerts)}!={expected_count}")

    forbidden_types = [
        str(item)
        for item in (expect.get("forbid_alert_types") or [])
        if any(alert.alert_type == item for alert in alerts)
    ]
    forbidden_categories = [
        str(item)
        for item in (expect.get("forbid_categories") or [])
        if any(alert.category == item for alert in alerts)
    ]
    header_security = [
        str(alert.id)
        for alert in alerts
        if alert.alert_type == "header_evidence_lost"
        and alert.category == "security_regression"
    ]

    episode_errors: list[str] = []
    last_seen: dict[str, str] = dict(previous_last_seen)
    for expected in expect.get("open_episodes") or []:
        alert_type = str(expected.get("alert_type") or "")
        hostname = str(expected.get("hostname") or "")
        matched = [
            row
            for row in episodes
            if row.alert_type == alert_type
            and row.status == "open"
            and (not hostname or _alert_hostname(row) == hostname)
        ]
        if not matched:
            episode_errors.append(f"missing_open:{alert_type}|{hostname or '-'}")
            continue
        row = matched[-1]
        last_seen[row.semantic_key] = str(row.last_seen_operation_id)
        advanced = str(row.last_seen_operation_id) == str(operation.id)
        expected_advanced = expected.get("last_seen_advanced")
        if expected_advanced is True and not advanced:
            episode_errors.append(f"last_seen_not_advanced:{row.semantic_key}")
        if expected_advanced is False and advanced:
            episode_errors.append(f"last_seen_advanced_unexpected:{row.semantic_key}")
        if expected.get("reopened_from_previous") is True and row.reopened_from_episode_id is None:
            episode_errors.append(f"missing_reopened_from:{row.semantic_key}")
        if expected.get("reopened_from_previous") is False and row.reopened_from_episode_id is not None:
            episode_errors.append(f"unexpected_reopened_from:{row.semantic_key}")
    for expected in expect.get("closed_episodes") or []:
        alert_type = str(expected.get("alert_type") or "")
        hostname = str(expected.get("hostname") or "")
        matched = [
            row
            for row in episodes
            if row.alert_type == alert_type
            and row.status == "closed"
            and (not hostname or _alert_hostname(row) == hostname)
        ]
        if not matched:
            episode_errors.append(f"missing_closed:{alert_type}|{hostname or '-'}")

    receipt_ok = receipt is not None and int(receipt.alert_count) == len(alerts)
    outbox_ok = len(outbox_rows) == len(alerts) and all(
        row.channel == "in_app" and row.destination_key == "org" for row in outbox_rows
    )
    overall = (
        not missing
        and not extra
        and not forbidden_types
        and not forbidden_categories
        and not header_security
        and not episode_errors
        and receipt_ok
        and outbox_ok
    )
    return {
        "expected_new_alert_count": expected_count,
        "actual_new_alert_count": len(alerts),
        "actual_new_alert_types": [item.alert_type for item in alerts],
        "missing": missing,
        "extra": extra,
        "forbidden_types": forbidden_types,
        "forbidden_categories": forbidden_categories,
        "header_security_regression": header_security,
        "episode_errors": episode_errors,
        "receipt_ok": receipt_ok,
        "outbox_ok": outbox_ok,
        "last_seen": last_seen,
        "correct": overall,
    }


def run_monitoring_alerts_fixture(
    db: Session,
    truth: GroundTruth,
    *,
    mode: str,
    save: bool,
    save_baseline: bool,
    warnings: list[str],
    started: float,
) -> dict[str, Any]:
    spec = (truth.raw.get("alerts") or {}) if isinstance(truth.raw, dict) else {}
    runs = list(spec.get("runs") or [])
    if not runs:
        raise RuntimeError("monitoring-alerts fixture is missing alerts.runs")
    from sqlalchemy.orm.attributes import flag_modified

    server = FixtureHttpServer(truth)
    try:
        port = server.start()
        http_client = LoopbackSafeHttpClient(port=port)
        tools = SeededLoopbackDiscoveryTools(truth, http_client)
        user, _org, target, first_operation = seed_world(
            db,
            root=truth.root,
            include_subdomains=truth.include_subdomains,
            exclusions=truth.exclusions,
        )
        cases: dict[str, Any] = {}
        operations: dict[str, Operation] = {}
        previous: Operation | None = None
        previous_last_seen: dict[str, str] = {}
        for index, run in enumerate(runs):
            run_id = str(run.get("id") or f"run{index}")
            if bool(run.get("bump_baseline_capability")) and previous is not None:
                row = db.scalar(
                    select(OperationDiffSummary).where(
                        OperationDiffSummary.operation_id == previous.id
                    )
                )
                if row is None:
                    raise RuntimeError("cannot bump capability without a frozen snapshot")
                snapshot = dict(row.comparison_snapshot or {})
                contract = dict(snapshot.get("contract") or {})
                contract["capability_manifest_version"] = (
                    int(contract.get("capability_manifest_version") or 1) + 1
                )
                snapshot["contract"] = contract
                row.comparison_snapshot = snapshot
                flag_modified(row, "comparison_snapshot")
                db.commit()
            exclusions = list(run.get("exclusions") or truth.exclusions)
            if exclusions != list(target.scope.exclusions or []) or bool(
                run.get("exclusions")
            ):
                db.refresh(target)
                update_scope(
                    db,
                    target,
                    include_subdomains=truth.include_subdomains,
                    exclusions=exclusions,
                    actor_user_id=user.id,
                )
                db.refresh(target)
            if bool(run.get("simulate_pre_m18")):
                if index == 0:
                    operation = first_operation
                else:
                    operation = create_operation(
                        db, user=user, target_id=target.id, source="manual"
                    )
                _apply_monitoring_run(tools, run)
                operation = _start_operation(db, operation.id)
                executed = execute_discovery_job(db, operation.id, tools)
                if executed.status != "completed":
                    raise RuntimeError(
                        f"{run_id} ended {executed.status}: {executed.error_message or 'unknown'}"
                    )
                row = db.scalar(
                    select(OperationDiffSummary).where(
                        OperationDiffSummary.operation_id == executed.id
                    )
                )
                if row is not None:
                    db.delete(row)
                    db.commit()
                operations[run_id] = executed
                previous = executed
                continue
            if index == 0:
                operation = first_operation
            else:
                operation = create_operation(
                    db, user=user, target_id=target.id, source="manual"
                )
            _apply_monitoring_run(tools, run)
            operation = _start_operation(db, operation.id)
            executed = execute_discovery_job(db, operation.id, tools)
            if executed.status != "completed":
                raise RuntimeError(
                    f"{run_id} ended {executed.status}: {executed.error_message or 'unknown'}"
                )
            expect = dict(run.get("expect") or {})
            if expect:
                case = _score_alerts_case(
                    expect=expect,
                    db=db,
                    operation=executed,
                    previous_last_seen=previous_last_seen,
                )
                cases[run_id] = case
                previous_last_seen = dict(case.get("last_seen") or previous_last_seen)
            operations[run_id] = executed
            previous = executed

        found_hosts, emitted = _pairs_for_operation(
            db, previous.id if previous is not None else first_operation.id
        )
        duration_ms = int((perf_counter() - started) * 1000)
        result = score(
            truth=truth,
            mode=mode,
            found_hosts=found_hosts,
            emitted=emitted,
            supported=set(),
            retest_actual={},
            duration_ms=duration_ms,
            warnings=warnings,
            git_sha=git_sha(),
            operation_id=str(previous.id if previous is not None else first_operation.id),
            coverage=_coverage_payload(
                db, previous if previous is not None else first_operation
            ),
            frozen_surface=None,
        )
        all_cases_ok = all(case.get("correct") is True for case in cases.values())
        result["alerts"] = {
            "note": (
                "Operation-scoped monitoring alerts from frozen M18 snapshots. "
                "Independent of candidate precision. Not a security score."
            ),
            "cases": cases,
            "all_correct": all_cases_ok and bool(cases),
        }
        result["schema_version"] = SCHEMA_VERSION
        validate_result(result)
        if save:
            write_json(result, result_path(result, baseline=False))
        if save_baseline:
            write_json(result, result_path(result, baseline=True))
        return result
    finally:
        server.stop()


def run_fixture(
    db: Session,
    fixture_id: str,
    mode: str = "offline",
    *,
    save: bool = False,
    save_baseline: bool = False,
) -> dict[str, Any]:
    if fixture_id not in ALL_FIXTURES:
        raise ValueError(f"unknown fixture: {fixture_id}")
    if mode not in {"offline", "local_live"}:
        raise ValueError(f"unsupported mode: {mode}")
    if fixture_id == "monitoring-diff":
        truth = load_ground_truth(fixture_id)
        return run_monitoring_diff_fixture(
            db,
            truth,
            mode=mode,
            save=save,
            save_baseline=save_baseline,
            warnings=[],
            started=perf_counter(),
        )
    if fixture_id == "monitoring-alerts":
        truth = load_ground_truth(fixture_id)
        return run_monitoring_alerts_fixture(
            db,
            truth,
            mode=mode,
            save=save,
            save_baseline=save_baseline,
            warnings=[],
            started=perf_counter(),
        )

    truth = load_ground_truth(fixture_id)
    warnings: list[str] = []
    started = perf_counter()
    server = FixtureHttpServer(truth)
    try:
        port = server.start()
        http_client = LoopbackSafeHttpClient(port=port)
        tools, subfinder_hosts, used_httpx = _build_tools(
            truth=truth, http_client=http_client, mode=mode, warnings=warnings
        )
        user, _org, _target, operation = seed_world(
            db,
            root=truth.root,
            include_subdomains=truth.include_subdomains,
            exclusions=truth.exclusions,
        )
        operation = _start_operation(db, operation.id)
        executed = execute_discovery_job(db, operation.id, tools)
        if executed.status != "completed":
            raise RuntimeError(
                f"discovery job ended {executed.status}: {executed.error_message or 'unknown'}"
            )
        db.refresh(executed)
        frozen_surface = dict(
            (_coverage_payload(db, executed).get("surface") or {})
        )

        if truth.coverage and truth.coverage.validation_force_redirect:
            for host in truth.coverage.validation_force_redirect:
                http_client.mark_redirect(host)

        candidates = list(
            db.scalars(
                select(SecurityCandidate).where(SecurityCandidate.operation_id == operation.id)
            ).all()
        )
        attempt_ids: list[UUID] = []
        for candidate in candidates:
            attempt = queue_candidate_validation(
                db, candidate_id=candidate.id, user_id=user.id
            )
            attempt_ids.append(attempt.id)
        for attempt_id in attempt_ids:
            execute_validation_job(db, attempt_id, http_client=http_client)

        found_hosts, emitted = _pairs_for_operation(db, operation.id)
        supported = _supported_pairs(db, operation.id)
        retest_actual = _run_retests(
            db,
            truth=truth,
            user_id=user.id,
            operation_id=operation.id,
            http_client=http_client,
            server=server,
        )
        live_probed = None
        if mode == "local_live" and isinstance(tools, LiveLoopbackDiscoveryTools):
            live_probed = list(tools.probed_hosts)
        duration_ms = int((perf_counter() - started) * 1000)
        result = score(
            truth=truth,
            mode=mode,
            found_hosts=found_hosts,
            emitted=emitted,
            supported=supported,
            retest_actual=retest_actual,
            duration_ms=duration_ms,
            warnings=warnings,
            live_probed_hosts=live_probed,
            subfinder_hosts=subfinder_hosts,
            used_httpx_binary=used_httpx,
            git_sha=git_sha(),
            operation_id=str(operation.id),
            coverage=_coverage_payload(db, executed),
            frozen_surface=frozen_surface,
        )
        result["schema_version"] = SCHEMA_VERSION
        validate_result(result)
        if save:
            write_json(result, result_path(result, baseline=False))
        if save_baseline:
            write_json(result, result_path(result, baseline=True))
        return result
    finally:
        server.stop()


def default_ci_fixture_ids() -> tuple[str, ...]:
    return DEFAULT_CI_FIXTURES


def format_human(result: dict[str, Any]) -> str:
    pipeline = result["pipeline_assets"]
    candidates = result["candidates"]
    lines = [
        f"=== {result['fixture_id']} ({result['mode']}) ===",
        "Asset pipeline (seeded hosts the harness handed Scout; not internet discovery):",
        f"  pipeline_asset_precision={pipeline['pipeline_asset_precision']}",
        f"  pipeline_asset_recall={pipeline['pipeline_asset_recall']}",
        f"  missing={pipeline['missing']}  extra={pipeline['extra']}",
        "Candidates (rule-faithful and desirable kept separate; not one accuracy score):",
        f"  recall={candidates['recall']}",
        f"  precision_rule_faithful={candidates['precision_rule_faithful']}",
        f"  precision_desirable={candidates['precision_desirable']}",
        f"  unexpected={candidates['unexpected']}",
        f"  false_positives_vs_not_candidates={candidates['false_positives_vs_not_candidates']}",
        f"  misses={candidates['misses']}",
        f"Overlaps (expected, not false positives): {json.dumps(result['overlaps'])}",
        f"known_misses (documented capability gaps, excluded from recall): {result['known_misses']}",
        (
            f"validation support_rate={result['validation']['support_rate']} "
            f"disagreements={result['validation']['disagreements']}"
        ),
    ]
    if result["mode"] == "local_live" and result.get("live_discovery"):
        live = result["live_discovery"]
        lines.append(
            "Live discovery-tool wiring against loopback-mapped fixture hosts "
            "(not internet-wide discovery quality):"
        )
        lines.append(
            f"  live_discovery_asset_recall={live.get('live_discovery_asset_recall')} "
            f"used_httpx_binary={live.get('used_httpx_binary')} "
            f"subfinder_public_host_count={live.get('subfinder_public_host_count')}"
        )
    if result.get("retest"):
        lines.append(f"retest={json.dumps(result['retest'])}")
    if result.get("coverage"):
        cov = result["coverage"]
        actual = cov.get("actual") or {}
        lines.append("Coverage (operation-scoped; not a security score):")
        lines.append(
            f"  in_scope_discovered={actual.get('in_scope_discovered')} "
            f"submitted={actual.get('submitted_for_http_observation')} "
            f"http_obtained={actual.get('http_observation_obtained')} "
            f"http_not_obtained={actual.get('http_observation_not_obtained')}"
        )
        lines.append(
            f"  probe_no_result={actual.get('probe_no_result')} "
            f"host_not_reachable={actual.get('host_not_reachable')} "
            f"discarded={actual.get('discarded_out_of_scope')}"
        )
        lines.append(f"  all_correct={cov.get('all_correct')} matches={cov.get('matches')}")
    if result.get("diff"):
        diff = result["diff"]
        lines.append("Monitoring diff (operation-scoped; not a security score):")
        lines.append(f"  all_correct={diff.get('all_correct')}")
        cases = diff.get("cases") or {}
        for run_id, case in cases.items():
            lines.append(
                f"  {run_id}: correct={case.get('correct')} "
                f"comparability={case.get('comparability')} "
                f"missing={case.get('missing')} extra={case.get('extra')}"
            )
        cap = diff.get("capability_change") or {}
        lines.append(
            f"  capability_change correct={cap.get('correct')} "
            f"types={cap.get('change_types')}"
        )
    if result.get("alerts"):
        alerts = result["alerts"]
        lines.append("Monitoring alerts (operation-scoped; not a security score):")
        lines.append(f"  all_correct={alerts.get('all_correct')}")
        cases = alerts.get("cases") or {}
        for run_id, case in cases.items():
            lines.append(
                f"  {run_id}: correct={case.get('correct')} "
                f"new_alerts={case.get('actual_new_alert_types')} "
                f"missing={case.get('missing')} extra={case.get('extra')}"
            )
    if result.get("warnings"):
        lines.append(f"warnings={result['warnings']}")
    lines.append(f"duration_ms={result['duration_ms']} operation_id={result['operation_id']}")
    return "\n".join(lines)
