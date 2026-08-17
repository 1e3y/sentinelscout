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
from app.models.asset import Asset, DiscoveryObservation
from app.models.candidate import SecurityCandidate
from app.models.coverage import OperationCoverageSummary
from app.models.finding import Finding
from app.models.operation import Operation
from app.models.retest import RetestAttempt
from app.models.validation import ValidationAttempt
from app.services.audit import record_audit
from app.services.coverage import (
    coverage_payload_from_snapshot,
    freeze_operation_coverage,
)
from app.services.findings import mark_ready_for_retest, promote_candidate_to_finding
from app.services.findings.remediation import start_remediation
from app.services.operations import append_event, queue_candidate_validation
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
    if result.get("warnings"):
        lines.append(f"warnings={result['warnings']}")
    lines.append(f"duration_ms={result['duration_ms']} operation_id={result['operation_id']}")
    return "\n".join(lines)
