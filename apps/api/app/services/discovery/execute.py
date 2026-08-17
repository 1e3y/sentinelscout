"""Authorize scope and persist discovery results for a claimed operation."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from app.models.asset import Asset, DiscoveryObservation
from app.models.operation import Operation
from app.models.target import AuthorizedTarget, TargetScope
from app.services.discovery.runner import DiscoveryTools
from app.services.discovery.scope import filter_hosts_for_scope, normalize_host
from app.services.http_evidence import evidence_from_probe, observation_metadata
from app.services.operations import append_event


class AuthorizationExecutionError(Exception):
    """Target is no longer authorized for discovery."""


class StopRequested(Exception):
    """Cooperative cancellation signal."""


def load_authorized_scope(
    db: Session, operation: Operation
) -> tuple[AuthorizedTarget, TargetScope]:
    target = db.scalar(
        select(AuthorizedTarget)
        .options(joinedload(AuthorizedTarget.scope))
        .where(AuthorizedTarget.id == operation.target_id)
    )
    if target is None:
        raise AuthorizationExecutionError("Target not found for operation")
    if target.organization_id != operation.organization_id:
        raise AuthorizationExecutionError("Target organization mismatch")
    if target.status == "revoked":
        raise AuthorizationExecutionError("Target is revoked")
    if target.status != "verified":
        raise AuthorizationExecutionError("Target is not verified")
    if target.scope is None:
        raise AuthorizationExecutionError("Target scope is missing")
    return target, target.scope


def _normalize_url(url: str) -> str:
    candidate = url if "://" in url else f"https://{url}"
    parsed = urlsplit(candidate)
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        return ""
    port = f":{parsed.port}" if parsed.port else ""
    path = parsed.path or ""
    # Recon only — keep path if httpx returned one, but never invent attack paths.
    return urlunsplit((parsed.scheme.lower() or "https", f"{host}{port}", path, "", ""))


def _upsert_asset(
    db: Session,
    *,
    organization_id: UUID,
    target_id: UUID,
    hostname: str,
    url: str,
    asset_type: str,
    status_code: int | None,
    title: str | None,
    source: str,
) -> tuple[Asset, bool]:
    existing = db.scalar(
        select(Asset).where(
            Asset.organization_id == organization_id,
            Asset.target_id == target_id,
            Asset.hostname == hostname,
            Asset.url == url,
        )
    )
    now = datetime.now(timezone.utc)
    if existing is None:
        asset = Asset(
            organization_id=organization_id,
            target_id=target_id,
            hostname=hostname,
            url=url,
            asset_type=asset_type,
            status_code=status_code,
            title=title,
            source=source,
            first_seen_at=now,
            last_seen_at=now,
        )
        db.add(asset)
        db.flush()
        return asset, True

    existing.status_code = status_code
    existing.title = title
    existing.source = source
    existing.asset_type = asset_type
    existing.last_seen_at = now
    db.flush()
    return existing, False


def _add_observation(
    db: Session,
    *,
    organization_id: UUID,
    operation_id: UUID,
    asset_id: UUID | None,
    observation_type: str,
    summary: str,
    metadata: dict | None,
    source: str,
) -> DiscoveryObservation:
    row = DiscoveryObservation(
        organization_id=organization_id,
        operation_id=operation_id,
        asset_id=asset_id,
        observation_type=observation_type,
        summary=summary[:512],
        observation_metadata=metadata or {},
        source=source,
    )
    db.add(row)
    db.flush()
    return row


def run_discovery(
    db: Session,
    operation: Operation,
    tools: DiscoveryTools,
    *,
    should_stop: Callable[[], bool] | None = None,
) -> dict:
    """Execute authorized discovery. Raises DiscoveryError / AuthorizationExecutionError."""
    target, scope = load_authorized_scope(db, operation)
    root = scope.root_domain
    exclusions = list(scope.exclusions or [])

    append_event(
        db,
        operation,
        event_type="discovery.started",
        summary=f"Asset discovery started for {root}.",
        metadata={"domain": root, "status": "running"},
    )
    db.commit()

    if should_stop and should_stop():
        raise StopRequested()

    if scope.include_subdomains:
        discovered, truncation_note = tools.discover_hosts(root)
        hosts = list(dict.fromkeys([root, *discovered]))
    else:
        hosts, truncation_note = [root], None

    if should_stop and should_stop():
        raise StopRequested()

    in_scope = filter_hosts_for_scope(
        hosts,
        root,
        include_subdomains=scope.include_subdomains,
        exclusions=exclusions,
    )
    discarded = len(hosts) - len(in_scope)

    for host in in_scope:
        asset, created = _upsert_asset(
            db,
            organization_id=operation.organization_id,
            target_id=target.id,
            hostname=host,
            url="",
            asset_type="hostname",
            status_code=None,
            title=None,
            source="subfinder",
        )
        _add_observation(
            db,
            organization_id=operation.organization_id,
            operation_id=operation.id,
            asset_id=asset.id,
            observation_type="subdomain_discovered",
            summary=f"Hostname observed in scope: {host}.",
            metadata={"hostname": host},
            source="subfinder",
        )
        if created:
            append_event(
                db,
                operation,
                event_type="asset.discovered",
                summary=f"Discovered hostname {host}.",
                metadata={"hostname": host, "asset_id": str(asset.id)},
            )
        else:
            append_event(
                db,
                operation,
                event_type="observation.created",
                summary=f"Hostname re-observed: {host}.",
                metadata={"hostname": host, "asset_id": str(asset.id)},
            )
    db.commit()

    if should_stop and should_stop():
        raise StopRequested()

    probes = tools.probe_hosts(in_scope)
    http_assets = 0
    for probe in probes:
        host = normalize_host(probe.url)
        if host not in in_scope:
            # Defense in depth: discard out-of-scope probe results.
            discarded += 1
            continue
        normalized_url = _normalize_url(probe.url)
        if not normalized_url:
            continue
        asset, created = _upsert_asset(
            db,
            organization_id=operation.organization_id,
            target_id=target.id,
            hostname=host,
            url=normalized_url,
            asset_type="http_service",
            status_code=probe.status_code,
            title=probe.title or None,
            source="subfinder_httpx",
        )
        http_assets += 1
        evidence = evidence_from_probe(
            headers_observed=probe.headers_observed,
            headers=probe.headers,
            headers_present=probe.headers_present,
            content_type=probe.content_type,
            location_url=probe.location_url,
            requested_url=probe.requested_url or normalized_url,
            final_url=probe.final_url or normalized_url,
            redirected=probe.redirected,
            scheme=probe.scheme,
        )
        http_meta = observation_metadata(
            evidence,
            hostname=host,
            status_code=probe.status_code,
            title=probe.title or None,
            url=normalized_url,
        )
        _add_observation(
            db,
            organization_id=operation.organization_id,
            operation_id=operation.id,
            asset_id=asset.id,
            observation_type="service_reachable",
            summary=f"HTTP service reachable at {host}.",
            metadata={
                "hostname": host,
                "url": normalized_url,
                "status_code": probe.status_code,
            },
            source="httpx",
        )
        _add_observation(
            db,
            organization_id=operation.organization_id,
            operation_id=operation.id,
            asset_id=asset.id,
            observation_type="http_response_observed",
            summary=f"HTTP response observed for {host}"
            + (f" ({probe.status_code})." if probe.status_code is not None else "."),
            metadata=http_meta,
            source="httpx",
        )
        append_event(
            db,
            operation,
            event_type="asset.discovered" if created else "observation.created",
            summary=(
                f"Discovered HTTP service at {host}."
                if created
                else f"HTTP service re-observed at {host}."
            ),
            metadata={
                "hostname": host,
                "url": normalized_url,
                "status_code": probe.status_code,
                "asset_id": str(asset.id),
            },
        )
    db.commit()

    summary = (
        f"Discovery completed for {root}: {len(in_scope)} in-scope host(s), "
        f"{http_assets} HTTP service(s)."
    )
    if truncation_note:
        summary = f"{summary} {truncation_note}"
    if discarded:
        summary = f"{summary} Discarded {discarded} out-of-scope result(s)."

    append_event(
        db,
        operation,
        event_type="discovery.completed",
        summary=summary,
        metadata={
            "domain": root,
            "status": "running",
            "count": len(in_scope),
        },
    )
    db.commit()
    return {
        "hosts": len(in_scope),
        "http_assets": http_assets,
        "discarded": discarded,
        "truncation_note": truncation_note,
    }
