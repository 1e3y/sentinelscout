"""Compare discovery observations across consecutive operations for a target."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.asset import DiscoveryObservation
from app.models.operation import Operation
from app.services.operations import append_event


@dataclass(frozen=True)
class AssetFingerprint:
    hostname: str
    url: str
    status_code: int | None
    title: str | None


def _fingerprints_for_operation(
    db: Session, operation_id: UUID
) -> dict[tuple[str, str], AssetFingerprint]:
    rows = db.scalars(
        select(DiscoveryObservation).where(
            DiscoveryObservation.operation_id == operation_id,
            DiscoveryObservation.observation_type.in_(
                ("service_reachable", "http_response_observed", "subdomain_discovered")
            ),
        )
    ).all()
    result: dict[tuple[str, str], AssetFingerprint] = {}
    for row in rows:
        meta = row.observation_metadata or {}
        hostname = str(meta.get("hostname") or "").lower().rstrip(".")
        url = str(meta.get("url") or "")
        if not hostname and not url:
            continue
        key = (hostname, url)
        status_code = meta.get("status_code")
        if status_code is not None:
            try:
                status_code = int(status_code)
            except (TypeError, ValueError):
                status_code = None
        title = meta.get("title")
        title_str = str(title) if title is not None else None
        existing = result.get(key)
        if existing is None:
            result[key] = AssetFingerprint(
                hostname=hostname,
                url=url,
                status_code=status_code,
                title=title_str,
            )
        else:
            # Prefer richer HTTP fingerprints over hostname-only.
            result[key] = AssetFingerprint(
                hostname=hostname,
                url=url or existing.url,
                status_code=status_code if status_code is not None else existing.status_code,
                title=title_str if title_str is not None else existing.title,
            )
    return result


def previous_completed_operation(
    db: Session, *, target_id: UUID, current_operation_id: UUID
) -> Operation | None:
    return db.scalar(
        select(Operation)
        .where(
            Operation.target_id == target_id,
            Operation.status == "completed",
            Operation.id != current_operation_id,
        )
        .order_by(Operation.completed_at.desc().nullslast(), Operation.created_at.desc())
        .limit(1)
    )


def detect_and_persist_changes(db: Session, operation: Operation) -> dict[str, int]:
    """Emit change events/observations vs previous completed operation for the target."""
    previous = previous_completed_operation(
        db, target_id=operation.target_id, current_operation_id=operation.id
    )
    if previous is None:
        return {"new": 0, "gone": 0, "changed": 0}

    current = _fingerprints_for_operation(db, operation.id)
    prior = _fingerprints_for_operation(db, previous.id)

    new_count = 0
    gone_count = 0
    changed_count = 0

    for key, fp in sorted(current.items()):
        if key not in prior:
            new_count += 1
            summary = (
                f"New externally reachable asset observed since previous assessment: "
                f"{fp.hostname or fp.url}."
            )
            obs = DiscoveryObservation(
                organization_id=operation.organization_id,
                operation_id=operation.id,
                asset_id=None,
                observation_type="asset_new_since_previous",
                summary=summary,
                observation_metadata={
                    "hostname": fp.hostname,
                    "url": fp.url,
                    "status_code": fp.status_code,
                    "previous_operation_id": str(previous.id),
                },
                source="change_detection",
            )
            db.add(obs)
            append_event(
                db,
                operation,
                event_type="asset.new_since_previous",
                summary=summary,
                metadata={
                    "hostname": fp.hostname,
                    "url": fp.url,
                    "status_code": fp.status_code,
                },
            )
            continue

        prev = prior[key]
        if fp.status_code != prev.status_code or (fp.title or "") != (prev.title or ""):
            changed_count += 1
            summary = (
                f"HTTP response metadata changed for {fp.hostname or fp.url} "
                f"since previous assessment."
            )
            obs = DiscoveryObservation(
                organization_id=operation.organization_id,
                operation_id=operation.id,
                asset_id=None,
                observation_type="asset_response_changed",
                summary=summary,
                observation_metadata={
                    "hostname": fp.hostname,
                    "url": fp.url,
                    "status_code": fp.status_code,
                    "previous_status_code": prev.status_code,
                    "title": fp.title,
                    "previous_title": prev.title,
                    "previous_operation_id": str(previous.id),
                },
                source="change_detection",
            )
            db.add(obs)
            append_event(
                db,
                operation,
                event_type="asset.response_changed",
                summary=summary,
                metadata={
                    "hostname": fp.hostname,
                    "url": fp.url,
                    "status_code": fp.status_code,
                },
            )

    for key, fp in sorted(prior.items()):
        if key not in current:
            gone_count += 1
            summary = (
                f"Previously observed asset no longer seen in this assessment: "
                f"{fp.hostname or fp.url}."
            )
            obs = DiscoveryObservation(
                organization_id=operation.organization_id,
                operation_id=operation.id,
                asset_id=None,
                observation_type="asset_no_longer_observed",
                summary=summary,
                observation_metadata={
                    "hostname": fp.hostname,
                    "url": fp.url,
                    "previous_status_code": fp.status_code,
                    "previous_operation_id": str(previous.id),
                },
                source="change_detection",
            )
            db.add(obs)
            append_event(
                db,
                operation,
                event_type="asset.no_longer_observed",
                summary=summary,
                metadata={
                    "hostname": fp.hostname,
                    "url": fp.url,
                },
            )

    db.commit()
    return {"new": new_count, "gone": gone_count, "changed": changed_count}
