"""Persist deterministic SecurityCandidate drafts with provenance + dedup."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.asset import Asset, DiscoveryObservation
from app.models.candidate import CANDIDATE_STATUSES, SecurityCandidate
from app.models.operation import Operation
from app.services.candidate_engine.rules import AssetContext, evaluate_asset
from app.services.operations import append_event


def _merge_evidence(existing: dict, draft_evidence: dict) -> dict:
    merged = dict(existing or {})
    obs = list(merged.get("observation_ids") or [])
    for item in draft_evidence.get("observation_ids") or []:
        if item not in obs:
            obs.append(item)
    merged["observation_ids"] = obs[:100]
    reasons = list(merged.get("reasons") or [])
    for item in draft_evidence.get("reasons") or []:
        if item not in reasons:
            reasons.append(item)
    merged["reasons"] = reasons[:50]
    signals = list(merged.get("signals") or [])
    for item in draft_evidence.get("signals") or []:
        if item not in signals:
            signals.append(item)
    merged["signals"] = signals[:50]
    ops = list(merged.get("operation_ids") or [])
    for item in draft_evidence.get("operation_ids") or []:
        if item not in ops:
            ops.append(item)
    merged["operation_ids"] = ops[:50]
    merged["why"] = draft_evidence.get("why") or merged.get("why")
    return merged


def generate_candidates_for_operation(db: Session, operation: Operation) -> list[SecurityCandidate]:
    observations = list(
        db.scalars(
            select(DiscoveryObservation).where(
                DiscoveryObservation.operation_id == operation.id
            )
        ).all()
    )
    by_asset: dict[UUID, list[DiscoveryObservation]] = {}
    for obs in observations:
        if obs.asset_id is None:
            continue
        by_asset.setdefault(obs.asset_id, []).append(obs)

    created_or_updated: list[SecurityCandidate] = []
    for asset_id, obs_list in sorted(by_asset.items(), key=lambda item: str(item[0])):
        asset = db.get(Asset, asset_id)
        if asset is None:
            continue
        # Prefer HTTP service assets for candidate generation; include hostname if needed.
        ctx = AssetContext(asset=asset, observations=tuple(obs_list))
        drafts = evaluate_asset(ctx)
        for draft in drafts:
            evidence = {
                "observation_ids": list(draft.observation_ids),
                "operation_ids": [str(operation.id)],
                "reasons": list(draft.reasons),
                "signals": list(draft.signals),
                "why": draft.summary,
                "asset_hostname": asset.hostname,
                "asset_url": asset.url,
            }
            existing = db.scalar(
                select(SecurityCandidate).where(
                    SecurityCandidate.organization_id == operation.organization_id,
                    SecurityCandidate.asset_id == draft.asset_id,
                    SecurityCandidate.candidate_type == draft.candidate_type,
                )
            )
            if existing is None:
                status = draft.status if draft.status in CANDIDATE_STATUSES else "candidate"
                # Hard ban confirmed/validated statuses.
                if status in {"validated", "confirmed", "exploitable"}:
                    status = "candidate"
                row = SecurityCandidate(
                    organization_id=operation.organization_id,
                    operation_id=operation.id,
                    asset_id=draft.asset_id,
                    candidate_type=draft.candidate_type,
                    title=draft.title,
                    summary=draft.summary,
                    status=status,
                    source=draft.source,
                    evidence=evidence,
                )
                db.add(row)
                db.flush()
                append_event(
                    db,
                    operation,
                    event_type="candidate.created",
                    summary=f"Security candidate created: {draft.title}",
                    metadata={
                        "asset_id": str(draft.asset_id),
                        "hostname": asset.hostname,
                        "candidate_type": draft.candidate_type,
                        "status": status,
                    },
                )
                created_or_updated.append(row)
            else:
                existing.evidence = _merge_evidence(existing.evidence, evidence)
                existing.operation_id = operation.id
                existing.title = draft.title
                existing.summary = draft.summary
                existing.updated_at = datetime.now(timezone.utc)
                # Do not resurrect dismissed candidates automatically.
                db.flush()
                created_or_updated.append(existing)

    db.flush()
    return created_or_updated
