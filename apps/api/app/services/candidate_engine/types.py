from __future__ import annotations

from dataclasses import dataclass, field
from uuid import UUID


@dataclass(frozen=True)
class CandidateDraft:
    asset_id: UUID
    candidate_type: str
    title: str
    summary: str
    status: str = "candidate"
    source: str = "deterministic_rules"
    observation_ids: tuple[str, ...] = field(default_factory=tuple)
    reasons: tuple[str, ...] = field(default_factory=tuple)
    signals: tuple[str, ...] = field(default_factory=tuple)
