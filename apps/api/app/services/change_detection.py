"""M10 change writers are retired. Operation diffs live in app.services.diff."""

from __future__ import annotations

from uuid import UUID

from sqlalchemy.orm import Session

from app.models.operation import Operation
from app.services.diff import previous_completed_operation as select_previous_completed


def previous_completed_operation(
    db: Session, *, target_id: UUID, current_operation_id: UUID
) -> Operation | None:
    """Compatibility wrapper. Baseline selection is organization+target+profile+completed."""
    current = db.get(Operation, current_operation_id)
    if current is None or current.target_id != target_id:
        return None
    return select_previous_completed(db, operation=current)


def detect_and_persist_changes(db: Session, operation: Operation) -> dict[str, int]:
    """No-op. M18 freezes hostname-keyed diffs at terminal completion."""
    _ = (db, operation)
    return {"new": 0, "gone": 0, "changed": 0}
