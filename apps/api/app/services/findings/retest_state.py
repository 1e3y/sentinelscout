"""Shared current-retest projection used by M30 and M32."""

from __future__ import annotations

RETEST_STATE_NONE = "none"
RETEST_STATE_IN_PROGRESS = "in_progress"


def current_retest_state(
    *, has_active: bool, latest_terminal_status: str | None
) -> str:
    """Return the one mutually exclusive current state for a finding."""
    if has_active:
        return RETEST_STATE_IN_PROGRESS
    if latest_terminal_status is None:
        return RETEST_STATE_NONE
    return latest_terminal_status
