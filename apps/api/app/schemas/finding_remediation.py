from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

MAX_REMEDIATION_SUMMARY_LENGTH = 4000

# Explicit directional formatting controls that can visually reorder or spoof
# surrounding text. Ordinary Arabic text and format characters such as ZWJ are
# intentionally allowed.
BIDI_CONTROL_CHARACTERS = frozenset(
    {
        "\u061c",  # Arabic letter mark
        "\u200e",  # left-to-right mark
        "\u200f",  # right-to-left mark
        "\u202a",  # left-to-right embedding
        "\u202b",  # right-to-left embedding
        "\u202c",  # pop directional formatting
        "\u202d",  # left-to-right override
        "\u202e",  # right-to-left override
        "\u2066",  # left-to-right isolate
        "\u2067",  # right-to-left isolate
        "\u2068",  # first strong isolate
        "\u2069",  # pop directional isolate
    }
)


def validate_remediation_summary(value: str) -> str:
    for character in value:
        codepoint = ord(character)
        is_c0_or_del = codepoint < 0x20 or codepoint == 0x7F
        is_c1 = 0x80 <= codepoint <= 0x9F
        if (is_c0_or_del or is_c1) and character not in {"\n", "\t"}:
            raise ValueError("Remediation summary contains a forbidden control character")
        if character in BIDI_CONTROL_CHARACTERS:
            raise ValueError("Remediation summary contains a forbidden bidi control character")
    summary = value.strip()
    if not summary:
        raise ValueError("Remediation summary must not be empty")
    if len(summary) > MAX_REMEDIATION_SUMMARY_LENGTH:
        raise ValueError(
            f"Remediation summary must be at most {MAX_REMEDIATION_SUMMARY_LENGTH} characters"
        )
    return summary


class CreateFindingRemediationRevisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    summary: str

    @field_validator("summary")
    @classmethod
    def validate_summary(cls, value: str) -> str:
        return validate_remediation_summary(value)


class FindingRemediationRevisionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: UUID
    revision_number: int
    summary: str
    created_at: datetime
    created_by_user_id: UUID
    created_by_name: str | None = None


class FindingRemediationHistoryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: UUID
    revision_count: int
    latest: FindingRemediationRevisionResponse | None = None
    page_size: int
    next_cursor: str | None = None
    revisions: list[FindingRemediationRevisionResponse] = Field(default_factory=list)
