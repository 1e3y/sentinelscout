"""Organization member invitations — provider-authoritative (Milestone 40).

CREATE is member-only. LIST reflects actual provider invitation roles (M38/M21
normalization). No local invitation table. Clerk owns invitation email delivery.
"""

from __future__ import annotations

import binascii
import logging
import re
from base64 import urlsafe_b64decode, urlsafe_b64encode
from datetime import datetime, timedelta, timezone
from uuid import UUID

from email_validator import EmailNotValidError, validate_email
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.models.organization import Organization
from app.schemas.organization_invitations import (
    LocalRecordingState,
    OrganizationInvitation,
    OrganizationInvitationCreated,
    OrganizationInvitationRevoked,
    OrganizationInvitationsResponse,
)
from app.services.audit import record_audit
from app.services.authorization import persistable_org_role
from app.services.clerk import (
    ClerkDirectory,
    ClerkInvitationMutationView,
    ClerkOrganizationInvitationRaw,
    OrganizationInvitationAlreadyMember,
    OrganizationInvitationAmbiguous,
    OrganizationInvitationDuplicatePending,
    OrganizationInvitationNotFound,
    OrganizationInvitationUnavailable,
)
from app.services.organization_access import classify_provider_role
from app.services.organization_invitation_refs import (
    InvitationRefCodecError,
    invitation_ref_codec_ready,
    mint_invitation_ref,
    open_invitation_ref,
)

logger = logging.getLogger("scout.organization_invitations")

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 100
CURSOR_VERSION = "v1"
INVALID_CURSOR_DETAIL = "Invalid organization invitations cursor"
CREATE_UNAVAILABLE_DETAIL = "Organization invitation could not be created."
LIST_UNAVAILABLE_DETAIL = "Organization invitations could not be verified."
REVOKE_UNAVAILABLE_DETAIL = "Organization invitation could not be revoked."
PENDING_NOT_FOUND_DETAIL = "Pending invitation not found."
ALREADY_MEMBER_DETAIL = "This person already has organization access."
DUPLICATE_PENDING_DETAIL = "An invitation is already pending for this address."
MAX_EMAIL_LENGTH = 254
# Provider clock skew tolerance for causal reconcile of ambiguous CREATE.
CREATE_CLOCK_SKEW = timedelta(seconds=120)
AUDIT_ACTION = "organization.invitation_created"
REVOKE_AUDIT_ACTION = "organization.invitation_revoked"
AUDIT_PERSIST_ATTEMPTS = 3

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def raise_create_unavailable() -> None:
    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail=CREATE_UNAVAILABLE_DETAIL,
    )


def raise_list_unavailable() -> None:
    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail=LIST_UNAVAILABLE_DETAIL,
    )


def raise_revoke_unavailable() -> None:
    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail=REVOKE_UNAVAILABLE_DETAIL,
    )


def raise_pending_not_found() -> None:
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=PENDING_NOT_FOUND_DETAIL,
    )


def require_invitation_ref_codec_ready_for_create() -> None:
    if not invitation_ref_codec_ready():
        raise_create_unavailable()


def require_invitation_ref_codec_ready_for_list() -> None:
    if not invitation_ref_codec_ready():
        raise_list_unavailable()


def require_invitation_ref_codec_ready_for_revoke() -> None:
    if not invitation_ref_codec_ready():
        raise_pending_not_found()


def encode_invitation_cursor(*, offset: int) -> str:
    payload = f"{CURSOR_VERSION}|{offset}"
    return urlsafe_b64encode(payload.encode("utf-8")).decode("ascii").rstrip("=")


def decode_invitation_cursor(raw: str) -> int:
    if not raw or not raw.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=INVALID_CURSOR_DETAIL,
        )
    padded = raw + ("=" * (-len(raw) % 4))
    try:
        decoded = urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=INVALID_CURSOR_DETAIL,
        ) from exc
    parts = decoded.split("|")
    if len(parts) != 2 or parts[0] != CURSOR_VERSION:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=INVALID_CURSOR_DETAIL,
        )
    try:
        offset = int(parts[1])
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=INVALID_CURSOR_DETAIL,
        ) from exc
    if offset < 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=INVALID_CURSOR_DETAIL,
        )
    return offset


def canonicalize_invitation_email(raw: str) -> str:
    """Validate and canonicalize invitation email.

    Uses ``email_validator.validate_email(..., check_deliverability=False).normalized``.
    That contract lowercases the domain and preserves local-part case — we do **not**
    apply an additional whole-mailbox ``.lower()``.
    """
    if not isinstance(raw, str):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Invalid email",
        )
    trimmed = raw.strip()
    if not trimmed:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Invalid email",
        )
    if len(trimmed) > MAX_EMAIL_LENGTH:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Invalid email",
        )
    if "," in trimmed or _CONTROL_CHARS.search(trimmed):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Invalid email",
        )
    try:
        result = validate_email(trimmed, check_deliverability=False)
    except EmailNotValidError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Invalid email",
        ) from exc
    # Use provider/library normalized form as-is (no blind local-part lowercasing).
    canonical = str(result.normalized)
    if len(canonical) > MAX_EMAIL_LENGTH:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Invalid email",
        )
    return canonical


def recipient_hint(canonical_email: str) -> str:
    """Deterministic presentation hint from the canonical mailbox only."""
    if "@" not in canonical_email:
        return "***"
    local, _, domain = canonical_email.partition("@")
    if not local or not domain:
        return "***"
    return f"{local[0]}***@{domain}"


def _ms_to_dt(value_ms: int | None) -> datetime | None:
    if value_ms is None:
        return None
    # Clerk uses milliseconds; tolerate seconds-scale values.
    seconds = value_ms / 1000.0 if value_ms > 10_000_000_000 else float(value_ms)
    return datetime.fromtimestamp(seconds, tz=timezone.utc)


def _status_is_pending(raw: str | None) -> bool:
    return isinstance(raw, str) and raw.strip().lower() == "pending"


def _dto_from_raw(
    row: ClerkOrganizationInvitationRaw,
    *,
    organization_id: UUID,
) -> OrganizationInvitation:
    if not _status_is_pending(row.status):
        raise_list_unavailable()
    created_at = _ms_to_dt(row.created_at_ms)
    if created_at is None:
        raise_list_unavailable()
    role, role_state = classify_provider_role(row.external_role)
    expires_at = _ms_to_dt(row.expires_at_ms)
    try:
        invitation_ref = mint_invitation_ref(
            organization_id=organization_id,
            provider_invitation_id=row.provider_invitation_id,
            provider_expires_at=expires_at,
        )
    except InvitationRefCodecError:
        raise_list_unavailable()
    return OrganizationInvitation(
        status="pending",
        role=role,
        role_state=role_state,
        recipient_hint=recipient_hint(row.email_address),
        created_at=created_at,
        expires_at=expires_at,
        invitation_ref=invitation_ref,
    )


def _persist_audit_with_retry(
    db: Session,
    *,
    organization_id: UUID,
    actor_user_id: UUID,
    action: str,
    summary: str,
    metadata: dict | None,
) -> bool:
    for _attempt in range(AUDIT_PERSIST_ATTEMPTS):
        try:
            record_audit(
                db,
                organization_id=organization_id,
                actor_type="user",
                actor_user_id=actor_user_id,
                action=action,
                resource_type="organization",
                resource_id=organization_id,
                summary=summary,
                metadata=metadata,
                commit=True,
            )
            return True
        except Exception:
            try:
                db.rollback()
            except Exception:
                pass
    return False


def _emit_audit_degraded(
    *,
    organization_id: UUID,
    actor_user_id: UUID,
    mutation_type: str,
) -> None:
    logger.error(
        "organization_invitation_audit_degraded",
        extra={
            "organization_app_id": str(organization_id),
            "actor_user_id": str(actor_user_id),
            "mutation_type": mutation_type,
        },
    )


def _lookup_pending_for_email(
    directory: ClerkDirectory,
    *,
    clerk_org_id: str,
    email_address: str,
) -> ClerkOrganizationInvitationRaw | None:
    try:
        rows, _total = directory.list_organization_invitations(
            clerk_org_id,
            status="pending",
            email_address=email_address,
            limit=1,
            offset=0,
        )
    except OrganizationInvitationUnavailable:
        raise_create_unavailable()
    except Exception:
        raise_create_unavailable()
    if not rows:
        return None
    row = rows[0]
    if not _status_is_pending(row.status):
        raise_create_unavailable()
    return row


def _correlates_to_attempt(
    row: ClerkOrganizationInvitationRaw,
    *,
    canonical_email: str,
    inviter_user_id: str,
    attempt_start: datetime,
) -> bool:
    if row.email_address != canonical_email:
        return False
    if not _status_is_pending(row.status):
        return False
    role, role_state = classify_provider_role(row.external_role)
    if role_state != "recognized" or role != "member":
        return False
    if row.inviter_user_id != inviter_user_id:
        return False
    created_at = _ms_to_dt(row.created_at_ms)
    if created_at is None:
        return False
    # Must not clearly predate this attempt (allow bounded provider clock skew).
    if created_at < (attempt_start - CREATE_CLOCK_SKEW):
        return False
    return True


def create_organization_invitation(
    db: Session,
    *,
    organization: Organization,
    directory: ClerkDirectory,
    actor_user_id: UUID,
    actor_clerk_user_id: str,
    email_raw: str,
) -> OrganizationInvitationCreated:
    # Codec readiness before any provider I/O (no invite email on misconfig).
    require_invitation_ref_codec_ready_for_create()

    if not organization.clerk_org_id or not organization.clerk_org_id.strip():
        raise_create_unavailable()
    if not actor_clerk_user_id or not actor_clerk_user_id.strip():
        raise_create_unavailable()

    canonical = canonicalize_invitation_email(email_raw)

    # Preflight: existing pending → 409, zero CREATE. Not the atomic race barrier.
    existing = _lookup_pending_for_email(
        directory,
        clerk_org_id=organization.clerk_org_id,
        email_address=canonical,
    )
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=DUPLICATE_PENDING_DETAIL,
        )

    attempt_start = datetime.now(timezone.utc)
    provider_role = persistable_org_role("member")
    created: ClerkOrganizationInvitationRaw | None = None

    try:
        created = directory.create_organization_invitation(
            organization.clerk_org_id,
            email_address=canonical,
            role=provider_role,
            inviter_user_id=actor_clerk_user_id,
            notify=True,
        )
    except OrganizationInvitationAlreadyMember:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=ALREADY_MEMBER_DETAIL,
        )
    except OrganizationInvitationDuplicatePending:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=DUPLICATE_PENDING_DETAIL,
        )
    except OrganizationInvitationAmbiguous:
        reconciled = _lookup_pending_for_email(
            directory,
            clerk_org_id=organization.clerk_org_id,
            email_address=canonical,
        )
        if reconciled is None:
            raise_create_unavailable()
        if not _correlates_to_attempt(
            reconciled,
            canonical_email=canonical,
            inviter_user_id=actor_clerk_user_id,
            attempt_start=attempt_start,
        ):
            raise_create_unavailable()
        created = reconciled
    except OrganizationInvitationUnavailable:
        raise_create_unavailable()
    except Exception:
        raise_create_unavailable()

    assert created is not None
    if not _status_is_pending(created.status):
        raise_create_unavailable()
    created_at = _ms_to_dt(created.created_at_ms)
    if created_at is None:
        raise_create_unavailable()

    expires_at = _ms_to_dt(created.expires_at_ms)
    try:
        invitation_ref = mint_invitation_ref(
            organization_id=organization.id,
            provider_invitation_id=created.provider_invitation_id,
            provider_expires_at=expires_at,
        )
    except InvitationRefCodecError:
        # Should be unreachable after readiness check; fail closed without leaking.
        raise_create_unavailable()

    audit_ok = _persist_audit_with_retry(
        db,
        organization_id=organization.id,
        actor_user_id=actor_user_id,
        action=AUDIT_ACTION,
        summary="Organization invitation created",
        metadata={"role": "member"},
    )
    recording: LocalRecordingState = "complete"
    if not audit_ok:
        recording = "audit_degraded"
        _emit_audit_degraded(
            organization_id=organization.id,
            actor_user_id=actor_user_id,
            mutation_type="invitation_create",
        )

    return OrganizationInvitationCreated(
        status="pending",
        role="member",
        role_state="recognized",
        recipient_hint=recipient_hint(canonical),
        created_at=created_at,
        expires_at=expires_at,
        invitation_ref=invitation_ref,
        local_recording_state=recording,
    )


def list_pending_organization_invitations(
    *,
    organization: Organization,
    directory: ClerkDirectory,
    page_size: int = DEFAULT_PAGE_SIZE,
    cursor: str | None = None,
) -> OrganizationInvitationsResponse:
    require_invitation_ref_codec_ready_for_list()

    if not organization.clerk_org_id or not organization.clerk_org_id.strip():
        raise_list_unavailable()

    size = min(max(page_size, 1), MAX_PAGE_SIZE)
    offset = decode_invitation_cursor(cursor) if cursor else 0

    try:
        rows, total = directory.list_organization_invitations(
            organization.clerk_org_id,
            status="pending",
            limit=size,
            offset=offset,
        )
    except OrganizationInvitationUnavailable:
        raise_list_unavailable()
    except Exception:
        raise_list_unavailable()

    items: list[OrganizationInvitation] = []
    for row in rows:
        # Correction 2: contradictory/malformed pending rows fail the page.
        items.append(_dto_from_raw(row, organization_id=organization.id))

    next_offset = offset + len(rows)
    if total is not None:
        next_cursor = (
            encode_invitation_cursor(offset=next_offset) if next_offset < total else None
        )
    else:
        next_cursor = (
            encode_invitation_cursor(offset=next_offset) if len(rows) == size else None
        )

    return OrganizationInvitationsResponse(
        page_size=size,
        next_cursor=next_cursor,
        total_invitations=total,
        items=items,
    )


def _status_norm(raw: str | None) -> str | None:
    if not isinstance(raw, str):
        return None
    value = raw.strip().lower()
    return value or None


def _require_pending_mutation_view(view: ClerkInvitationMutationView) -> None:
    status_value = _status_norm(view.status)
    if status_value == "pending":
        return
    # accepted / revoked / expired / unknown non-pending → uniform miss
    raise_pending_not_found()


def _reconcile_revoke_after_ambiguous(
    directory: ClerkDirectory,
    *,
    clerk_org_id: str,
    provider_invitation_id: str,
) -> ClerkInvitationMutationView:
    try:
        view = directory.get_organization_invitation(clerk_org_id, provider_invitation_id)
    except OrganizationInvitationNotFound:
        # Clerk normally preserves revoked records; absence after write is ambiguous.
        raise_revoke_unavailable()
    except OrganizationInvitationUnavailable:
        raise_revoke_unavailable()
    except Exception:
        raise_revoke_unavailable()

    status_value = _status_norm(view.status)
    if status_value == "revoked":
        return view
    if status_value == "pending":
        raise_revoke_unavailable()
    if status_value in {"accepted", "expired"}:
        raise_pending_not_found()
    raise_revoke_unavailable()


def revoke_organization_invitation(
    db: Session,
    *,
    organization: Organization,
    directory: ClerkDirectory,
    actor_user_id: UUID,
    actor_clerk_user_id: str,
    invitation_ref: str,
) -> OrganizationInvitationRevoked:
    """Revoke one pending provider invitation via opaque invitation_ref (M41)."""
    require_invitation_ref_codec_ready_for_revoke()

    if not organization.clerk_org_id or not organization.clerk_org_id.strip():
        raise_revoke_unavailable()
    if not actor_clerk_user_id or not actor_clerk_user_id.strip():
        raise_revoke_unavailable()

    try:
        payload = open_invitation_ref(
            invitation_ref,
            expected_organization_id=organization.id,
        )
    except InvitationRefCodecError:
        raise_pending_not_found()

    provider_invitation_id = payload.provider_invitation_id

    # 1) Authoritative pending precheck (exact GET; email-blind).
    try:
        current = directory.get_organization_invitation(
            organization.clerk_org_id,
            provider_invitation_id,
        )
    except OrganizationInvitationNotFound:
        raise_pending_not_found()
    except OrganizationInvitationUnavailable:
        raise_revoke_unavailable()
    except Exception:
        raise_revoke_unavailable()

    _require_pending_mutation_view(current)
    role, role_state = classify_provider_role(current.external_role)
    audit_metadata: dict | None = None
    if role_state == "recognized" and role is not None:
        audit_metadata = {"role": role}

    # 2) Provider revoke write (at most once).
    revoked_view: ClerkInvitationMutationView | None = None
    try:
        revoked_view = directory.revoke_organization_invitation(
            organization.clerk_org_id,
            provider_invitation_id,
            requesting_user_id=actor_clerk_user_id,
        )
    except OrganizationInvitationAmbiguous:
        revoked_view = _reconcile_revoke_after_ambiguous(
            directory,
            clerk_org_id=organization.clerk_org_id,
            provider_invitation_id=provider_invitation_id,
        )
    except OrganizationInvitationUnavailable:
        raise_revoke_unavailable()
    except OrganizationInvitationNotFound:
        raise_pending_not_found()
    except Exception:
        raise_revoke_unavailable()

    assert revoked_view is not None
    if _status_norm(revoked_view.status) != "revoked":
        # Exact non-revoked success body: treat non-pending as miss, else unavailable.
        status_value = _status_norm(revoked_view.status)
        if status_value in {"accepted", "expired", "pending"}:
            if status_value == "pending":
                raise_revoke_unavailable()
            raise_pending_not_found()
        raise_revoke_unavailable()

    audit_ok = _persist_audit_with_retry(
        db,
        organization_id=organization.id,
        actor_user_id=actor_user_id,
        action=REVOKE_AUDIT_ACTION,
        summary="Organization invitation revoked",
        metadata=audit_metadata,
    )
    recording: LocalRecordingState = "complete"
    if not audit_ok:
        recording = "audit_degraded"
        _emit_audit_degraded(
            organization_id=organization.id,
            actor_user_id=actor_user_id,
            mutation_type="invitation_revoke",
        )

    return OrganizationInvitationRevoked(
        revoked=True,
        local_recording_state=recording,
    )
