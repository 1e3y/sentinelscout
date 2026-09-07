"""AES-256-GCM opaque invitation refs (Milestone 41).

Token format version is ``v1`` (wire prefix only). There is a single dedicated
active encryption key — no fake key-version rotation ring.

Wire format::

    v1.<base64url(nonce || ciphertext_and_tag)>

Plaintext (UTF-8)::

    v1|{app_organization_uuid}|{provider_invitation_id}|{exp_unix}

Key parsing matches the repository AES-256-GCM hex key convention used elsewhere
(32-byte key as 64 hex chars). This uses a dedicated M41 secret, never the
report-delivery key.
"""

from __future__ import annotations

import binascii
from base64 import urlsafe_b64decode, urlsafe_b64encode
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from os import urandom
from uuid import UUID

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import Settings, get_settings

INVITATION_REF_KEY_BYTES = 32
INVITATION_REF_NONCE_BYTES = 12
TOKEN_FORMAT_VERSION = "v1"
DEFAULT_REF_TTL = timedelta(hours=24)
# Structural check only — never treat as provider id equality outside decrypt.
_PROVIDER_INVITATION_ID_MAX_LEN = 128


class InvitationRefCodecError(Exception):
    """Ref mint/parse failed (missing key, corrupt token, expired, etc.)."""


@dataclass(frozen=True)
class InvitationRefPayload:
    organization_id: UUID
    provider_invitation_id: str
    expires_at: datetime


def parse_invitation_ref_key(raw: str | None) -> bytes | None:
    value = (raw or "").strip()
    if not value:
        return None
    if len(value) != INVITATION_REF_KEY_BYTES * 2:
        return None
    try:
        key = binascii.unhexlify(value)
    except binascii.Error:
        return None
    if len(key) != INVITATION_REF_KEY_BYTES:
        return None
    return key


def invitation_ref_codec_ready(settings: Settings | None = None) -> bool:
    cfg = settings or get_settings()
    return parse_invitation_ref_key(cfg.organization_invitation_ref_secret_key) is not None


def _require_key(settings: Settings | None = None) -> bytes:
    cfg = settings or get_settings()
    key = parse_invitation_ref_key(cfg.organization_invitation_ref_secret_key)
    if key is None:
        raise InvitationRefCodecError("invitation_ref_codec_unavailable")
    return key


def _ref_expiry(*, now: datetime, provider_expires_at: datetime | None) -> datetime:
    capped = now + DEFAULT_REF_TTL
    if provider_expires_at is None:
        return capped
    if provider_expires_at.tzinfo is None:
        return capped
    return min(capped, provider_expires_at)


def mint_invitation_ref(
    *,
    organization_id: UUID,
    provider_invitation_id: str,
    provider_expires_at: datetime | None = None,
    now: datetime | None = None,
    settings: Settings | None = None,
) -> str:
    if not isinstance(provider_invitation_id, str) or not provider_invitation_id.strip():
        raise InvitationRefCodecError("invalid_provider_invitation_id")
    if len(provider_invitation_id) > _PROVIDER_INVITATION_ID_MAX_LEN:
        raise InvitationRefCodecError("invalid_provider_invitation_id")
    if any(ch in provider_invitation_id for ch in ("|", "\n", "\r")):
        raise InvitationRefCodecError("invalid_provider_invitation_id")

    key = _require_key(settings)
    current = now or datetime.now(timezone.utc)
    expires_at = _ref_expiry(now=current, provider_expires_at=provider_expires_at)
    plaintext = (
        f"{TOKEN_FORMAT_VERSION}|{organization_id}|{provider_invitation_id}|"
        f"{int(expires_at.timestamp())}"
    ).encode("utf-8")
    nonce = urandom(INVITATION_REF_NONCE_BYTES)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    blob = urlsafe_b64encode(nonce + ciphertext).decode("ascii").rstrip("=")
    return f"{TOKEN_FORMAT_VERSION}.{blob}"


def open_invitation_ref(
    raw: str,
    *,
    expected_organization_id: UUID,
    now: datetime | None = None,
    settings: Settings | None = None,
) -> InvitationRefPayload:
    """Decrypt and validate a ref. Raises InvitationRefCodecError on any failure."""
    if not isinstance(raw, str) or not raw.strip():
        raise InvitationRefCodecError("invalid_ref")
    token = raw.strip()
    if not token.startswith(f"{TOKEN_FORMAT_VERSION}."):
        raise InvitationRefCodecError("invalid_ref")
    blob = token[len(TOKEN_FORMAT_VERSION) + 1 :]
    if not blob:
        raise InvitationRefCodecError("invalid_ref")
    padded = blob + ("=" * (-len(blob) % 4))
    try:
        packed = urlsafe_b64decode(padded.encode("ascii"))
    except (binascii.Error, ValueError) as exc:
        raise InvitationRefCodecError("invalid_ref") from exc
    if len(packed) <= INVITATION_REF_NONCE_BYTES:
        raise InvitationRefCodecError("invalid_ref")
    nonce = packed[:INVITATION_REF_NONCE_BYTES]
    ciphertext = packed[INVITATION_REF_NONCE_BYTES:]
    key = _require_key(settings)
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, None).decode("utf-8")
    except Exception as exc:
        raise InvitationRefCodecError("invalid_ref") from exc

    parts = plaintext.split("|")
    if len(parts) != 4 or parts[0] != TOKEN_FORMAT_VERSION:
        raise InvitationRefCodecError("invalid_ref")
    try:
        organization_id = UUID(parts[1])
    except (TypeError, ValueError) as exc:
        raise InvitationRefCodecError("invalid_ref") from exc
    provider_invitation_id = parts[2]
    if (
        not provider_invitation_id
        or len(provider_invitation_id) > _PROVIDER_INVITATION_ID_MAX_LEN
        or "|" in provider_invitation_id
    ):
        raise InvitationRefCodecError("invalid_ref")
    try:
        exp_unix = int(parts[3])
    except (TypeError, ValueError) as exc:
        raise InvitationRefCodecError("invalid_ref") from exc
    expires_at = datetime.fromtimestamp(exp_unix, tz=timezone.utc)
    current = now or datetime.now(timezone.utc)
    if expires_at <= current:
        raise InvitationRefCodecError("expired_ref")
    if organization_id != expected_organization_id:
        raise InvitationRefCodecError("org_mismatch")
    return InvitationRefPayload(
        organization_id=organization_id,
        provider_invitation_id=provider_invitation_id,
        expires_at=expires_at,
    )
