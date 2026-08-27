"""AES-256-GCM for transient automatic-report share secrets.

The plaintext share secret and fragment URL never persist. Only ciphertext,
nonce, and key version sit on pending outbox rows, and those fields are
cleared on terminal status.
"""

from __future__ import annotations

import binascii
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

REPORT_DELIVERY_KEY_BYTES = 32
REPORT_DELIVERY_NONCE_BYTES = 12
DEFAULT_KEY_VERSION = "v1"


class ReportDeliveryCryptoError(Exception):
    """Missing or invalid report-delivery encryption key."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class EncryptedShareSecret:
    nonce: bytes
    ciphertext: bytes
    key_version: str


def parse_report_delivery_key(raw: str | None) -> bytes | None:
    value = (raw or "").strip()
    if not value:
        return None
    if len(value) != REPORT_DELIVERY_KEY_BYTES * 2:
        return None
    try:
        key = binascii.unhexlify(value)
    except binascii.Error:
        return None
    if len(key) != REPORT_DELIVERY_KEY_BYTES:
        return None
    return key


def report_delivery_crypto_ready(settings) -> tuple[bool, str | None]:
    key = parse_report_delivery_key(getattr(settings, "report_delivery_secret_key", ""))
    if key is None:
        return False, "missing_report_delivery_secret_key"
    version = str(getattr(settings, "report_delivery_secret_key_version", "") or "").strip()
    if not version:
        return False, "missing_report_delivery_secret_key_version"
    return True, None


def encrypt_share_secret(
    secret: str,
    *,
    key: bytes,
    key_version: str = DEFAULT_KEY_VERSION,
) -> EncryptedShareSecret:
    if len(key) != REPORT_DELIVERY_KEY_BYTES:
        raise ReportDeliveryCryptoError("invalid_report_delivery_secret_key")
    from os import urandom

    nonce = urandom(REPORT_DELIVERY_NONCE_BYTES)
    ciphertext = AESGCM(key).encrypt(nonce, secret.encode("ascii"), None)
    return EncryptedShareSecret(nonce=nonce, ciphertext=ciphertext, key_version=key_version)


def decrypt_share_secret(
    *,
    nonce: bytes,
    ciphertext: bytes,
    key: bytes,
) -> str:
    if len(key) != REPORT_DELIVERY_KEY_BYTES:
        raise ReportDeliveryCryptoError("invalid_report_delivery_secret_key")
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
    return plaintext.decode("ascii")
