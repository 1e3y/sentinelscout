from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import httpx
import jwt
from fastapi import HTTPException, status
from jwt import PyJWKClient

from app.core.config import Settings


@dataclass(frozen=True)
class AuthenticatedIdentity:
    clerk_user_id: str
    claims: dict[str, Any]

    @property
    def active_org_id(self) -> str | None:
        org = self.claims.get("o")
        if isinstance(org, dict):
            org_id = org.get("id")
            if isinstance(org_id, str) and org_id:
                return org_id
        org_id = self.claims.get("org_id")
        if isinstance(org_id, str) and org_id:
            return org_id
        return None

    @property
    def active_org_role(self) -> str | None:
        org = self.claims.get("o")
        if isinstance(org, dict):
            role = org.get("rol") or org.get("role")
            if isinstance(role, str) and role:
                return role
        role = self.claims.get("org_role")
        if isinstance(role, str) and role:
            return role
        return None


class TokenVerifier:
    """Verifies Clerk session JWTs using JWKS. Replaceable in tests."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._jwk_client: PyJWKClient | None = None

    def _client(self) -> PyJWKClient:
        if self._jwk_client is None:
            if not self._settings.clerk_jwks_url:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="CLERK_JWKS_URL is not configured",
                )
            self._jwk_client = PyJWKClient(self._settings.clerk_jwks_url, cache_keys=True)
        return self._jwk_client

    def verify(self, token: str) -> AuthenticatedIdentity:
        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing bearer token",
            )
        try:
            signing_key = self._client().get_signing_key_from_jwt(token)
            decode_kwargs: dict[str, Any] = {
                "algorithms": ["RS256"],
                "options": {"require": ["exp", "iss", "sub"]},
            }
            if self._settings.clerk_issuer:
                decode_kwargs["issuer"] = self._settings.clerk_issuer
            claims = jwt.decode(token, signing_key.key, **decode_kwargs)
        except jwt.PyJWTError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token",
            ) from exc

        parties = self._settings.authorized_parties
        if parties:
            azp = claims.get("azp")
            if azp not in parties:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid authorized party",
                )

        sub = claims.get("sub")
        if not isinstance(sub, str) or not sub:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token missing subject",
            )

        return AuthenticatedIdentity(clerk_user_id=sub, claims=claims)


class StaticKeyTokenVerifier(TokenVerifier):
    """Test helper: verifies JWTs signed with a known PEM public key."""

    def __init__(
        self,
        settings: Settings,
        *,
        public_key_pem: str,
        algorithm: str = "RS256",
    ) -> None:
        super().__init__(settings)
        self._public_key_pem = public_key_pem
        self._algorithm = algorithm

    def verify(self, token: str) -> AuthenticatedIdentity:
        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing bearer token",
            )
        try:
            decode_kwargs: dict[str, Any] = {
                "algorithms": [self._algorithm],
                "options": {"require": ["exp", "iss", "sub"]},
            }
            if self._settings.clerk_issuer:
                decode_kwargs["issuer"] = self._settings.clerk_issuer
            claims = jwt.decode(token, self._public_key_pem, **decode_kwargs)
        except jwt.PyJWTError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token",
            ) from exc

        parties = self._settings.authorized_parties
        if parties:
            azp = claims.get("azp")
            if azp not in parties:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid authorized party",
                )

        sub = claims.get("sub")
        if not isinstance(sub, str) or not sub:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token missing subject",
            )

        return AuthenticatedIdentity(clerk_user_id=sub, claims=claims)


# Keep a small module-level clock helper for tests that freeze time indirectly.
def now_ts() -> int:
    return int(time.time())


async def fetch_jwks(url: str) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(url)
        response.raise_for_status()
        return response.json()
