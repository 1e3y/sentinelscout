from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

import httpx
from fastapi import HTTPException, status

from app.core.config import Settings


@dataclass(frozen=True)
class ClerkUserInfo:
    clerk_user_id: str
    email: str
    name: str | None
    email_verified: bool = False


@dataclass(frozen=True)
class ClerkOrgMembership:
    clerk_org_id: str
    org_name: str
    role: str


@dataclass(frozen=True)
class ClerkOrganizationMember:
    """One member of a Clerk organization (org-scoped directory row)."""

    clerk_user_id: str
    email: str
    name: str | None
    email_verified: bool = False


class ClerkDirectory(Protocol):
    def get_user(self, clerk_user_id: str) -> ClerkUserInfo: ...

    def list_organization_memberships(self, clerk_user_id: str) -> list[ClerkOrgMembership]: ...

    def list_organization_members(
        self,
        clerk_org_id: str,
        *,
        limit: int,
        offset: int,
    ) -> tuple[list[ClerkOrganizationMember], int]: ...


class HttpClerkDirectory:
    """Fetches user and membership data from Clerk Backend API (source of truth)."""

    def __init__(self, settings: Settings, client: httpx.Client | None = None) -> None:
        self._settings = settings
        self._owns_client = client is None
        self._client = client or httpx.Client(
            base_url=settings.clerk_api_base_url.rstrip("/"),
            headers={"Authorization": f"Bearer {settings.clerk_secret_key}"},
            timeout=15.0,
        )

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def get_user(self, clerk_user_id: str) -> ClerkUserInfo:
        if not self._settings.clerk_secret_key:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="CLERK_SECRET_KEY is not configured",
            )
        response = self._client.get(f"/users/{clerk_user_id}")
        if response.status_code == 404:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found in Clerk",
            )
        if response.status_code >= 400:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Failed to fetch user from Clerk",
            )
        data = response.json()
        email, email_verified = primary_email_info(data)
        name = _display_name(data)
        return ClerkUserInfo(
            clerk_user_id=clerk_user_id,
            email=email,
            name=name,
            email_verified=email_verified,
        )

    def list_organization_memberships(self, clerk_user_id: str) -> list[ClerkOrgMembership]:
        if not self._settings.clerk_secret_key:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="CLERK_SECRET_KEY is not configured",
            )
        response = self._client.get(
            f"/users/{clerk_user_id}/organization_memberships",
            params={"limit": 100},
        )
        if response.status_code >= 400:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Failed to fetch organization memberships from Clerk",
            )
        payload = response.json()
        items = payload.get("data", payload if isinstance(payload, list) else [])
        memberships: list[ClerkOrgMembership] = []
        for item in items:
            org = item.get("organization") or {}
            clerk_org_id = org.get("id")
            org_name = org.get("name") or "Unnamed organization"
            role = item.get("role") or "org:member"
            if isinstance(clerk_org_id, str) and clerk_org_id:
                memberships.append(
                    ClerkOrgMembership(
                        clerk_org_id=clerk_org_id,
                        org_name=org_name,
                        role=role,
                    )
                )
        return memberships

    def list_organization_members(
        self,
        clerk_org_id: str,
        *,
        limit: int,
        offset: int,
    ) -> tuple[list[ClerkOrganizationMember], int]:
        """Authoritative org roster from Clerk Backend API (paginated)."""
        if not self._settings.clerk_secret_key:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="CLERK_SECRET_KEY is not configured",
            )
        if limit < 1 or offset < 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid organization member page",
            )
        response = self._client.get(
            f"/organizations/{clerk_org_id}/organization_memberships",
            params={"limit": limit, "offset": offset},
        )
        if response.status_code >= 400:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Failed to fetch organization members from Clerk",
            )
        payload = response.json()
        items = payload.get("data", payload if isinstance(payload, list) else [])
        total_raw = payload.get("total_count")
        members: list[ClerkOrganizationMember] = []
        for item in items:
            public_user = item.get("public_user_data") or {}
            clerk_user_id = public_user.get("user_id")
            if not isinstance(clerk_user_id, str) or not clerk_user_id:
                continue
            identifier = public_user.get("identifier")
            email = identifier if isinstance(identifier, str) and identifier else None
            if email is None:
                # Identifier missing: fall back to full user fetch for required email.
                info = self.get_user(clerk_user_id)
                members.append(
                    ClerkOrganizationMember(
                        clerk_user_id=info.clerk_user_id,
                        email=info.email,
                        name=info.name,
                        email_verified=info.email_verified,
                    )
                )
                continue
            first = public_user.get("first_name") or ""
            last = public_user.get("last_name") or ""
            full = f"{first} {last}".strip()
            name = full or None
            members.append(
                ClerkOrganizationMember(
                    clerk_user_id=clerk_user_id,
                    email=email,
                    name=name,
                    email_verified=False,
                )
            )
        if isinstance(total_raw, int) and total_raw >= 0:
            total = total_raw
        else:
            total = offset + len(members)
        return members, total


def primary_email_info(data: dict) -> tuple[str, bool]:
    """Return (email, verified). Unverified unless Clerk status is explicitly verified."""
    addresses = data.get("email_addresses") or []
    primary_id = data.get("primary_email_address_id")
    chosen: dict | None = None
    for addr in addresses:
        if addr.get("id") == primary_id and addr.get("email_address"):
            chosen = addr
            break
    if chosen is None:
        for addr in addresses:
            if addr.get("email_address"):
                chosen = addr
                break
    if chosen is None:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Clerk user has no email address",
        )
    return str(chosen["email_address"]), _email_is_verified(chosen)


def _email_is_verified(addr: dict) -> bool:
    verification = addr.get("verification")
    if isinstance(verification, dict):
        status_value = verification.get("status")
        if isinstance(status_value, str) and status_value.strip().lower() == "verified":
            return True
        return False
    return False


def _display_name(data: dict) -> str | None:
    first = data.get("first_name") or ""
    last = data.get("last_name") or ""
    full = f"{first} {last}".strip()
    if full:
        return full
    username = data.get("username")
    if isinstance(username, str) and username:
        return username
    return None
