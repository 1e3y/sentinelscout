from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

import httpx
from fastapi import HTTPException, status

from app.core.config import Settings


class CurrentAccessUnavailable(Exception):
    """Authoritative current org membership could not be verified (M38 fail-closed)."""


class FindingOwnershipPresenceUnavailable(Exception):
    """Authoritative membership presence for finding ownership could not be verified."""


class ClerkMembershipNotFound(Exception):
    """Authoritative organization membership is absent for the target user."""


class OrganizationAccessWriteUnavailable(Exception):
    """Definite inability to complete an organization-access provider write."""


class OrganizationAccessWriteAmbiguous(Exception):
    """Provider write outcome is ambiguous (timeout/5xx/connection after attempt)."""


class OrganizationInvitationUnavailable(Exception):
    """Definite inability to complete an organization-invitation provider operation."""


class OrganizationInvitationAmbiguous(Exception):
    """Invitation create outcome is ambiguous after the write was attempted."""


class OrganizationInvitationAlreadyMember(Exception):
    """Provider rejected create: email already belongs to an org member."""


class OrganizationInvitationDuplicatePending(Exception):
    """Provider rejected create: a pending invitation already exists for the email."""


class OrganizationInvitationNotFound(Exception):
    """Exact organization invitation was not found under the Clerk org."""


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


@dataclass(frozen=True)
class ClerkOrganizationMembershipRaw:
    """Read-only org membership row for access review (no email / no get_user)."""

    provider_user_id: str
    external_role: str | None
    first_name: str | None
    last_name: str | None


@dataclass(frozen=True)
class ClerkOrganizationInvitationRaw:
    """Organization invitation row for M40 (internal; never expose provider ids)."""

    provider_invitation_id: str
    email_address: str
    external_role: str | None
    status: str | None
    inviter_user_id: str | None
    created_at_ms: int | None
    expires_at_ms: int | None


@dataclass(frozen=True)
class ClerkInvitationMutationView:
    """Email-blind invitation view for M41 revoke verify/reconcile.

    Provider GET/revoke payloads may include email and other fields; the adapter
    projects only these fields before returning to service code.
    """

    provider_invitation_id: str
    status: str | None
    external_role: str | None


@dataclass(frozen=True)
class ClerkInvitationHistoryView:
    """Terminal invitation history row (M43).

    Full recipient email is converted to recipient_hint inside the adapter and
    never leaves this projection.
    """

    status: str
    external_role: str | None
    recipient_hint: str
    created_at_ms: int
    expires_at_ms: int | None


# Canonical provider terminal statuses for M43 "All terminal" (fixed order).
ORGANIZATION_INVITATION_TERMINAL_STATUSES: tuple[str, ...] = (
    "accepted",
    "revoked",
    "expired",
)


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

    def list_organization_memberships_raw(
        self,
        clerk_org_id: str,
        *,
        limit: int,
        offset: int,
    ) -> tuple[list[ClerkOrganizationMembershipRaw], int | None]: ...

    def get_organization_membership(
        self,
        clerk_org_id: str,
        clerk_user_id: str,
    ) -> ClerkOrganizationMembershipRaw: ...

    def list_organization_membership_presence(
        self,
        clerk_org_id: str,
        *,
        provider_user_ids: tuple[str, ...] | list[str],
    ) -> frozenset[str]: ...

    def update_organization_membership_role(
        self,
        clerk_org_id: str,
        clerk_user_id: str,
        *,
        role: str,
    ) -> ClerkOrganizationMembershipRaw: ...

    def delete_organization_membership(
        self,
        clerk_org_id: str,
        clerk_user_id: str,
    ) -> None: ...

    def list_organization_invitations(
        self,
        clerk_org_id: str,
        *,
        status: str | None = None,
        email_address: str | None = None,
        limit: int,
        offset: int,
    ) -> tuple[list[ClerkOrganizationInvitationRaw], int | None]: ...

    def list_organization_invitation_history(
        self,
        clerk_org_id: str,
        *,
        statuses: tuple[str, ...] | list[str],
        limit: int,
        offset: int,
    ) -> tuple[list[ClerkInvitationHistoryView], int]: ...

    def create_organization_invitation(
        self,
        clerk_org_id: str,
        *,
        email_address: str,
        role: str,
        inviter_user_id: str,
        notify: bool = True,
    ) -> ClerkOrganizationInvitationRaw: ...

    def get_organization_invitation(
        self,
        clerk_org_id: str,
        invitation_id: str,
    ) -> ClerkInvitationMutationView: ...

    def revoke_organization_invitation(
        self,
        clerk_org_id: str,
        invitation_id: str,
        *,
        requesting_user_id: str,
    ) -> ClerkInvitationMutationView: ...


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

    def list_organization_memberships_raw(
        self,
        clerk_org_id: str,
        *,
        limit: int,
        offset: int,
    ) -> tuple[list[ClerkOrganizationMembershipRaw], int | None]:
        """Strict read-only org memberships page (M38).

        Exactly one Backend API call. Never calls get_user. Never returns email.
        Any provider / config failure raises ``CurrentAccessUnavailable``.
        """
        if not self._settings.clerk_secret_key:
            raise CurrentAccessUnavailable()
        if not isinstance(clerk_org_id, str) or not clerk_org_id.strip():
            raise CurrentAccessUnavailable()
        if limit < 1 or offset < 0:
            raise CurrentAccessUnavailable()
        try:
            response = self._client.get(
                f"/organizations/{clerk_org_id}/organization_memberships",
                params={"limit": limit, "offset": offset},
            )
        except (httpx.TimeoutException, httpx.TransportError, httpx.HTTPError) as exc:
            raise CurrentAccessUnavailable() from exc
        if response.status_code >= 400:
            raise CurrentAccessUnavailable()
        try:
            payload = response.json()
        except ValueError as exc:
            raise CurrentAccessUnavailable() from exc
        if not isinstance(payload, dict):
            raise CurrentAccessUnavailable()
        items = payload.get("data", [])
        if not isinstance(items, list):
            raise CurrentAccessUnavailable()
        members: list[ClerkOrganizationMembershipRaw] = []
        for item in items:
            if not isinstance(item, dict):
                raise CurrentAccessUnavailable()
            public_user = item.get("public_user_data")
            if not isinstance(public_user, dict):
                raise CurrentAccessUnavailable()
            provider_user_id = public_user.get("user_id")
            if not isinstance(provider_user_id, str) or not provider_user_id:
                # Structurally unusable after pagination — fail the page, never drop.
                raise CurrentAccessUnavailable()
            role_raw = item.get("role")
            external_role = role_raw if isinstance(role_raw, str) else None
            first_raw = public_user.get("first_name")
            last_raw = public_user.get("last_name")
            first_name = first_raw.strip() if isinstance(first_raw, str) and first_raw.strip() else None
            last_name = last_raw.strip() if isinstance(last_raw, str) and last_raw.strip() else None
            members.append(
                ClerkOrganizationMembershipRaw(
                    provider_user_id=provider_user_id,
                    external_role=external_role,
                    first_name=first_name,
                    last_name=last_name,
                )
            )
        total_raw = payload.get("total_count")
        total: int | None
        if isinstance(total_raw, int) and total_raw >= 0:
            total = total_raw
        else:
            total = None
        return members, total

    def get_organization_membership(
        self,
        clerk_org_id: str,
        clerk_user_id: str,
    ) -> ClerkOrganizationMembershipRaw:
        """Authoritative single membership read (M39 verification / reconciliation)."""
        if not self._settings.clerk_secret_key:
            raise OrganizationAccessWriteUnavailable()
        if not isinstance(clerk_org_id, str) or not clerk_org_id.strip():
            raise OrganizationAccessWriteUnavailable()
        if not isinstance(clerk_user_id, str) or not clerk_user_id.strip():
            raise OrganizationAccessWriteUnavailable()
        try:
            response = self._client.get(
                f"/organizations/{clerk_org_id}/memberships/{clerk_user_id}"
            )
        except (httpx.TimeoutException, httpx.TransportError, httpx.HTTPError) as exc:
            raise OrganizationAccessWriteUnavailable() from exc
        if response.status_code == 404:
            raise ClerkMembershipNotFound()
        if response.status_code >= 400:
            raise OrganizationAccessWriteUnavailable()
        try:
            payload = response.json()
        except ValueError as exc:
            raise OrganizationAccessWriteUnavailable() from exc
        return self._parse_membership_payload(payload, expected_user_id=clerk_user_id)

    def list_organization_membership_presence(
        self,
        clerk_org_id: str,
        *,
        provider_user_ids: tuple[str, ...] | list[str],
    ) -> frozenset[str]:
        """Batch current-membership presence for M44 finding ownership review.

        Endpoint: GET /organizations/{organization_id}/memberships
        Wire: repeated ``user_id`` query params + ``limit=U`` + ``offset=0``.

        Returns only the set of requested provider user IDs that are currently
        members. Discards email/name/role/metadata/membership ids immediately.
        """
        if not self._settings.clerk_secret_key:
            raise FindingOwnershipPresenceUnavailable()
        if not isinstance(clerk_org_id, str) or not clerk_org_id.strip():
            raise FindingOwnershipPresenceUnavailable()
        requested = tuple(provider_user_ids)
        if not requested:
            return frozenset()
        if len(requested) > 100:
            raise FindingOwnershipPresenceUnavailable()
        requested_set: set[str] = set()
        for raw in requested:
            if not isinstance(raw, str) or not raw.strip():
                raise FindingOwnershipPresenceUnavailable()
            value = raw.strip()
            if value in requested_set:
                raise FindingOwnershipPresenceUnavailable()
            requested_set.add(value)
        # Canonical order for stable wire encoding.
        ordered = tuple(sorted(requested_set))
        limit = len(ordered)
        params: list[tuple[str, str | int]] = [
            ("limit", limit),
            ("offset", 0),
        ]
        for user_id in ordered:
            params.append(("user_id", user_id))
        try:
            response = self._client.get(
                f"/organizations/{clerk_org_id}/memberships",
                params=params,
            )
        except (httpx.TimeoutException, httpx.TransportError, httpx.HTTPError) as exc:
            raise FindingOwnershipPresenceUnavailable() from exc
        if response.status_code >= 400:
            raise FindingOwnershipPresenceUnavailable()
        try:
            payload = response.json()
        except ValueError as exc:
            raise FindingOwnershipPresenceUnavailable() from exc
        if not isinstance(payload, dict):
            raise FindingOwnershipPresenceUnavailable()
        items = payload.get("data", [])
        if not isinstance(items, list):
            raise FindingOwnershipPresenceUnavailable()
        if len(items) > limit:
            raise FindingOwnershipPresenceUnavailable()

        present: set[str] = set()
        for item in items:
            if not isinstance(item, dict):
                raise FindingOwnershipPresenceUnavailable()
            provider_user_id = self._membership_presence_user_id(item)
            if provider_user_id not in requested_set:
                raise FindingOwnershipPresenceUnavailable()
            if provider_user_id in present:
                raise FindingOwnershipPresenceUnavailable()
            present.add(provider_user_id)
        return frozenset(present)

    @staticmethod
    def _membership_presence_user_id(payload: dict) -> str:
        """Extract provider user id for presence only; ignore all other fields."""
        public_user = payload.get("public_user_data")
        if isinstance(public_user, dict):
            raw = public_user.get("user_id")
            if isinstance(raw, str) and raw.strip():
                return raw.strip()
        top = payload.get("user_id")
        if isinstance(top, str) and top.strip():
            return top.strip()
        raise FindingOwnershipPresenceUnavailable()

    def update_organization_membership_role(
        self,
        clerk_org_id: str,
        clerk_user_id: str,
        *,
        role: str,
    ) -> ClerkOrganizationMembershipRaw:
        """PATCH organization membership role (Clerk BAPI).

        Endpoint: PATCH /organizations/{organization_id}/memberships/{user_id}
        Body: {"role": "org:admin" | "org:member"}
        """
        if not self._settings.clerk_secret_key:
            raise OrganizationAccessWriteUnavailable()
        if not isinstance(clerk_org_id, str) or not clerk_org_id.strip():
            raise OrganizationAccessWriteUnavailable()
        if not isinstance(clerk_user_id, str) or not clerk_user_id.strip():
            raise OrganizationAccessWriteUnavailable()
        if not isinstance(role, str) or not role.strip():
            raise OrganizationAccessWriteUnavailable()
        try:
            response = self._client.patch(
                f"/organizations/{clerk_org_id}/memberships/{clerk_user_id}",
                json={"role": role},
            )
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            raise OrganizationAccessWriteAmbiguous() from exc
        except httpx.HTTPError as exc:
            raise OrganizationAccessWriteAmbiguous() from exc
        if response.status_code == 404:
            raise ClerkMembershipNotFound()
        if response.status_code >= 500:
            raise OrganizationAccessWriteAmbiguous()
        if response.status_code >= 400:
            # Definite client/validation rejection — treat as no successful mutation.
            raise OrganizationAccessWriteUnavailable()
        try:
            payload = response.json()
        except ValueError as exc:
            # Response may still have applied; reconcile via re-read.
            raise OrganizationAccessWriteAmbiguous() from exc
        return self._parse_membership_payload(payload, expected_user_id=clerk_user_id)

    def delete_organization_membership(
        self,
        clerk_org_id: str,
        clerk_user_id: str,
    ) -> None:
        """DELETE organization membership (Clerk BAPI).

        Endpoint: DELETE /organizations/{organization_id}/memberships/{user_id}
        """
        if not self._settings.clerk_secret_key:
            raise OrganizationAccessWriteUnavailable()
        if not isinstance(clerk_org_id, str) or not clerk_org_id.strip():
            raise OrganizationAccessWriteUnavailable()
        if not isinstance(clerk_user_id, str) or not clerk_user_id.strip():
            raise OrganizationAccessWriteUnavailable()
        try:
            response = self._client.delete(
                f"/organizations/{clerk_org_id}/memberships/{clerk_user_id}"
            )
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            raise OrganizationAccessWriteAmbiguous() from exc
        except httpx.HTTPError as exc:
            raise OrganizationAccessWriteAmbiguous() from exc
        if response.status_code == 404:
            raise ClerkMembershipNotFound()
        if response.status_code >= 500:
            raise OrganizationAccessWriteAmbiguous()
        if response.status_code >= 400:
            raise OrganizationAccessWriteUnavailable()
        # 200/204 success — no body required.

    @staticmethod
    def _parse_membership_payload(
        payload: object,
        *,
        expected_user_id: str,
    ) -> ClerkOrganizationMembershipRaw:
        if not isinstance(payload, dict):
            raise OrganizationAccessWriteUnavailable()
        public_user = payload.get("public_user_data")
        if not isinstance(public_user, dict):
            # Some responses nest user under `public_user_data`; role is top-level.
            provider_user_id = payload.get("user_id")
            if not isinstance(provider_user_id, str) or not provider_user_id:
                raise OrganizationAccessWriteUnavailable()
            role_raw = payload.get("role")
            external_role = role_raw if isinstance(role_raw, str) else None
            if provider_user_id != expected_user_id:
                raise OrganizationAccessWriteUnavailable()
            return ClerkOrganizationMembershipRaw(
                provider_user_id=provider_user_id,
                external_role=external_role,
                first_name=None,
                last_name=None,
            )
        provider_user_id = public_user.get("user_id")
        if not isinstance(provider_user_id, str) or not provider_user_id:
            raise OrganizationAccessWriteUnavailable()
        if provider_user_id != expected_user_id:
            raise OrganizationAccessWriteUnavailable()
        role_raw = payload.get("role")
        external_role = role_raw if isinstance(role_raw, str) else None
        first_raw = public_user.get("first_name")
        last_raw = public_user.get("last_name")
        first_name = first_raw.strip() if isinstance(first_raw, str) and first_raw.strip() else None
        last_name = last_raw.strip() if isinstance(last_raw, str) and last_raw.strip() else None
        return ClerkOrganizationMembershipRaw(
            provider_user_id=provider_user_id,
            external_role=external_role,
            first_name=first_name,
            last_name=last_name,
        )

    def list_organization_invitations(
        self,
        clerk_org_id: str,
        *,
        status: str | None = None,
        email_address: str | None = None,
        limit: int,
        offset: int,
    ) -> tuple[list[ClerkOrganizationInvitationRaw], int | None]:
        """List organization invitations (M40).

        Endpoint: GET /organizations/{organization_id}/invitations
        """
        if not self._settings.clerk_secret_key:
            raise OrganizationInvitationUnavailable()
        if not isinstance(clerk_org_id, str) or not clerk_org_id.strip():
            raise OrganizationInvitationUnavailable()
        if limit < 1 or offset < 0:
            raise OrganizationInvitationUnavailable()
        params: dict[str, str | int] = {"limit": limit, "offset": offset}
        if status is not None:
            params["status"] = status
        if email_address is not None:
            params["email_address"] = email_address
        try:
            response = self._client.get(
                f"/organizations/{clerk_org_id}/invitations",
                params=params,
            )
        except (httpx.TimeoutException, httpx.TransportError, httpx.HTTPError) as exc:
            raise OrganizationInvitationUnavailable() from exc
        if response.status_code >= 400:
            raise OrganizationInvitationUnavailable()
        try:
            payload = response.json()
        except ValueError as exc:
            raise OrganizationInvitationUnavailable() from exc
        if not isinstance(payload, dict):
            raise OrganizationInvitationUnavailable()
        items = payload.get("data", [])
        if not isinstance(items, list):
            raise OrganizationInvitationUnavailable()
        invitations: list[ClerkOrganizationInvitationRaw] = []
        for item in items:
            invitations.append(self._parse_invitation_payload(item))
        total_raw = payload.get("total_count")
        total: int | None
        if isinstance(total_raw, int) and total_raw >= 0:
            total = total_raw
        else:
            total = None
        return invitations, total

    def list_organization_invitation_history(
        self,
        clerk_org_id: str,
        *,
        statuses: tuple[str, ...] | list[str],
        limit: int,
        offset: int,
    ) -> tuple[list[ClerkInvitationHistoryView], int]:
        """List terminal organization invitations (M43).

        Endpoint: GET /organizations/{organization_id}/invitations
        Multi-status filter uses repeated ``status`` query parameters (Clerk
        documented multi-value filter), never comma-joined or unfiltered fetch.
        """
        if not self._settings.clerk_secret_key:
            raise OrganizationInvitationUnavailable()
        if not isinstance(clerk_org_id, str) or not clerk_org_id.strip():
            raise OrganizationInvitationUnavailable()
        if limit < 1 or offset < 0:
            raise OrganizationInvitationUnavailable()
        status_values = tuple(statuses)
        if not status_values:
            raise OrganizationInvitationUnavailable()
        for value in status_values:
            if not isinstance(value, str) or not value.strip():
                raise OrganizationInvitationUnavailable()
        # Repeated status=… query params — the documented multi-value encoding.
        params: list[tuple[str, str | int]] = [
            ("limit", limit),
            ("offset", offset),
        ]
        for value in status_values:
            params.append(("status", value))
        try:
            response = self._client.get(
                f"/organizations/{clerk_org_id}/invitations",
                params=params,
            )
        except (httpx.TimeoutException, httpx.TransportError, httpx.HTTPError) as exc:
            raise OrganizationInvitationUnavailable() from exc
        if response.status_code >= 400:
            raise OrganizationInvitationUnavailable()
        try:
            payload = response.json()
        except ValueError as exc:
            raise OrganizationInvitationUnavailable() from exc
        if not isinstance(payload, dict):
            raise OrganizationInvitationUnavailable()
        items = payload.get("data", [])
        if not isinstance(items, list):
            raise OrganizationInvitationUnavailable()
        total_raw = payload.get("total_count")
        if not isinstance(total_raw, int) or isinstance(total_raw, bool) or total_raw < 0:
            raise OrganizationInvitationUnavailable()
        history: list[ClerkInvitationHistoryView] = []
        for item in items:
            history.append(self._parse_invitation_history_view(item))
        return history, total_raw

    def create_organization_invitation(
        self,
        clerk_org_id: str,
        *,
        email_address: str,
        role: str,
        inviter_user_id: str,
        notify: bool = True,
    ) -> ClerkOrganizationInvitationRaw:
        """Create organization invitation (M40).

        Endpoint: POST /organizations/{organization_id}/invitations
        Body includes notify=true explicitly (provider-owned email delivery).
        """
        if not self._settings.clerk_secret_key:
            raise OrganizationInvitationUnavailable()
        if not isinstance(clerk_org_id, str) or not clerk_org_id.strip():
            raise OrganizationInvitationUnavailable()
        if not isinstance(email_address, str) or not email_address.strip():
            raise OrganizationInvitationUnavailable()
        if not isinstance(role, str) or not role.strip():
            raise OrganizationInvitationUnavailable()
        if not isinstance(inviter_user_id, str) or not inviter_user_id.strip():
            raise OrganizationInvitationUnavailable()
        body = {
            "email_address": email_address,
            "role": role,
            "inviter_user_id": inviter_user_id,
            "notify": bool(notify),
        }
        try:
            response = self._client.post(
                f"/organizations/{clerk_org_id}/invitations",
                json=body,
            )
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            raise OrganizationInvitationAmbiguous() from exc
        except httpx.HTTPError as exc:
            raise OrganizationInvitationAmbiguous() from exc
        if response.status_code >= 500:
            raise OrganizationInvitationAmbiguous()
        if response.status_code >= 400:
            self._raise_invitation_create_error(response)
        try:
            payload = response.json()
        except ValueError as exc:
            raise OrganizationInvitationAmbiguous() from exc
        return self._parse_invitation_payload(payload)

    def _raise_invitation_create_error(self, response: httpx.Response) -> None:
        """Map only exact documented business codes; everything else → unavailable."""
        codes: set[str] = set()
        try:
            payload = response.json()
        except ValueError:
            raise OrganizationInvitationUnavailable() from None
        if isinstance(payload, dict):
            errors = payload.get("errors")
            if isinstance(errors, list):
                for err in errors:
                    if isinstance(err, dict):
                        code = err.get("code")
                        if isinstance(code, str) and code:
                            codes.add(code)
            # Some responses surface a single code at the top level.
            top = payload.get("code")
            if isinstance(top, str) and top:
                codes.add(top)
        if "already_a_member_in_organization" in codes:
            raise OrganizationInvitationAlreadyMember()
        if "organization_invitation_not_unique" in codes or "duplicate_record" in codes:
            raise OrganizationInvitationDuplicatePending()
        raise OrganizationInvitationUnavailable()

    @staticmethod
    def _parse_invitation_payload(payload: object) -> ClerkOrganizationInvitationRaw:
        if not isinstance(payload, dict):
            raise OrganizationInvitationUnavailable()
        invitation_id = payload.get("id")
        if not isinstance(invitation_id, str) or not invitation_id:
            raise OrganizationInvitationUnavailable()
        email_raw = payload.get("email_address")
        if not isinstance(email_raw, str) or not email_raw:
            raise OrganizationInvitationUnavailable()
        role_raw = payload.get("role")
        external_role = role_raw if isinstance(role_raw, str) else None
        status_raw = payload.get("status")
        status_value = status_raw if isinstance(status_raw, str) else None
        inviter = payload.get("inviter_user_id")
        if inviter is None:
            inviter = payload.get("inviter_id")
        inviter_user_id = inviter if isinstance(inviter, str) and inviter else None
        created_at_ms = _coerce_unix_ms(payload.get("created_at"))
        expires_at_ms = _coerce_unix_ms(payload.get("expires_at"))
        return ClerkOrganizationInvitationRaw(
            provider_invitation_id=invitation_id,
            email_address=email_raw,
            external_role=external_role,
            status=status_value,
            inviter_user_id=inviter_user_id,
            created_at_ms=created_at_ms,
            expires_at_ms=expires_at_ms,
        )

    def get_organization_invitation(
        self,
        clerk_org_id: str,
        invitation_id: str,
    ) -> ClerkInvitationMutationView:
        """Fetch one organization invitation (M41 verify/reconcile).

        Endpoint: GET /organizations/{organization_id}/invitations/{invitation_id}
        """
        if not self._settings.clerk_secret_key:
            raise OrganizationInvitationUnavailable()
        if not isinstance(clerk_org_id, str) or not clerk_org_id.strip():
            raise OrganizationInvitationUnavailable()
        if not isinstance(invitation_id, str) or not invitation_id.strip():
            raise OrganizationInvitationUnavailable()
        try:
            response = self._client.get(
                f"/organizations/{clerk_org_id}/invitations/{invitation_id}",
            )
        except (httpx.TimeoutException, httpx.TransportError, httpx.HTTPError) as exc:
            raise OrganizationInvitationUnavailable() from exc
        if response.status_code == 404:
            raise OrganizationInvitationNotFound()
        if response.status_code >= 400:
            raise OrganizationInvitationUnavailable()
        try:
            payload = response.json()
        except ValueError as exc:
            raise OrganizationInvitationUnavailable() from exc
        return self._parse_invitation_mutation_view(payload)

    def revoke_organization_invitation(
        self,
        clerk_org_id: str,
        invitation_id: str,
        *,
        requesting_user_id: str,
    ) -> ClerkInvitationMutationView:
        """Revoke one organization invitation (M41).

        Endpoint: POST /organizations/{organization_id}/invitations/{invitation_id}/revoke
        Body: requesting_user_id (current actor Clerk user id).
        """
        if not self._settings.clerk_secret_key:
            raise OrganizationInvitationUnavailable()
        if not isinstance(clerk_org_id, str) or not clerk_org_id.strip():
            raise OrganizationInvitationUnavailable()
        if not isinstance(invitation_id, str) or not invitation_id.strip():
            raise OrganizationInvitationUnavailable()
        if not isinstance(requesting_user_id, str) or not requesting_user_id.strip():
            raise OrganizationInvitationUnavailable()
        body = {"requesting_user_id": requesting_user_id}
        try:
            response = self._client.post(
                f"/organizations/{clerk_org_id}/invitations/{invitation_id}/revoke",
                json=body,
            )
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            raise OrganizationInvitationAmbiguous() from exc
        except httpx.HTTPError as exc:
            raise OrganizationInvitationAmbiguous() from exc
        if response.status_code >= 500:
            raise OrganizationInvitationAmbiguous()
        # Unexpected absence after a successful pending precheck → reconcile once.
        if response.status_code == 404:
            raise OrganizationInvitationAmbiguous()
        if response.status_code >= 400:
            raise OrganizationInvitationUnavailable()
        try:
            payload = response.json()
        except ValueError as exc:
            raise OrganizationInvitationAmbiguous() from exc
        return self._parse_invitation_mutation_view(payload)

    @staticmethod
    def _parse_invitation_mutation_view(payload: object) -> ClerkInvitationMutationView:
        """Project provider invitation payload to an email-blind mutation view."""
        if not isinstance(payload, dict):
            raise OrganizationInvitationUnavailable()
        invitation_id = payload.get("id")
        if not isinstance(invitation_id, str) or not invitation_id:
            raise OrganizationInvitationUnavailable()
        role_raw = payload.get("role")
        external_role = role_raw if isinstance(role_raw, str) else None
        status_raw = payload.get("status")
        status_value = status_raw if isinstance(status_raw, str) else None
        return ClerkInvitationMutationView(
            provider_invitation_id=invitation_id,
            status=status_value,
            external_role=external_role,
        )

    @staticmethod
    def _history_recipient_hint(email_raw: str) -> str:
        """Validate mailbox and emit M40-compatible recipient_hint; discard email."""
        from email_validator import EmailNotValidError, validate_email

        if not isinstance(email_raw, str) or not email_raw.strip():
            raise OrganizationInvitationUnavailable()
        try:
            canonical = str(
                validate_email(email_raw.strip(), check_deliverability=False).normalized
            )
        except EmailNotValidError as exc:
            raise OrganizationInvitationUnavailable() from exc
        if "@" not in canonical:
            raise OrganizationInvitationUnavailable()
        local, _, domain = canonical.partition("@")
        if not local or not domain:
            raise OrganizationInvitationUnavailable()
        return f"{local[0]}***@{domain}"

    @classmethod
    def _parse_invitation_history_view(cls, payload: object) -> ClerkInvitationHistoryView:
        """Project provider invitation to hint-only history view (no email retained)."""
        if not isinstance(payload, dict):
            raise OrganizationInvitationUnavailable()
        status_raw = payload.get("status")
        if not isinstance(status_raw, str) or not status_raw.strip():
            raise OrganizationInvitationUnavailable()
        status_value = status_raw.strip().lower()
        role_raw = payload.get("role")
        external_role = role_raw if isinstance(role_raw, str) else None
        email_raw = payload.get("email_address")
        if not isinstance(email_raw, str):
            raise OrganizationInvitationUnavailable()
        recipient_hint = cls._history_recipient_hint(email_raw)
        created_at_ms = _coerce_unix_ms(payload.get("created_at"))
        if created_at_ms is None:
            raise OrganizationInvitationUnavailable()
        expires_at_ms = _coerce_unix_ms(payload.get("expires_at"))
        return ClerkInvitationHistoryView(
            status=status_value,
            external_role=external_role,
            recipient_hint=recipient_hint,
            created_at_ms=created_at_ms,
            expires_at_ms=expires_at_ms,
        )


def _coerce_unix_ms(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    return None


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
