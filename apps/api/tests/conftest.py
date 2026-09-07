from __future__ import annotations

import os
import time
import uuid
from collections.abc import Generator
from dataclasses import dataclass, field

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

os.environ["ENVIRONMENT"] = "test"
os.environ["DATABASE_URL"] = os.environ.get(
    "DATABASE_URL",
    "postgresql+psycopg://scout:scout@localhost:5432/scout",
)
os.environ["CLERK_ISSUER"] = "https://clerk.test"
os.environ["CLERK_JWKS_URL"] = "https://clerk.test/.well-known/jwks.json"
os.environ["CLERK_SECRET_KEY"] = "sk_test_dummy"
os.environ["CLERK_AUTHORIZED_PARTIES"] = "http://localhost:3000"
os.environ["FRONTEND_URL"] = "http://localhost:3000"
os.environ["CORS_ALLOWED_ORIGINS"] = "http://localhost:3000"
os.environ["API_CORS_ORIGINS"] = "http://localhost:3000"
os.environ["LOG_LEVEL"] = "WARNING"
os.environ.setdefault(
    "REPORT_DELIVERY_SECRET_KEY",
    "aa" * 32,
)

from app.core.config import get_settings, reset_settings_cache
from app.core.db import Base, get_db
from app.core.security import StaticKeyTokenVerifier
from app.main import create_app
from app.services.clerk import (
    ClerkMembershipNotFound,
    ClerkOrgMembership,
    ClerkOrganizationInvitationRaw,
    ClerkOrganizationMember,
    ClerkOrganizationMembershipRaw,
    ClerkUserInfo,
    CurrentAccessUnavailable,
    OrganizationAccessWriteAmbiguous,
    OrganizationAccessWriteUnavailable,
    OrganizationInvitationAlreadyMember,
    OrganizationInvitationAmbiguous,
    OrganizationInvitationDuplicatePending,
    OrganizationInvitationUnavailable,
)
from app.services.dns import StaticDnsTxtResolver

reset_settings_cache()


@dataclass
class FakeClerkDirectory:
    users: dict[str, ClerkUserInfo] = field(default_factory=dict)
    memberships: dict[str, list[ClerkOrgMembership]] = field(default_factory=dict)
    invitations: dict[str, list[ClerkOrganizationInvitationRaw]] = field(default_factory=dict)
    fail_get_user: bool = False
    fail_memberships: bool = False
    fail_org_memberships_raw: bool = False
    fail_get_membership: bool = False
    fail_list_invitations: bool = False
    # None | "non_pending" | "missing_created_at"
    list_invitations_corrupt: str | None = None
    # None | "unavailable" | "ambiguous" | "ambiguous_applied" |
    # "ambiguous_applied_other_inviter" | "ambiguous_applied_stale" |
    # "already_member" | "duplicate"
    create_invitation_mode: str | None = None
    # None | "unavailable" | "ambiguous" | "ambiguous_applied"
    update_role_mode: str | None = None
    # None | "unavailable" | "ambiguous" | "ambiguous_applied"
    delete_membership_mode: str | None = None
    get_user_calls: int = 0
    memberships_raw_calls: int = 0
    list_organization_members_calls: int = 0
    get_membership_calls: int = 0
    update_role_calls: int = 0
    delete_membership_calls: int = 0
    list_invitations_calls: int = 0
    create_invitation_calls: int = 0
    _invitation_seq: int = 0

    def get_user(self, clerk_user_id: str) -> ClerkUserInfo:
        self.get_user_calls += 1
        if self.fail_get_user:
            from fastapi import HTTPException, status

            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Failed to fetch user from Clerk",
            )
        return self.users[clerk_user_id]

    def list_organization_memberships(self, clerk_user_id: str) -> list[ClerkOrgMembership]:
        if self.fail_memberships:
            from fastapi import HTTPException, status

            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Failed to fetch organization memberships from Clerk",
            )
        return list(self.memberships.get(clerk_user_id, []))

    def list_organization_members(
        self,
        clerk_org_id: str,
        *,
        limit: int,
        offset: int,
    ) -> tuple[list[ClerkOrganizationMember], int]:
        """Derive org roster from the same membership map used for assignability."""
        self.list_organization_members_calls += 1
        members: list[ClerkOrganizationMember] = []
        for clerk_user_id, rows in self.memberships.items():
            if not any(row.clerk_org_id == clerk_org_id for row in rows):
                continue
            info = self.users[clerk_user_id]
            members.append(
                ClerkOrganizationMember(
                    clerk_user_id=info.clerk_user_id,
                    email=info.email,
                    name=info.name,
                    email_verified=info.email_verified,
                )
            )
        members.sort(key=lambda row: row.clerk_user_id)
        total = len(members)
        if limit < 1 or offset < 0:
            return [], total
        return members[offset : offset + limit], total

    def list_organization_memberships_raw(
        self,
        clerk_org_id: str,
        *,
        limit: int,
        offset: int,
    ) -> tuple[list[ClerkOrganizationMembershipRaw], int | None]:
        """Read-only org memberships page (M38). Never calls get_user."""
        self.memberships_raw_calls += 1
        if self.fail_org_memberships_raw:
            raise CurrentAccessUnavailable()
        members: list[ClerkOrganizationMembershipRaw] = []
        for clerk_user_id, rows in self.memberships.items():
            match = next((row for row in rows if row.clerk_org_id == clerk_org_id), None)
            if match is None:
                continue
            info = self.users.get(clerk_user_id)
            first_name: str | None = None
            last_name: str | None = None
            if info is not None and info.name:
                parts = info.name.split(None, 1)
                first_name = parts[0] if parts else None
                last_name = parts[1] if len(parts) > 1 else None
            members.append(
                ClerkOrganizationMembershipRaw(
                    provider_user_id=clerk_user_id,
                    external_role=match.role,
                    first_name=first_name,
                    last_name=last_name,
                )
            )
        members.sort(key=lambda row: row.provider_user_id)
        total = len(members)
        if limit < 1 or offset < 0:
            raise CurrentAccessUnavailable()
        return members[offset : offset + limit], total

    def _raw_for(self, clerk_org_id: str, clerk_user_id: str) -> ClerkOrganizationMembershipRaw:
        match = next(
            (
                row
                for row in self.memberships.get(clerk_user_id, [])
                if row.clerk_org_id == clerk_org_id
            ),
            None,
        )
        if match is None:
            raise ClerkMembershipNotFound()
        info = self.users.get(clerk_user_id)
        first_name: str | None = None
        last_name: str | None = None
        if info is not None and info.name:
            parts = info.name.split(None, 1)
            first_name = parts[0] if parts else None
            last_name = parts[1] if len(parts) > 1 else None
        return ClerkOrganizationMembershipRaw(
            provider_user_id=clerk_user_id,
            external_role=match.role,
            first_name=first_name,
            last_name=last_name,
        )

    def get_organization_membership(
        self,
        clerk_org_id: str,
        clerk_user_id: str,
    ) -> ClerkOrganizationMembershipRaw:
        self.get_membership_calls += 1
        if self.fail_get_membership:
            raise OrganizationAccessWriteUnavailable()
        return self._raw_for(clerk_org_id, clerk_user_id)

    def update_organization_membership_role(
        self,
        clerk_org_id: str,
        clerk_user_id: str,
        *,
        role: str,
    ) -> ClerkOrganizationMembershipRaw:
        self.update_role_calls += 1
        mode = self.update_role_mode
        if mode == "unavailable":
            raise OrganizationAccessWriteUnavailable()
        if mode == "ambiguous":
            raise OrganizationAccessWriteAmbiguous()
        if mode == "ambiguous_applied":
            rows = self.memberships.get(clerk_user_id, [])
            for index, row in enumerate(rows):
                if row.clerk_org_id == clerk_org_id:
                    rows[index] = ClerkOrgMembership(
                        clerk_org_id=row.clerk_org_id,
                        org_name=row.org_name,
                        role=role,
                    )
                    break
            else:
                raise ClerkMembershipNotFound()
            raise OrganizationAccessWriteAmbiguous()
        rows = self.memberships.get(clerk_user_id, [])
        for index, row in enumerate(rows):
            if row.clerk_org_id == clerk_org_id:
                rows[index] = ClerkOrgMembership(
                    clerk_org_id=row.clerk_org_id,
                    org_name=row.org_name,
                    role=role,
                )
                return self._raw_for(clerk_org_id, clerk_user_id)
        raise ClerkMembershipNotFound()

    def delete_organization_membership(
        self,
        clerk_org_id: str,
        clerk_user_id: str,
    ) -> None:
        self.delete_membership_calls += 1
        mode = self.delete_membership_mode
        if mode == "unavailable":
            raise OrganizationAccessWriteUnavailable()
        if mode == "ambiguous":
            raise OrganizationAccessWriteAmbiguous()
        if mode == "ambiguous_applied":
            rows = self.memberships.get(clerk_user_id, [])
            remaining = [row for row in rows if row.clerk_org_id != clerk_org_id]
            if len(remaining) == len(rows):
                raise ClerkMembershipNotFound()
            self.memberships[clerk_user_id] = remaining
            raise OrganizationAccessWriteAmbiguous()
        rows = self.memberships.get(clerk_user_id, [])
        remaining = [row for row in rows if row.clerk_org_id != clerk_org_id]
        if len(remaining) == len(rows):
            raise ClerkMembershipNotFound()
        self.memberships[clerk_user_id] = remaining

    def list_organization_invitations(
        self,
        clerk_org_id: str,
        *,
        status: str | None = None,
        email_address: str | None = None,
        limit: int,
        offset: int,
    ) -> tuple[list[ClerkOrganizationInvitationRaw], int | None]:
        self.list_invitations_calls += 1
        if self.fail_list_invitations:
            raise OrganizationInvitationUnavailable()
        if limit < 1 or offset < 0:
            raise OrganizationInvitationUnavailable()
        rows = list(self.invitations.get(clerk_org_id, []))
        if status is not None:
            rows = [row for row in rows if row.status == status]
        if email_address is not None:
            rows = [row for row in rows if row.email_address == email_address]
        rows.sort(
            key=lambda row: row.created_at_ms if row.created_at_ms is not None else 0,
            reverse=True,
        )
        if self.list_invitations_corrupt == "non_pending" and rows:
            bad = rows[0]
            rows[0] = ClerkOrganizationInvitationRaw(
                provider_invitation_id=bad.provider_invitation_id,
                email_address=bad.email_address,
                external_role=bad.external_role,
                status="accepted",
                inviter_user_id=bad.inviter_user_id,
                created_at_ms=bad.created_at_ms,
                expires_at_ms=bad.expires_at_ms,
            )
        elif self.list_invitations_corrupt == "missing_created_at" and rows:
            bad = rows[0]
            rows[0] = ClerkOrganizationInvitationRaw(
                provider_invitation_id=bad.provider_invitation_id,
                email_address=bad.email_address,
                external_role=bad.external_role,
                status=bad.status,
                inviter_user_id=bad.inviter_user_id,
                created_at_ms=None,
                expires_at_ms=bad.expires_at_ms,
            )
        total = len(rows)
        return rows[offset : offset + limit], total

    def create_organization_invitation(
        self,
        clerk_org_id: str,
        *,
        email_address: str,
        role: str,
        inviter_user_id: str,
        notify: bool = True,
    ) -> ClerkOrganizationInvitationRaw:
        self.create_invitation_calls += 1
        assert notify is True
        mode = self.create_invitation_mode
        if mode == "unavailable":
            raise OrganizationInvitationUnavailable()
        if mode == "already_member":
            raise OrganizationInvitationAlreadyMember()
        if mode == "duplicate":
            raise OrganizationInvitationDuplicatePending()
        if mode == "ambiguous":
            raise OrganizationInvitationAmbiguous()

        from datetime import datetime, timezone

        now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
        self._invitation_seq += 1
        effective_inviter = inviter_user_id
        created_ms = now_ms
        if mode == "ambiguous_applied_other_inviter":
            effective_inviter = f"user_other_{uuid.uuid4().hex[:8]}"
        if mode == "ambiguous_applied_stale":
            created_ms = now_ms - (7 * 24 * 60 * 60 * 1000)

        invitation = ClerkOrganizationInvitationRaw(
            provider_invitation_id=f"inv_{self._invitation_seq}_{uuid.uuid4().hex[:8]}",
            email_address=email_address,
            external_role=role,
            status="pending",
            inviter_user_id=effective_inviter,
            created_at_ms=created_ms,
            expires_at_ms=now_ms + 30 * 24 * 60 * 60 * 1000,
        )
        if mode in {
            "ambiguous_applied",
            "ambiguous_applied_other_inviter",
            "ambiguous_applied_stale",
        }:
            self.invitations.setdefault(clerk_org_id, []).append(invitation)
            raise OrganizationInvitationAmbiguous()

        # Simulate provider uniqueness for pending same email.
        existing = self.invitations.get(clerk_org_id, [])
        if any(
            row.email_address == email_address and row.status == "pending"
            for row in existing
        ):
            raise OrganizationInvitationDuplicatePending()
        # Simulate already-member when membership email matches a FakeClerk user email.
        for clerk_user_id, memberships in self.memberships.items():
            if not any(m.clerk_org_id == clerk_org_id for m in memberships):
                continue
            info = self.users.get(clerk_user_id)
            if info is not None and info.email == email_address:
                raise OrganizationInvitationAlreadyMember()

        self.invitations.setdefault(clerk_org_id, []).append(invitation)
        return invitation


@pytest.fixture(scope="session")
def rsa_keys() -> tuple[str, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    return private_pem, public_pem


@pytest.fixture(scope="session")
def engine():
    settings = get_settings()
    eng = create_engine(settings.database_url, pool_pre_ping=True)
    with eng.connect() as conn:
        conn.execute(text("SELECT 1"))
    yield eng
    eng.dispose()


@pytest.fixture
def session_factory(engine):
    return sessionmaker(bind=engine, autocommit=False, autoflush=False)


def _drop_test_schema(engine) -> None:
    """Drop ORM tables and Alembic state as one intentional test reset."""
    Base.metadata.drop_all(bind=engine)
    with engine.begin() as connection:
        connection.execute(text("DROP TABLE IF EXISTS alembic_version"))
        assert connection.scalar(text("SELECT to_regclass('alembic_version')")) is None


@pytest.fixture
def db_session(engine) -> Generator[Session, None, None]:
    _drop_test_schema(engine)
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
        _drop_test_schema(engine)


@pytest.fixture
def fake_clerk() -> FakeClerkDirectory:
    return FakeClerkDirectory()


@pytest.fixture
def make_token(rsa_keys):
    private_pem, _ = rsa_keys

    def _make(
        *,
        sub: str,
        org_id: str | None = None,
        org_role: str | None = None,
        omit_org_role: bool = False,
        expired: bool = False,
        azp: str = "http://localhost:3000",
        issuer: str = "https://clerk.test",
    ) -> str:
        now = int(time.time())
        claims: dict = {
            "sub": sub,
            "iss": issuer,
            "azp": azp,
            "iat": now - 10,
            "nbf": now - 10,
            "exp": now - 60 if expired else now + 3600,
        }
        if org_id:
            org_claims: dict = {"id": org_id}
            if not omit_org_role:
                org_claims["rol"] = org_role or "org:admin"
            claims["o"] = org_claims
        return jwt.encode(claims, private_pem, algorithm="RS256")

    return _make


@pytest.fixture
def dns_resolver() -> StaticDnsTxtResolver:
    return StaticDnsTxtResolver()


@pytest.fixture
def client(
    db_session, fake_clerk, rsa_keys, dns_resolver
) -> Generator[TestClient, None, None]:
    _, public_pem = rsa_keys
    settings = get_settings()
    verifier = StaticKeyTokenVerifier(settings, public_key_pem=public_pem)
    app = create_app(
        token_verifier=verifier,
        clerk_directory=fake_clerk,
        dns_resolver=dns_resolver,
    )

    def _override_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = _override_db

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()


@pytest.fixture
def seed_user_a(fake_clerk) -> tuple[str, str]:
    user_id = f"user_{uuid.uuid4().hex}"
    org_id = f"org_{uuid.uuid4().hex}"
    fake_clerk.users[user_id] = ClerkUserInfo(
        clerk_user_id=user_id,
        email="alice@example.com",
        name="Alice",
        email_verified=True,
    )
    fake_clerk.memberships[user_id] = [
        ClerkOrgMembership(clerk_org_id=org_id, org_name="Org A", role="org:admin")
    ]
    return user_id, org_id


@pytest.fixture
def seed_user_b(fake_clerk) -> tuple[str, str]:
    user_id = f"user_{uuid.uuid4().hex}"
    org_id = f"org_{uuid.uuid4().hex}"
    fake_clerk.users[user_id] = ClerkUserInfo(
        clerk_user_id=user_id,
        email="bob@example.com",
        name="Bob",
        email_verified=True,
    )
    fake_clerk.memberships[user_id] = [
        ClerkOrgMembership(clerk_org_id=org_id, org_name="Org B", role="org:admin")
    ]
    return user_id, org_id
