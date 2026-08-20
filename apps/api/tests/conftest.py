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

from app.core.config import get_settings, reset_settings_cache
from app.core.db import Base, get_db
from app.core.security import StaticKeyTokenVerifier
from app.main import create_app
from app.services.clerk import ClerkOrgMembership, ClerkUserInfo
from app.services.dns import StaticDnsTxtResolver

reset_settings_cache()


@dataclass
class FakeClerkDirectory:
    users: dict[str, ClerkUserInfo] = field(default_factory=dict)
    memberships: dict[str, list[ClerkOrgMembership]] = field(default_factory=dict)

    def get_user(self, clerk_user_id: str) -> ClerkUserInfo:
        return self.users[clerk_user_id]

    def list_organization_memberships(self, clerk_user_id: str) -> list[ClerkOrgMembership]:
        return list(self.memberships.get(clerk_user_id, []))


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


@pytest.fixture
def db_session(engine) -> Generator[Session, None, None]:
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


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
            claims["o"] = {"id": org_id, "rol": org_role or "org:admin"}
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
        ClerkOrgMembership(clerk_org_id=org_id, org_name="Org B", role="org:member")
    ]
    return user_id, org_id
