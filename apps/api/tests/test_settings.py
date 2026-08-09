from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.core.config import Settings, reset_settings_cache


def test_missing_required_production_settings_fail_closed(monkeypatch):
    reset_settings_cache()
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("DATABASE_URL", "")
    monkeypatch.delenv("CLERK_ISSUER", raising=False)
    monkeypatch.delenv("CLERK_JWKS_URL", raising=False)
    monkeypatch.delenv("CLERK_SECRET_KEY", raising=False)
    monkeypatch.delenv("CORS_ALLOWED_ORIGINS", raising=False)
    monkeypatch.delenv("API_CORS_ORIGINS", raising=False)
    monkeypatch.delenv("FRONTEND_URL", raising=False)

    with pytest.raises((ValidationError, ValueError)):
        Settings()


def test_production_rejects_localhost_database(monkeypatch):
    reset_settings_cache()
    monkeypatch.setenv("ENVIRONMENT", "staging")
    monkeypatch.setenv(
        "DATABASE_URL", "postgresql+psycopg://scout:scout@localhost:5432/scout"
    )
    monkeypatch.setenv("CLERK_ISSUER", "https://clerk.example")
    monkeypatch.setenv("CLERK_JWKS_URL", "https://clerk.example/.well-known/jwks.json")
    monkeypatch.setenv("CLERK_SECRET_KEY", "sk_live_dummy")
    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", "https://app.example.com")
    monkeypatch.setenv("FRONTEND_URL", "https://app.example.com")

    with pytest.raises((ValidationError, ValueError)):
        Settings()


def test_development_allows_localhost_defaults(monkeypatch):
    reset_settings_cache()
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("DATABASE_URL", "")
    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", "")
    monkeypatch.setenv("FRONTEND_URL", "")
    monkeypatch.setenv("CLERK_ISSUER", "")
    settings = Settings()
    assert "localhost" in settings.database_url
    assert settings.frontend_url.startswith("http://localhost")


def test_database_url_normalizes_railway_style(monkeypatch):
    reset_settings_cache()
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv(
        "DATABASE_URL", "postgresql://scout:scout@db.example:5432/scout"
    )
    settings = Settings()
    assert settings.database_url.startswith("postgresql+psycopg://")
    assert "db.example" in settings.database_url
