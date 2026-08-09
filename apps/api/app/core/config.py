from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import AliasChoices, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

EnvironmentName = Literal["development", "test", "staging", "production"]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    environment: EnvironmentName = Field(default="development", alias="ENVIRONMENT")

    database_url: str = Field(default="", alias="DATABASE_URL")
    clerk_issuer: str = Field(default="", alias="CLERK_ISSUER")
    clerk_jwks_url: str = Field(default="", alias="CLERK_JWKS_URL")
    clerk_secret_key: str = Field(default="", alias="CLERK_SECRET_KEY")
    clerk_authorized_parties: str = Field(default="", alias="CLERK_AUTHORIZED_PARTIES")
    clerk_api_base_url: str = Field(
        default="https://api.clerk.com/v1",
        alias="CLERK_API_BASE_URL",
    )

    cors_allowed_origins: str = Field(
        default="",
        validation_alias=AliasChoices("CORS_ALLOWED_ORIGINS", "API_CORS_ORIGINS"),
    )
    frontend_url: str = Field(default="", alias="FRONTEND_URL")

    log_level: str = Field(default="INFO", alias="LOG_LEVEL")

    worker_poll_interval: float = Field(
        default=1.0,
        validation_alias=AliasChoices("WORKER_POLL_INTERVAL", "WORKER_POLL_INTERVAL_SECONDS"),
    )
    scheduler_poll_interval: float = Field(
        default=5.0,
        validation_alias=AliasChoices(
            "SCHEDULER_POLL_INTERVAL", "SCHEDULER_POLL_INTERVAL_SECONDS"
        ),
    )

    scout_max_discovered_assets: int = Field(
        default=500,
        validation_alias=AliasChoices("SCOUT_MAX_DISCOVERED_ASSETS", "MAX_DISCOVERED_HOSTS"),
    )
    scout_http_timeout: int = Field(
        default=120,
        validation_alias=AliasChoices("SCOUT_HTTP_TIMEOUT", "HTTPX_TIMEOUT_SECONDS"),
    )
    scout_subfinder_timeout: int = Field(
        default=180,
        validation_alias=AliasChoices("SCOUT_SUBFINDER_TIMEOUT", "SUBFINDER_TIMEOUT_SECONDS"),
    )

    db_pool_size: int = Field(default=5, alias="DB_POOL_SIZE")
    db_max_overflow: int = Field(default=10, alias="DB_MAX_OVERFLOW")
    db_pool_recycle_seconds: int = Field(default=1800, alias="DB_POOL_RECYCLE_SECONDS")

    rate_limit_enabled: bool = Field(default=True, alias="RATE_LIMIT_ENABLED")
    rate_limit_target_create: int = Field(default=20, alias="RATE_LIMIT_TARGET_CREATE")
    rate_limit_verification: int = Field(default=30, alias="RATE_LIMIT_VERIFICATION")
    rate_limit_operation_create: int = Field(default=30, alias="RATE_LIMIT_OPERATION_CREATE")
    rate_limit_validation: int = Field(default=60, alias="RATE_LIMIT_VALIDATION")
    rate_limit_retest: int = Field(default=30, alias="RATE_LIMIT_RETEST")
    rate_limit_window_seconds: int = Field(default=3600, alias="RATE_LIMIT_WINDOW_SECONDS")

    @field_validator("environment", mode="before")
    @classmethod
    def _normalize_environment(cls, value: object) -> object:
        if isinstance(value, str):
            return value.strip().lower()
        return value

    @field_validator("log_level", mode="before")
    @classmethod
    def _normalize_log_level(cls, value: object) -> object:
        if isinstance(value, str):
            return value.strip().upper()
        return value

    @field_validator("database_url", mode="before")
    @classmethod
    def _normalize_database_url(cls, value: object) -> object:
        # Railway/managed Postgres often provides postgresql:// or postgres://.
        if isinstance(value, str) and value:
            if value.startswith("postgres://"):
                return "postgresql+psycopg://" + value[len("postgres://") :]
            if value.startswith("postgresql://"):
                return "postgresql+psycopg://" + value[len("postgresql://") :]
        return value

    @model_validator(mode="after")
    def _apply_defaults_and_fail_closed(self) -> Settings:
        if not self.database_url:
            if self.environment in {"development", "test"}:
                object.__setattr__(
                    self,
                    "database_url",
                    "postgresql+psycopg://scout:scout@localhost:5432/scout",
                )
            else:
                raise ValueError("DATABASE_URL is required in staging/production")

        if not self.cors_allowed_origins:
            if self.environment in {"development", "test"}:
                object.__setattr__(
                    self,
                    "cors_allowed_origins",
                    self.frontend_url or "http://localhost:3000",
                )
            else:
                raise ValueError(
                    "CORS_ALLOWED_ORIGINS (or API_CORS_ORIGINS) is required in staging/production"
                )

        if not self.frontend_url:
            if self.environment in {"development", "test"}:
                object.__setattr__(self, "frontend_url", "http://localhost:3000")
            else:
                raise ValueError("FRONTEND_URL is required in staging/production")

        if self.environment in {"staging", "production"}:
            missing: list[str] = []
            if not self.clerk_issuer:
                missing.append("CLERK_ISSUER")
            if not self.clerk_jwks_url:
                missing.append("CLERK_JWKS_URL")
            if not self.clerk_secret_key:
                missing.append("CLERK_SECRET_KEY")
            if "localhost" in self.database_url.lower() or "127.0.0.1" in self.database_url:
                missing.append(
                    "DATABASE_URL (must not point at localhost in staging/production)"
                )
            if any(
                "localhost" in origin.lower() or "127.0.0.1" in origin
                for origin in self.cors_origins
            ):
                missing.append(
                    "CORS_ALLOWED_ORIGINS (must not include localhost in staging/production)"
                )
            if "localhost" in self.frontend_url.lower() or "127.0.0.1" in self.frontend_url:
                missing.append("FRONTEND_URL (must not be localhost in staging/production)")
            if missing:
                raise ValueError(
                    "Invalid staging/production settings: " + "; ".join(missing)
                )

        return self

    @property
    def cors_origins(self) -> list[str]:
        return [o.strip() for o in self.cors_allowed_origins.split(",") if o.strip()]

    @property
    def authorized_parties(self) -> list[str]:
        return [p.strip() for p in self.clerk_authorized_parties.split(",") if p.strip()]

    # Compatibility accessors for existing service code.
    @property
    def max_discovered_hosts(self) -> int:
        return self.scout_max_discovered_assets

    @property
    def subfinder_timeout_seconds(self) -> int:
        return self.scout_subfinder_timeout

    @property
    def httpx_timeout_seconds(self) -> int:
        return self.scout_http_timeout

    @property
    def api_cors_origins(self) -> str:
        return self.cors_allowed_origins

    @property
    def is_production_like(self) -> bool:
        return self.environment in {"staging", "production"}


@lru_cache
def get_settings() -> Settings:
    return Settings()


def reset_settings_cache() -> None:
    get_settings.cache_clear()
