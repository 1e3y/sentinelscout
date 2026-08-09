# Shared image for Scout API, worker, and scheduler (Railway).
# Different services override the start command; migrations are NOT run here.
#
# Build (from apps/api):
#   docker build -t scout-api:local .
#
# Start examples:
#   API:       uv run uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}
#   Worker:    uv run python -m app.worker
#   Scheduler: uv run python -m app.scheduler
#   Migrate:   uv run alembic upgrade head

FROM python:3.12-slim-bookworm

# Put /usr/local/bin ahead of the venv so ProjectDiscovery `httpx` is not
# shadowed by the Python `httpx` console script from dependencies.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PATH="/usr/local/bin:/app/.venv/bin:${PATH}"

WORKDIR /app

# System deps + ProjectDiscovery CLI tools (worker discovery).
# API/scheduler ignore these binaries; keeping one image simplifies Railway.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        unzip \
    && rm -rf /var/lib/apt/lists/*

ARG TARGETARCH=amd64
ARG SUBFINDER_VERSION=2.6.7
ARG PD_HTTPX_VERSION=1.6.10

RUN set -eux; \
    arch="${TARGETARCH}"; \
    if [ "$arch" = "amd64" ]; then pd_arch="amd64"; \
    elif [ "$arch" = "arm64" ]; then pd_arch="arm64"; \
    else pd_arch="amd64"; fi; \
    curl -fsSL \
      "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_${pd_arch}.zip" \
      -o /tmp/subfinder.zip; \
    curl -fsSL \
      "https://github.com/projectdiscovery/httpx/releases/download/v${PD_HTTPX_VERSION}/httpx_${PD_HTTPX_VERSION}_linux_${pd_arch}.zip" \
      -o /tmp/httpx.zip; \
    unzip -qo /tmp/subfinder.zip -d /usr/local/bin subfinder; \
    unzip -qo /tmp/httpx.zip -d /usr/local/bin httpx; \
    chmod +x /usr/local/bin/subfinder /usr/local/bin/httpx; \
    rm -f /tmp/subfinder.zip /tmp/httpx.zip; \
    subfinder -version; \
    httpx -version

COPY --from=ghcr.io/astral-sh/uv:0.7.12 /uv /uvx /usr/local/bin/

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev

COPY alembic.ini ./
COPY alembic ./alembic
COPY app ./app
COPY scripts ./scripts

EXPOSE 8000

# Use the image venv directly (avoid `uv run` re-syncing deps at container start).
# Railway worker/scheduler services override startCommand.
CMD ["sh", "-c", "/app/.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
