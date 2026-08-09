# Sentinel Scout API

FastAPI backend + Postgres-backed discovery worker.

## Setup

```bash
docker compose up -d db
cd apps/api
uv sync
cp ../../.env.example .env
uv run alembic upgrade head
uv run uvicorn app.main:app --reload --port 8000
```

## Worker

```bash
cd apps/api
uv run python -m app.worker
```

Requires `subfinder` and `httpx` on `PATH` for real discovery. Automated tests mock both.

## Tests / offline e2e

```bash
uv run pytest
PYTHONPATH=. uv run python scripts/e2e_discovery_operation.py
```
