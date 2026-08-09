#!/usr/bin/env sh
# Explicit Alembic migration for staging/production release.
# Run as a Railway release command or one-off job — NOT on every API request/startup.
set -eu

cd "$(dirname "$0")/.."

if [ -z "${DATABASE_URL:-}" ]; then
  echo "DATABASE_URL is required" >&2
  exit 1
fi

echo "Running: alembic upgrade head"
if [ -x /app/.venv/bin/alembic ]; then
  /app/.venv/bin/alembic upgrade head
  echo "Current revision:"
  /app/.venv/bin/alembic current
else
  uv run alembic upgrade head
  echo "Current revision:"
  uv run alembic current
fi
