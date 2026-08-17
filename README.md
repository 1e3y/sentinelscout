# Sentinel Scout

Authorized autonomous black-box security assessment platform.

## Current scope (through Milestone 16)

Staging host plan: **Vercel (web) + Railway (API, worker, scheduler, Postgres)**.
Deploy config lives under `apps/api/Dockerfile`, `deploy/railway/`, `apps/web/vercel.json`, and [`docs/staging.md`](docs/staging.md).

Offline evaluation harness: [`benchmark/README.md`](benchmark/README.md) (`python -m app.benchmark`). CI is offline-only against `bench.example` fixtures.

- Next.js frontend with Clerk sign-in
- FastAPI backend that independently verifies Clerk JWTs
- PostgreSQL persistence through monitoring configurations, findings, retests, discovery artifacts, and audit events
- Authorized targets with DNS TXT verification, scope, and revoke
- Postgres-backed **worker** (discovery / validation / retest) and **scheduler** (monitoring → queued operations)
- Deterministic candidates, safe validation, findings + remediation, safe retest
- **Continuous monitoring** (`daily` / `weekly`) that creates normal authorized Operations (`source=scheduled`)
- Factual change detection between assessments (new / gone / response changed)
- **Audit trail** (`AuditEvent`) separate from operation timeline events; org-scoped `GET /v1/audit-events`
- **Immutable operation control snapshots** + `safe_production` testing profile at operation creation
- Finding **provenance** chain (observation → candidate → validation → finding → retest)
- **Staging readiness:** typed settings (fail-closed), structured logs + redaction, request IDs, `/ready`, Postgres rate limits, safe errors, worker/scheduler graceful shutdown, web security headers
- Alembic migrations, authenticated dashboard, backend tests, minimal CI

See [docs/staging.md](docs/staging.md) for staging process model and migration/startup commands.

The frontend is **not** a security boundary.

## Async + discovery architecture

- **Queue:** Postgres `FOR UPDATE SKIP LOCKED` (no Redis)
- **Scheduler:** claims due monitoring configs, creates queued Operations only (`uv run python -m app.scheduler`)
- **Worker:** discovery ops → change detection → candidates → validation attempts → retest attempts
- **Tools:** `subfinder` and ProjectDiscovery `httpx` via subprocess (mocked in automated tests)
- **Monitoring:** re-checks authorization before each run; revoked/unverified targets disable monitoring
- **Findings / retest:** promote from supported candidates; resolve only after a passing retest
- **Audit / controls:** who acted, authorized boundary at launch, evidence provenance without secret metadata
- **Ops readiness:** `/health` liveness, `/ready` DB/config checks, structured logs, org/user rate limits
- **Benchmark (M14):** loopback fixtures + explicit ground truth; offline CI pack `visible-surface` + `naming-traps`; report-only baseline diffs. Offline metrics are `pipeline_asset_precision` / `pipeline_asset_recall` (not discovery recall).
- **Candidate matching (M15):** token-aware hostnames with marker categories (role/env vs named product vs short infra); stronger admin/auth/sensitive emission thresholds
- **HTTP evidence (M16):** allowlisted response-header facts with explicit `headers_observed`; HSTS configuration observations only when capture is complete and the response was not redirected

## Prerequisites

- Docker / Docker Compose
- [uv](https://docs.astral.sh/uv/)
- Node.js 20+ and [pnpm](https://pnpm.io/)
- Clerk application with Organizations enabled
- For real discovery: `subfinder` and `httpx` on `PATH`

## Quick start

### 1. PostgreSQL

```bash
docker compose up -d db
```

### 2. Environment

```bash
cp .env.example apps/api/.env
# fill Clerk + optional MAX_DISCOVERED_HOSTS / SUBFINDER_TIMEOUT_SECONDS / HTTPX_TIMEOUT_SECONDS

cp apps/web/.env.example apps/web/.env.local
# fill Clerk publishable/secret + NEXT_PUBLIC_API_BASE_URL
```

### 3. API

```bash
cd apps/api
uv sync
uv run alembic upgrade head
uv run uvicorn app.main:app --reload --port 8000
```

### 4. Worker

```bash
cd apps/api
uv run python -m app.worker
```

### 5. Web

```bash
cd apps/web
pnpm install
pnpm dev
```

Verify a target you control, set scope (include subdomains / exclusions), create an operation, and watch the worker discover assets.

## Local discovery checks

Automated / offline (mocked tools, no public domains):

```bash
cd apps/api
PYTHONPATH=. uv run python scripts/e2e_discovery_operation.py
PYTHONPATH=. uv run python scripts/e2e_monitoring_cycle.py
```

Manual real tools: only against a domain you authorize and control.

### Scheduler

```bash
cd apps/api
uv run python -m app.scheduler
```

## Tests

```bash
cd apps/api && uv run pytest
cd apps/web && pnpm lint && pnpm typecheck && pnpm build
```
