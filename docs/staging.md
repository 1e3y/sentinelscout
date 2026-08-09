# Staging deployment guide

**Architecture (approved):** Vercel for Next.js web + Railway for API, worker, scheduler, and managed PostgreSQL.

Do **not** auto-run Alembic on every API process start. Migrations run explicitly as the API service **release command** (once per deploy) or via a one-off migrate job.

---

## Service map

| Process | Host | Root / image | Start |
|---|---|---|---|
| Postgres | Railway Plugin | managed | Railway-managed |
| API | Railway service | `apps/api` Dockerfile | `uvicorn app.main:app` |
| Worker | Railway service | same Dockerfile | `python -m app.worker` |
| Scheduler | Railway service | same Dockerfile | `python -m app.scheduler` |
| Web | Vercel project | `apps/web` | Next.js (`pnpm build` / Vercel runtime) |

Reference configs:

- `deploy/railway/api.toml`
- `deploy/railway/worker.toml`
- `deploy/railway/scheduler.toml`
- `apps/api/Dockerfile`
- `apps/web/vercel.json`
- Env placeholders: `deploy/env/*.env.example`

---

## Exact setup steps (high level)

### A. Clerk (staging app)

1. Create a **separate** Clerk application for staging (do not reuse production keys).
2. Enable **Organizations**.
3. Note:
   - Publishable key (`pk_test_…`)
   - Secret key (`sk_test_…`)
   - Frontend API / issuer host (e.g. `https://verb-noun-00.clerk.accounts.dev`)
4. After Vercel URL exists, set Clerk allowed origins / redirect URLs to that staging web URL.

### B. Railway project

1. Create a Railway project (e.g. `sentinelscout-staging`).
2. Add **PostgreSQL** plugin → copy/`DATABASE_URL` reference for other services.
3. Create three services from the same GitHub repo, each with **Root Directory = `apps/api`**:

#### API service

- Builder: Dockerfile (`apps/api/Dockerfile`)
- **Release command:** `sh scripts/migrate.sh`
- **Start command:** `sh -c '/app/.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}'`
- Health check path: `/ready`
- Generate a public domain (Railway → Settings → Networking)
- Apply variables from `deploy/env/railway-api.env.example`

#### Worker service

- Same Dockerfile / root directory
- **Start command:** `/app/.venv/bin/python -m app.worker`
- **No** release command
- Variables from `deploy/env/railway-worker.env.example`
- Restart on failure enabled

#### Scheduler service

- Same Dockerfile / root directory
- **Start command:** `/app/.venv/bin/python -m app.scheduler`
- **No** release command
- Variables from `deploy/env/railway-scheduler.env.example`
- Restart on failure enabled

### C. Vercel project

1. Import the same GitHub repo.
2. Set **Root Directory** to `apps/web`.
3. Framework: Next.js (see `apps/web/vercel.json`).
4. Set env vars from `deploy/env/vercel-web.env.example` (use the Railway API public URL).
5. Deploy → copy the staging web URL.
6. Update Railway `FRONTEND_URL`, `CORS_ALLOWED_ORIGINS`, `CLERK_AUTHORIZED_PARTIES` to that URL.
7. Update Clerk staging app URLs to match Vercel.

### D. Wire URLs (order matters)

1. Postgres ready on Railway  
2. Deploy API (release runs migrations) → note API URL  
3. Deploy worker + scheduler (same `DATABASE_URL`)  
4. Deploy Vercel web with `NEXT_PUBLIC_API_BASE_URL=<API URL>`  
5. Patch CORS / FRONTEND_URL / Clerk parties to the Vercel URL  
6. Redeploy API if CORS/FRONTEND_URL changed  

Platform URLs are acceptable; custom domains are optional.

---

## Environment variables

### Railway Postgres

Provided by the plugin (do not invent):

| Variable | Notes |
|---|---|
| `DATABASE_URL` | Usually `postgresql://…`. SQLAlchemy in this app accepts `postgresql://` and `postgres://` and normalizes to `postgresql+psycopg://`. |

Backup expectations: use Railway’s managed Postgres backups / snapshots for staging. Point-in-time restore depends on Railway plan — treat staging as rebuildable but keep snapshots before risky migrations.

Inspect migration state (one-off shell on API service or local with staging `DATABASE_URL`):

```bash
uv run alembic current
uv run alembic history
```

### Railway API

| Variable | Required | Example / notes |
|---|---|---|
| `ENVIRONMENT` | yes | `staging` |
| `DATABASE_URL` | yes | Railway Postgres reference |
| `CLERK_ISSUER` | yes | `https://….clerk.accounts.dev` |
| `CLERK_JWKS_URL` | yes | `https://….clerk.accounts.dev/.well-known/jwks.json` |
| `CLERK_SECRET_KEY` | yes | staging secret only |
| `FRONTEND_URL` | yes | Vercel staging URL (non-localhost) |
| `CORS_ALLOWED_ORIGINS` | yes | same Vercel URL (comma-separated if multiple) |
| `CLERK_AUTHORIZED_PARTIES` | recommended | Vercel staging URL |
| `LOG_LEVEL` | no | `INFO` |
| `SCOUT_MAX_DISCOVERED_ASSETS` | no | `200` (conservative for staging) |
| `SCOUT_HTTP_TIMEOUT` | no | `120` |
| `SCOUT_SUBFINDER_TIMEOUT` | no | `180` |
| `RATE_LIMIT_*` | no | defaults OK |

### Railway worker

Same as API for DB + Clerk/settings validation fields that Settings requires in staging, plus:

| Variable | Required | Notes |
|---|---|---|
| `WORKER_POLL_INTERVAL` | no | `1` |
| `SCOUT_*` timeouts/limits | no | discovery safety |

Start: `/app/.venv/bin/python -m app.worker`  
Restart policy: on failure (persistent process).

### Railway scheduler

| Variable | Required | Notes |
|---|---|---|
| `SCHEDULER_POLL_INTERVAL` | no | `5` |
| Same staging Settings requirements as API | yes | fail-closed |

Start: `/app/.venv/bin/python -m app.scheduler`  
Do not combine with API or worker.

### Vercel web

| Variable | Required | Notes |
|---|---|---|
| `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY` | yes | staging publishable |
| `CLERK_SECRET_KEY` | yes | staging secret |
| `NEXT_PUBLIC_API_BASE_URL` | yes | Railway API public URL (https) |
| `NEXT_PUBLIC_CLERK_SIGN_IN_URL` | no | `/sign-in` |
| `NEXT_PUBLIC_CLERK_SIGN_UP_URL` | no | `/sign-up` |

`NEXT_PUBLIC_API_BASE_URL` is baked into the client bundle and CSP `connect-src` at **build** time — set it before building/deploying web.

---

## Migration / release procedure

**Preferred (API deploy):**

Railway API service → **Release Command**:

```bash
sh scripts/migrate.sh
```

(Equivalent: `/app/.venv/bin/alembic upgrade head` inside the built image.)

**Manual one-off** (API container shell or local with staging DB URL):

```bash
cd apps/api
export DATABASE_URL='postgresql://…'   # staging
export ENVIRONMENT=staging
# …other required staging vars if validating Settings elsewhere
uv run alembic upgrade head
uv run alembic current
```

Rules:

- Run migrations **before** or as release for the API deploy that needs the new schema.
- Do **not** put `alembic upgrade` in the API `CMD` / startup lifespan.
- Do **not** run release migrations on worker/scheduler (avoids concurrent upgrade races).

---

## Build / start commands (local parity)

```bash
# API image
cd apps/api
docker build -t scout-api:local .

# Run shapes (do not use real secrets in shell history carelessly)
docker run --rm -e PORT=8000 -e ENVIRONMENT=staging … scout-api:local
docker run --rm … scout-api:local uv run python -m app.worker
docker run --rm … scout-api:local uv run python -m app.scheduler
docker run --rm -e DATABASE_URL=… scout-api:local uv run alembic upgrade head
```

Web:

```bash
cd apps/web
pnpm install
pnpm build
pnpm start
```

---

## Health / readiness / logs

| Check | URL |
|---|---|
| Liveness | `GET https://<api>/health` → `{"status":"ok"}` |
| Readiness | `GET https://<api>/ready` → `200` + `status=ready` when DB+config OK; `503` otherwise |

- API responses include `X-Request-ID`.
- Worker/scheduler emit structured JSON logs; correlate with `operation_id`.
- Railway → each service → **Logs** for diagnosis.

---

## Rollback basics

1. **App rollback:** redeploy previous Railway/Vercel deployment for the affected service.
2. **Schema:** Alembic downgrades are possible but rare in staging; prefer forward fix. If needed: `uv run alembic downgrade <rev>` against staging DB from a one-off, then redeploy matching code.
3. **Config mistakes:** fix env vars and redeploy; no secrets in git.

---

## Common deployment issues

| Symptom | Likely cause |
|---|---|
| API won’t boot in staging | Missing Clerk/DB/FRONTEND/CORS; localhost values forbidden |
| `/ready` → database unavailable | Wrong `DATABASE_URL` or Postgres not linked |
| CORS errors in browser | `CORS_ALLOWED_ORIGINS` ≠ Vercel URL |
| Clerk redirect errors | Staging Clerk URLs not updated to Vercel domain |
| Worker completes with tool errors | Image missing `subfinder`/`httpx` (rebuild Dockerfile) |
| Web can’t call API | `NEXT_PUBLIC_API_BASE_URL` wrong or CSP/connect-src stale (rebuild web) |
| Migrations not applied | Release command missing on API service |
| Concurrent migration errors | Release command also set on worker/scheduler |

---

## Controlled discovery only

First real staging discovery must use a domain **you own/control**. Keep `SCOUT_MAX_DISCOVERED_ASSETS` conservative (e.g. `200`). Do not scan unrelated public domains.
