# Sentinel Scout benchmark harness (Milestone 14)

Offline-first evaluation of Scout’s **authorized pipeline** against explicit
ground truth. The harness does **not** change candidate, validation, finding, or
retest behavior to improve scores. Poor product behavior is reported honestly.

## What is measured

### Offline (`--mode offline`, default CI)

Discovery tools are **not** used. Hosts are seeded from fixture YAML and probed
on loopback with `Host: <fixture-hostname>`.

Asset metrics are therefore **pipeline** metrics, not discovery quality:

| Name | Meaning |
| --- | --- |
| `pipeline_asset_precision` | Of HTTP-service assets Scout persisted, how many were expected reachable fixture hosts |
| `pipeline_asset_recall` | Of expected reachable fixture hosts, how many Scout scoped, probed, persisted, and processed |

Do **not** call these “Scout asset recall” or “Scout discovery recall”. Offline
mode only checks whether Scout correctly handled the hosts it was handed.

### local_live (explicit, never CI)

Optional local mode. Subfinder may be invoked against `bench.example` and the
result is **recorded only** (public DNS is expected empty). ProjectDiscovery
`httpx` may probe loopback with a `Host` header.

Only this mode may report `live_discovery_asset_recall`. That value measures
**discovery-tool wiring** against loopback-mapped fixture hosts. It is **not**
an internet-wide discovery-quality claim.

### Candidates

Two precision numbers are always reported separately. They are never collapsed
into one accuracy score:

- `precision_rule_faithful` — emitted ∩ expected-present / emitted (deterministic regression)
- `precision_desirable` — emitted ∩ desirable / emitted (whether rules produce signals we actually want)

Jenkins `sensitive_service_exposed` + `exposed_admin_interface` is **expected
overlap**, not a false positive.

Header observations stay in `known_misses` until discovery persists
`security_headers_missing`. They are excluded from recall on purpose.

Candidate emission uses **marker categories**. Role/environment tokens (`admin`,
`staging`, `dev`) may match an exact DNS label or a hyphen/underscore token.
Named products (`jenkins`, `grafana`, …) are strong on an exact DNS label, or
with product title/path corroboration — not because the product name is one
hyphen token. Short infra tokens (`ci`, `cd`, `db`, `git`, `mail`) prefer an
exact DNS label. Production rules do not special-case words such as `training`
or `docs`.

## Fixtures (`bench.example`)

The fixture root is **`bench.example`** (RFC 2606 reserved). Labels `bench` and
`example` are not Scout staging/dev markers, so the namespace itself must not
emit `staging_dev_exposed`. Do not use a `test` TLD here: current product rules
treat the DNS label `test` as a staging marker.

| Id | Default CI | Purpose |
| --- | --- | --- |
| `visible-surface` | yes | Obvious reachable admin / staging / auth / Jenkins surfaces |
| `naming-traps` | yes | Marker-category traps and recall anchors (`devshop`, `administrator-training`, dashboard title, `grafana-training` / `jenkins-docs`, plus exact-label `grafana` / `jenkins`) |
| `retest-delta` | **no** | Fixture C: take staging down, expect a passing retest. Run explicitly until the harness is trusted |

## Commands

From `apps/api` (Postgres required; uses `DATABASE_URL`):

```bash
# Default CI pack (A + B), offline
uv run python -m app.benchmark run --all --mode offline --save

# Single fixture
uv run python -m app.benchmark run --fixture visible-surface --mode offline --save
uv run python -m app.benchmark run --fixture naming-traps --mode offline --save

# Fixture C — explicit only, not the default CI pack
uv run python -m app.benchmark run --fixture retest-delta --mode offline --save

# Report-only baseline diff (never fails CI merely because metrics moved)
uv run python -m app.benchmark compare --against ../../benchmark/results/baselines

# Optional loopback HTML server (Compose is optional local parity)
uv run python -m app.benchmark serve --fixture visible-surface --port 18080
```

`--all` is **only** `visible-surface` and `naming-traps`.

CI fails if the benchmark crashes, fixtures fail to start, schema/result
generation fails, or tests fail. CI does **not** fail because candidate/asset
metrics differ from the committed baseline. The compare command prints a clear
diff. Selected regressions become hard gates only after those baselines are
reviewed and trusted.

## Network policy

CI is offline-only. It must not use live subfinder, public DNS, staging
Railway, or unrelated external targets. Loopback HTTP is `127.0.0.1` with a
fixture `Host` header.

Optional Compose (`benchmark/compose.yaml`) binds `127.0.0.1:18080` only.
Naming-traps uses a different `www.bench.example` HTML file than visible-surface;
prefer `python -m app.benchmark serve` or the in-process runner for Fixture B.

## Result JSON

`schema_version: 1`. Top-level fields include `pipeline_assets`, `candidates`,
`overlaps`, `known_misses`, `validation`, `retest`, and `live_discovery`
(null in offline mode). Forbidden names include `scout_asset_recall`,
`scout_discovery_recall`, `discovery_recall`, and a blended `accuracy` score.
