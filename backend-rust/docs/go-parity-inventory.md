# Go Backend Parity Inventory

Go snapshot: `448788c92d9c8a2f5a3000f182e96856cb87f062`. Rust migration
status on branch `codex/rust-postgres` was updated 2026-07-14.

This document is the migration inventory for replacing the Go process with the
PostgreSQL-only Rust process. The row-level HTTP contract is in
[`go-routes.tsv`](./go-routes.tsv). Test-only Gin routers and generated Ent code
are deliberately excluded. The contract sections retain the Go source behavior
that drove the rewrite; **Rust migration completion status** records the current
implementation outcome.

## Route census

| Registration source | Records | Runtime |
| --- | ---: | --- |
| `routes/common.go` | 3 | normal server |
| `routes/auth.go` | 51 | normal server |
| `routes/user.go` | 49 | normal server |
| `routes/payment.go` | 37 | normal server |
| `routes/gateway.go` | 47 | normal server |
| `routes/admin.go` | 338 | normal server |
| `handler/page_handler.go` | 3 | normal server |
| `setup/handler.go` | 4 | setup server only |
| **Total registration records** | **532** | both mutually exclusive modes |

The six explicit route files contain exactly 525 registrations. The normal
server also registers three page routes, for 528 active registrations. Setup
mode exposes four different registrations. Across both modes there are 531
unique `method+path` keys because `GET /setup/status` exists in both modes with
different implementations.

- Methods: 239 GET, 208 POST, 52 PUT, 33 DELETE.
- Dynamic routes: 178 total; 173 contain `:param`, six contain `*wildcard`, and
  one contains both.
- Every source registration matched one TSV row. No production PATCH, HEAD,
  OPTIONS, Any, or Handle registration was found.
- `dynamic=yes` means the path contains a Gin parameter or catch-all. It is one
  registered contract, not an expansion into concrete paths.

The TSV columns are:

| Column | Meaning |
| --- | --- |
| `method`, `path` | Fully resolved prefix plus route path. |
| `handler` | Handler selector; `a\|b` denotes inline platform dispatch. |
| `auth` | Effective route-group and route-local authentication/guard chain. |
| `source` | Go registration file and logical UTF-8 line. |
| `migration_category` | Suggested Rust migration workstream. |
| `dynamic` | `yes` for `:param` or `*wildcard`. |
| `transport` | HTTP, conditional SSE, or WebSocket upgrade. |

## Middleware contract

The normal router is built in `internal/server/http.go` and
`internal/server/router.go`.

1. Gin recovery is installed first. Trusted proxies are explicitly configured
   or disabled. Release mode warns when no trusted proxy is configured.
2. Request access logging, application logging, CORS, and dynamic CSP/security
   headers apply globally.
3. The embedded frontend middleware is installed before route registration.
   Its HTML cache is invalidated when public settings change, and frame origins
   are refreshed with a five-second lookup timeout.
4. A global `http.MaxBytesHandler` uses `server.max_request_body_size`, falling
   back to the gateway body limit. Gateway groups additionally use their own
   request-body limiter.
5. H2C is optional. The server deliberately has no write timeout or read
   timeout because upstream requests can stream for many minutes.

Effective route guards are:

| Surface | Guard chain |
| --- | --- |
| Common and public settings | Public; global middleware only. |
| `/api/v1/auth/**` | `BackendModeAuthGuard`; sensitive POSTs add fail-close rate limiting. |
| Authenticated user routes | JWT, then `BackendModeUserGuard`. |
| Admin routes | Admin JWT, then `AdminComplianceGuard`. Compliance status/accept still require admin auth but are exempt from prior acceptance. |
| User payment routes | JWT and user-mode guard. |
| Payment webhooks/public resume | No JWT; provider signature or signed resume token is checked in handlers. |
| Anthropic/OpenAI gateway | Body limit, request ID, ops error logger, endpoint normalization, API-key auth, assigned-group requirement. |
| Gemini native gateway | Same request middleware, Google-compatible API-key extraction with subscription validation, assigned-group requirement. |
| Antigravity gateway | The corresponding API-key chain plus forced antigravity platform. |
| Setup mutation routes | `setupGuard`; only usable while setup mode is active. |

The Go auth rate limiter is Redis-backed and fail-closed. The Rust replacement
keeps a bounded L1 precheck and stores only domain-separated identity hashes in
atomic, expiring PostgreSQL windows. Login failures and sensitive auth actions
therefore share one limit across replicas without persisting raw email
addresses or requiring an ingress-layer correctness fallback.

## Streaming and static content

### WebSocket

Four GET routes require an upgrade:

- `/v1/responses`
- `/responses`
- `/backend-api/codex/responses`
- `/api/v1/admin/ops/ws/qps`

The first three return 426 when the request is not a valid WebSocket upgrade.
They implement bidirectional OpenAI Responses ingress, account selection,
concurrency, billing, failover, and usage recording. The ops socket is admin
authenticated and emits real-time QPS/TPS data with ping/close handling.

### Conditional SSE

Twelve POST registrations can return SSE depending on the request or Gemini
action:

- Anthropic/messages: `/v1/messages`, `/antigravity/v1/messages`.
- OpenAI chat: `/v1/chat/completions`, `/chat/completions`.
- OpenAI responses and catch-alls under `/v1`, `/`, and
  `/backend-api/codex`.
- Gemini action catch-alls under `/v1beta` and `/antigravity/v1beta`.

Parity includes status, headers, event framing, keepalives, client disconnect
cancellation, upstream error events, timeout behavior, and usage extraction
after a partial stream. Token-count routes are ordinary JSON, not SSE.

### Embedded frontend and pages

An embed build serves bundled `dist` files and `data/public` overrides through
middleware. Existing files are static assets; missing non-API paths return the
SPA `index.html` with injected public settings and CSP nonce. The middleware
bypasses `/api/`, `/v1/`, `/v1beta/`, `/backend-api/`, `/antigravity/`,
`/setup/`, `/health`, `/responses`, and `/images/`.

This creates an existing effective-routing hazard: `/chat/completions`,
`/embeddings`, `/videos/generations`, and `/videos/:request_id` are registered
gateway aliases but are not on the frontend bypass list. In an embedded
production build the frontend middleware can serve SPA HTML before those
handlers run. Rust resolves this explicitly: the gateway classifier runs before
SPA fallback, and `/chat/`, `/embeddings`, and `/videos/` are backend bypass
prefixes. The frontend bypass set has regression tests rather than depending on
incidental router order.

Page-specific routes are separate from the SPA:

- `GET /api/v1/pages/:slug`: JWT plus per-page visibility.
- `GET /api/v1/pages/:slug/images/*filename`: public browser image access,
  with admin-only slugs denied in the handler.
- `GET /api/v1/pages`: admin JWT and compliance guard.

## Startup and administrator bootstrap

`cmd/server/main.go` has three mutually exclusive flows:

1. `--setup` runs an interactive CLI setup and exits.
2. A missing config file and missing `.installed` lock enter setup mode. With
   `AUTO_SETUP=true`, setup runs from environment and then continues to the
   normal server; otherwise a setup-only HTTP server starts.
3. An installed system loads bootstrap config, initializes logging, constructs
   all dependencies, starts the HTTP server, waits for SIGINT/SIGTERM, grants
   HTTP shutdown 15 seconds, then runs service cleanup.

Normal database initialization (`internal/repository/ent.go`) performs:

1. timezone initialization;
2. PostgreSQL connection and pool configuration;
3. embedded SQL migrations under a ten-minute context;
4. Ent client construction;
5. bootstrap of JWT/TOTP/payment encryption secrets from config or the
   settings table, followed by full config validation;
6. simple-mode default groups and admin concurrency repair.

Setup migration timeout defaults to 60 seconds. The Go migration runner also
uses a database migration lock and handles non-transactional migrations. The
Rust migration subsystem is the schema authority and preserves advisory
locking, checksum validation, transactional migrations, and explicit
non-transactional migrations. Ent auto-migration is not part of the contract.

Admin creation is deliberately takeover-resistant:

- Create only when `COUNT(users)=0` and no admin exists.
- If any admin exists, skip. If users exist but no admin exists, also skip
  rather than creating an attacker-controlled admin.
- Default email is `ADMIN_EMAIL` or `admin@sub2api.local`.
- Empty `ADMIN_PASSWORD` generates a 16-byte secret and prints
  `Generated admin password (one-time): ...`. Deployment compatibility relies
  on the lowercase substring `admin password` being grep-able.
- The inserted user is active/admin with zero balance and the configured
  setup concurrency; password hashing uses the existing bcrypt contract.

The legacy web/CLI/auto setup contract always tests and serializes Redis. A
PostgreSQL-only Rust deployment must replace that setup model rather than expose
a misleading `/setup/test-redis`: keep status/bootstrap behavior, remove Redis
inputs, and retain the one-time admin log and empty-database safety decision.

## Long-lived jobs and queues

These components start during dependency construction or normal startup. This
table excludes request-scoped goroutines such as an individual SSE relay,
batch-image heartbeat, async balance notification, or system restart.

| Component | Trigger/default | Go responsibility / Rust replacement note |
| --- | --- | --- |
| Pricing updater | Startup load; hash poll every 10 min | Refresh model pricing with local fallback. |
| Email queue | 3 workers | Bounded asynchronous verification/reset email delivery. |
| Token refresh | Every 5 min, configurable | Refresh near-expiry upstream OAuth credentials with retries. |
| Dashboard aggregation | Every 60 s; retention every 6 h | Incremental usage aggregates, watermark, partitions, retention; leader elected. |
| Usage cleanup | Timing wheel every 10 s | Executes persisted cleanup tasks in batches with a 30 min task timeout. |
| Account expiry | Every 1 min | Pause expired accounts. |
| Proxy expiry | Every 1 min | Disable expired proxies. |
| Subscription expiry | Every 1 min | Expire subscriptions and send reminders; leader elected. |
| Deferred account last-used | Timing wheel every 10 s | Coalesce hot-path `last_used_at` writes. |
| User platform quota flusher | 30 s, batch 1000 | Flush L1 quota deltas to PostgreSQL. This is already the requested cadence. |
| Usage billing write-behind | 30 s, up to 16 batches | Flush balance, subscription, API-key, rate, account quota, and command deltas. Rust uses a bounded idempotent PostgreSQL write-behind path and exposes pending/unflushed status. |
| Pending usage-log repository | 30 s, drain up to 4096 | Flush L1 usage records. Rust uses its separate bounded PostgreSQL usage-log worker without a Redis pending list. |
| Usage record pool | 128 workers, queue 16384; scale check 3 s | Bounded post-request usage processing; default auto-scales 128..512 and sync-falls back on overflow. |
| Billing cache writers | Fixed bounded worker queue | Apply asynchronous cache writes and invalidations. |
| Subscription maintenance | 2 workers, queue 1024 | Bounded maintenance work triggered from the hot path. |
| API-key/subscription invalidation subscribers | Continuous pub/sub | Rust uses PostgreSQL `LISTEN/NOTIFY` as a wake-up hint plus TTL/version fallback. |
| Scheduler snapshots | Initial rebuild, outbox every 1 s, full rebuild every 300 s | Maintain account/group scheduling snapshots and lag recovery. Rust consumes the PostgreSQL outbox directly into bounded L1 snapshots. |
| Concurrency slot cleanup | Every 30 s | Remove expired/stale request slots; Go defaults to local L1 slots. |
| User message queue cleanup | Every 60 s when enabled | Clean per-user serialization/RPM queue state. |
| Idempotency cleanup | Every 60 s, batch 500 | Delete expired request/system-operation idempotency records. |
| Batch image cleanup | Every 30 min when enabled | Delete retained inputs/outputs and release account holds. |
| Batch image worker runtime | Queue-enabled multi-loop runtime | Ready consumer, delayed mover, active recovery, billing recovery, and shutdown drain use PostgreSQL leases and `FOR UPDATE SKIP LOCKED`. |
| Payment order expiry | Every 60 s | Expire pending orders under a distributed leader lock. |
| Scheduled test runner | Cron scheduler | Load enabled test plans and execute due tests, max 10 concurrent jobs. |
| Channel monitor runner | Per-monitor timer with jitter | Load enabled monitors and execute checks through a bounded pool; runtime setting checked on each fire. |
| Backup service | DB-configured 5-field cron | Schedule pg_dump/S3 backups and asynchronous restore/cleanup. |
| Ops metrics collector | Dynamic 60 s..1 h | Rust collects process, database, account, and concurrency metrics under an advisory lock with heartbeat. Legacy Redis metric columns remain `NULL`, not falsely healthy. |
| Ops hourly/daily aggregation | 10 min / 1 h | Pre-aggregate ops tables with overlap, safe delay, leader locks, and heartbeats. |
| Ops alert evaluator | Dynamic, default 60 s | Evaluate sustained rules, resolve events, and email alerts under leader lock. |
| Ops cleanup | Default `0 2 * * *` | Retention cleanup plus channel-monitor maintenance; DB settings can reload cron. |
| Ops scheduled reports | Poll every 1 min | Evaluate report crons, deduplicate runs, email reports, heartbeat. |
| Ops system log sink | Flush every 1 s | Batch indexed system logs to PostgreSQL. |
| Content moderation | Up to 32 resident workers plus cleanup | Runtime-configured moderation queue, hash checks, audit logs, and automatic bans. |
| OpenAI WebSocket pool | Ping and sweep every 30 s | Maintain pooled upstream OpenAI sockets and idle/prewarm state. |
| OAuth state stores | Cleanup every 5 min | Claude, OpenAI, Gemini CLI, Antigravity, and xAI in-process OAuth state expiration. |

Go shutdown invokes 30 named application cleanup steps in parallel, then closes
Redis and Ent sequentially. Rust stops HTTP intake, cancels or drains streaming
and worker queues, performs the bounded final billing and usage flushes, stops
schedulers, and then closes PostgreSQL. It does not treat the periodic
30-second flush alone as graceful shutdown.

## Configuration surface

The root Go config namespaces are:

`server`, `log`, `cors`, `security`, `billing`, `turnstile`, `database`,
`redis`, `ops`, `jwt`, `totp`, `linuxdo_connect`, `wechat_connect`,
`oidc_connect`, `dingtalk_connect`, `github_oauth`, `google_oauth`, `default`,
`rate_limit`, `pricing`, `gateway`, `api_key_auth_cache`,
`subscription_cache`, `subscription_maintenance`, `dashboard_cache`,
`dashboard_aggregation`, `usage_cleanup`, `concurrency`, `token_refresh`,
`run_mode`, `timezone`, `gemini`, `update`, `idempotency`, and `batch_image`.

Normal config lookup order is `$DATA_DIR/config.yaml`, `/app/data/config.yaml`,
`./config.yaml`, `./config/config.yaml`, then `/etc/sub2api/config.yaml`.
Viper defaults are applied first, YAML is loaded when present, and environment
variables override dotted keys by replacing `.` with `_`. Bootstrap loading
temporarily permits an empty JWT secret; database secret bootstrap must finish
before full validation.

The auto-setup variables are `AUTO_SETUP`, `DATA_DIR`, `DATABASE_HOST`,
`DATABASE_PORT`, `DATABASE_USER`, `DATABASE_PASSWORD`, `DATABASE_DBNAME`,
`DATABASE_SSLMODE`, legacy `REDIS_*`, `ADMIN_EMAIL`, `ADMIN_PASSWORD`,
`SERVER_HOST`, `SERVER_PORT`, `SERVER_MODE`, `JWT_SECRET`, `JWT_EXPIRE_HOUR`,
`TZ`/`TIMEZONE`, and `SETUP_MIGRATION_TIMEOUT_SECONDS`.

Migration-critical defaults include:

- API-key auth L1: 65,535 entries, 15 s TTL, negative 30 s, singleflight.
- Subscription L1: 16,384 entries, 10 s TTL, singleflight behavior in service.
- Local concurrency slots enabled; local billing cache enabled with 262,144
  entries; direct local cache write-through disabled.
- Usage billing write-behind enabled with an exact 30,000 ms interval.
- User platform quota flusher enabled with an exact 30,000 ms interval.
- Scheduler outbox poll 1 s and full rebuild 300 s.
- Access token defaults to 24 h; refresh session defaults to 30 days and rotates
  on every use.
- Server body limit and gateway body limit default to 256 MiB.

The Rust configuration may intentionally omit the `redis` namespace, but every
other externally used environment/YAML setting needs either compatible parsing
or a documented unsupported-feature failure. Silently ignoring security,
payment, OAuth, proxy, body-limit, or gateway flags is unsafe.

## Redis removal map

The Go repository provider graph constructs Redis implementations for gateway
cache, billing, API-key state, temporary unschedulable state, timeout/403/500
counters, concurrency and session limits, RPM/user RPM, user message queues,
dashboard cache, email and identity state, redeem state, update state, upstream
tokens, batch-image queue/download limits, leader locks, scheduler snapshots,
proxy latency, TOTP, refresh sessions, error passthrough, TLS profiles, and
content-moderation hashes.

Use these PostgreSQL-only replacement classes:

| Semantic class | PostgreSQL-only design |
| --- | --- |
| Read-mostly auth/config/scheduler data | Bounded L1 + TTL + singleflight; transactional outbox or LISTEN/NOTIFY invalidation; PostgreSQL fallback. |
| Refresh sessions, email/TOTP/reset/OAuth state | PostgreSQL rows containing only token hashes, expiry, consumption/revocation state, and indexed owner/family. |
| Leader election | PostgreSQL advisory locks held on dedicated connections, with fencing/state rows when jobs mutate durable data. |
| Batch/cleanup work queues | Durable rows claimed with `FOR UPDATE SKIP LOCKED`, lease expiry, attempts, and idempotency key. |
| Rate/concurrency/session/RPM state | L1 prechecks for the hot path plus PostgreSQL-authoritative fixed windows and expiring leases. Atomic multi-replica limits are never claimed from L1 alone. |
| Write-behind crash recovery | Durable idempotent command/dedup rows or a PostgreSQL outbox. A second in-memory cache is not recovery. |
| Dashboard/update/proxy-latency derived cache | Recomputable L1 with bounded TTL; no durable cache required. |

## Rust migration completion status

The Rust route-coverage check accounts for all 532 Go registration records and
all 531 unique `method+path` contracts. It reports 531 mounted unique contracts,
zero missing contracts, and one intentional absence: the Redis-specific
`POST /setup/test-redis`. Rust also exposes `/ready` as a PostgreSQL readiness
probe. Unknown API and gateway paths return an explicit 404 instead of falling
through to the embedded frontend.

The runtime is PostgreSQL-only. It has no Redis client dependency, does not read
`REDIS_*`, and the Rust Compose topology contains only the application and
PostgreSQL services. PostgreSQL tables, transactions, advisory locks,
`LISTEN/NOTIFY`, durable outboxes, and expiring leases own cross-process
correctness. Bounded L1 caches remain the preferred hot path for authentication,
scheduler snapshots, pricing, quotas, and other read-heavy state; PostgreSQL is
the source of truth and notification is only a wake-up hint.

Implemented migration surfaces include:

| Surface | Rust implementation status |
| --- | --- |
| Gateway | Anthropic, OpenAI, Gemini, Antigravity, and Grok routing is mounted across HTTP, conditional SSE, and OpenAI Responses WebSocket transports. API-key/group selection, model mapping, quota and rate gates, cross-replica concurrency leases, scheduling/failover, durable pre-flush billing reservations, usage extraction, billing, and ops-error recording are integrated with the PostgreSQL/L1 runtime. |
| Authentication and OAuth | Access and refresh authentication, TOTP, email/reset state, OAuth/OIDC callbacks, provider identities, account credential flows, login-failure windows, and sensitive-action rate windows use PostgreSQL. Rate-limit subjects are stored only as domain-separated hashes. Refresh-session rotation, family revocation, reuse detection, logout-all, and restart persistence no longer depend on Redis. |
| User and administrator APIs | The user, payment, page, and administrator route inventories are mounted with dedicated handlers for resource relations, usage views, operational dashboards, imports/exports, settings, and compatibility responses. Admin authentication and compliance guards remain enforced. |
| Payment | Provider configuration, order lifecycle, refunds, signed resume handling, and provider webhooks are PostgreSQL-backed. Provider lookup, database, configuration, order lookup, and signature-verification failures are non-2xx; only a verified, explicitly irrelevant event or verified unknown order is acknowledged. |
| Operations and schedulers | Metrics and dashboard aggregation, upstream/system error logs, alerts (including percentile rules and durable notification retry), cleanup, scheduled reports, scheduled tests, channel monitors, expiry maintenance, pricing refresh, and token refresh run without Redis. Advisory locks and persisted claims prevent duplicate durable work. |
| Backup and batch work | PostgreSQL `pg_dump`/restore, legacy Go gzip/plain-SQL restore, local or S3 backup scheduling and cleanup, and the batch-image queue/leases, recovery, settlement, download, and retention paths are implemented with durable PostgreSQL state. |
| Setup and frontend | Web setup accepts PostgreSQL only, persists its restart configuration under `DATA_DIR`, and retains empty-database administrator takeover protection. Embedded assets, public settings/CSP injection, page visibility, static overrides, health, and readiness are served by the Rust process. |

There are two distinct fixed 30-second write-behind paths: billing/quota
mutations and detailed usage logs. Both use bounded queues, idempotent durable
writes, retry/error visibility, and a final bounded drain during graceful
shutdown. L1 state that has not reached PostgreSQL is not described as durable;
operators should use the exposed pending/unflushed health data when deciding
whether a shutdown completed cleanly.

System restart and immutable-container deployment are deliberately different.
A restart request is persisted and causes graceful process shutdown so the
container restart policy or supervisor can start it again. Update and rollback
requests do not download a binary, replace the running executable, invoke
Docker, or mount the Docker socket. They persist the current request plus a
bounded request history, and return `requires_redeploy=true`, the validated
target version, and a `redeploy_command` for an operator or host orchestrator to
execute. `SUB2API_REDEPLOY_COMMAND` may provide that host-command template with
`{operation}` and `{version}` placeholders.

Route coverage establishes registration completeness, not automatic semantic
equivalence for every credential, upstream, failure, or timing combination.
The PostgreSQL integration suite and target-container smoke tests in the next
section remain release gates.

## Reproducible checks

The manifest was produced by resolving Gin `Group` assignments and route calls
in the eight production registration sources, then cross-checking the result
against every source-level method registration.

Recorded route-coverage acceptance result for the completed Rust migration:

```text
TSV row count                         532
unique method+path                    531
normal-mode registration count       528
dynamic route count                   178
WebSocket registrations                 4
conditional-SSE registrations          12
```

Contract testing should enumerate the TSV against Go and Rust with anonymous,
user JWT, admin JWT, Anthropic API-key, Google API-key, invalid credential, body
limit, and backend-mode cases. Dynamic routes need representative valid and
invalid parameters; wildcard routes need empty and nested subpaths.

The route inventory can be reproduced with:

```bash
cargo run --manifest-path backend-rust/Cargo.toml --example route_coverage --locked
```

Before production use, run the ignored integration tests against a disposable
PostgreSQL database and build/start the Compose deployment in the target Linux
container runtime. The documentation update itself does not claim that Docker
or the deployment shell script was executed on the authoring host.
