# Sub2API Rust / PostgreSQL migration target

This directory contains the Rust rewrite of the Sub2API backend. It is
deliberately PostgreSQL-only: the crate has no Redis dependency and does not
read any `REDIS_*` configuration.

The retired `backend/` tree remains in the repository only for behavior
comparison and migration research. The Rust build consumes no source,
migrations, or static resources from it, and it is not part of any supported
build, test, release, or deployment path.

## Runtime scope

This is the PostgreSQL-only replacement backend. It provides:

- Axum/Tokio HTTP runtime with graceful shutdown and request tracing.
- PostgreSQL-backed setup, authentication, OAuth/OIDC, TOTP, user, payment,
  administrator, and compatibility APIs.
- Anthropic, OpenAI, Gemini, Antigravity, and Grok gateway proxying, including
  HTTP, SSE, OpenAI Responses WebSocket transport, exact pending billing,
  quota gates, and durable usage writes.
- PostgreSQL-backed batch-image submission, polling, cancellation, settlement,
  output download, and retention cleanup.
- Embedded frontend assets plus `/health` and PostgreSQL-backed `/ready` probes.
- SQLx PostgreSQL pooling using the existing `DATABASE_*` environment contract.
- All existing SQL migrations embedded in the binary.
- Migration filename ordering, SHA-256 immutability checks, advisory locking,
  transactional migrations, concurrent-index migrations, and the existing
  checksum compatibility exceptions.
- PostgreSQL `LISTEN/NOTIFY`, durable outboxes, leases, and bounded L1 caches in
  place of Redis queues, pub/sub, and shared cache state.
- Hashed PostgreSQL authentication rate windows and gateway-wide fixed-minute
  RPM/concurrency authority for multi-replica enforcement.
- A fixed 30-second billing and usage write-behind interval, plus a final
  bounded drain before PostgreSQL is closed during graceful shutdown.

`examples/route_coverage.rs` checks all 532 Go registration records (531 unique
method/path contracts). The only intentional absence is the legacy
`POST /setup/test-redis` endpoint; unknown routes return an explicit 404.

## Docker deployment

The deployment uses only the application and PostgreSQL containers. It creates
`./postgres_data` for PostgreSQL and reuses `./data` for application data, so a
Go deployment's local backups and public assets remain visible during the Rust
switch. Generated PostgreSQL, JWT, and TOTP secrets are persisted in `.env`.

```bash
SUB2API_PATH=/data/sub2api
mkdir -p "$SUB2API_PATH"
cd "$SUB2API_PATH"

curl -sSL \
  https://raw.githubusercontent.com/bailangvvkruner/sub2api/main/deploy/docker-deploy-rust.sh \
  | sh

docker compose up -d --build --remove-orphans
docker compose logs sub2api | grep '@'
docker compose logs sub2api | grep 'admin password'
```

Use `docker-compose` in place of `docker compose` on hosts that still ship the
standalone Compose v1 command. An empty `ADMIN_PASSWORD` causes the first empty
database startup to generate a one-time administrator password in the log.

The deploy script treats the bind-mounted directories and `.env` as one
deployment unit:

- `./data` is mounted at `/app/data`; setup state, pricing data, local backups,
  and public overrides survive replacement of the application container. The
  entrypoint gives the unprivileged application user ownership of this mount.
- `./postgres_data` is mounted as PostgreSQL's data directory. If it already
  contains `PG_VERSION`, the script requires PostgreSQL 18 and refuses to
  continue when `.env` is absent or any persisted database/JWT/TOTP credential
  is missing. Use `pg_upgrade` or restore a logical dump before switching an
  older cluster. Restore the matching `.env`; generating new secrets for an
  existing cluster will not recover database access or encrypted application
  state.
- Back up `.env`, `data`, and `postgres_data` together before switching an
  existing deployment. The script preserves non-empty existing values and
  creates only missing Rust secrets.
- Keep `--remove-orphans` on the first Rust `docker compose up`. When the old Go
  Compose project used the same project directory, this removes its orphaned
  Redis service; the Rust application never connects to Redis.
- Redis-backed Go refresh sessions are not imported into PostgreSQL. Existing
  access tokens can only follow their normal validity rules; an old refresh
  token cannot create a Rust session, so affected users must sign in again
  after cutover.

Backup metadata created by Go is retained. Go `.sql.gz` objects are restored
through the legacy gzip/plain-SQL path with compressed-size and gzip CRC
validation plus a decompressed-size ceiling (`BACKUP_MAX_RESTORE_BYTES`, 64 GiB
by default). New Rust backups use
custom PostgreSQL archives with a persisted SHA-256 digest. Both formats restore
under the same cross-instance operation lock, temporary read-only gate, and
single-transaction/stop-on-first-error policy.

Web setup writes the selected database and server address to
`DATA_DIR/rust-setup.json`. Environment variables win by default when running
the binary directly. The supplied Compose file defaults
`SETUP_CONFIG_OVERRIDES_ENV=true`, so an existing setup file takes precedence
over the Compose bootstrap values for `DATABASE_URL`, `DATABASE_*`,
`SERVER_HOST`, and `SERVER_PORT` after setup. Set it to `false` when deployment
configuration must remain authoritative. Other runtime environment variables
are unaffected by this switch. The setup file contains the database credential;
keep the application data volume private and include it in protected backups.

For cutover, the Rust binary searches the legacy `config.yaml` locations and
honors `SUB2API_CONFIG_FILE`. Environment variables take precedence. The
compatibility layer maps database, listener, JWT/TOTP lifetime and secrets,
gateway limits, administrator bootstrap, timezone, CORS, and trusted-proxy
settings. A legacy OAuth or Turnstile feature that is explicitly enabled, or a
non-default authentication, security, proxy, or critical gateway setting that
has no Rust equivalent, aborts startup with the exact key. Migrate that setting
through the Rust administrator settings or supported environment contract,
then remove or reset the legacy key; it is never silently ignored.

### Immutable container update and rollback

The administrator update and rollback APIs record a PostgreSQL deployment
request and return `requires_redeploy=true`, a target version, and a host-side
`redeploy_command`. They do not modify the binary or execute Docker inside the
application container. The supplied Compose file passes through an optional
`SUB2API_REDEPLOY_COMMAND` template; `{operation}` and `{version}` are replaced
in the returned command.

For example, point the response at a host-owned, reviewed deployment wrapper:

```dotenv
SUB2API_REDEPLOY_COMMAND="cd /data/sub2api && ./redeploy-sub2api.sh {operation} {version}"
```

The operator or external orchestrator must execute the returned command on the
host. The wrapper should validate the operation/version again, select the
approved image or Git ref, and finish with:

```bash
docker compose up -d --build --remove-orphans
```

When no template is configured, the API returns the built-in Git/Compose host
command. Treat it as an instruction for the deployment host, not as work that
has already run. A service restart is separate: it records the request and
gracefully exits, after which `restart: unless-stopped` or the host supervisor
starts the container again.

## Run locally

PostgreSQL 18 is the current integration-test target. Compatibility with older
supported Sub2API PostgreSQL versions should be claimed only after the same
migration suite runs there.

```bash
export DATABASE_URL='postgresql://sub2api:password@127.0.0.1:5432/sub2api?sslmode=disable'
export TOTP_ENCRYPTION_KEY="$(openssl rand -hex 32)"
cargo run --manifest-path backend-rust/Cargo.toml --locked
```

The legacy variables are also supported:

```text
DATABASE_HOST
DATABASE_PORT
DATABASE_USER
DATABASE_PASSWORD
DATABASE_DBNAME
DATABASE_SSLMODE
DATABASE_MAX_OPEN_CONNS
DATABASE_MIN_CONNS
DATABASE_ACQUIRE_TIMEOUT_SECONDS
DATABASE_CONN_MAX_LIFETIME_MINUTES
DATABASE_CONN_MAX_IDLE_TIME_MINUTES
```

`DATABASE_MAX_IDLE_CONNS` has no exact SQLx pool equivalent and is currently
ignored; maximum connections, connection lifetime, and idle timeout are
honored explicitly.

Cross-origin requests are rejected by default. Set `CORS_ALLOWED_ORIGINS` to
a comma-separated list of exact origins, or to `*` for public API deployments.
`CORS_ALLOW_CREDENTIALS` defaults to `true` for explicit origins and is always
disabled when the wildcard is used.

The bundled pricing catalog is the startup fallback. A background runtime
checks the published SHA-256 manifest every ten minutes, validates the complete
replacement catalog, persists it under the application data volume, and swaps
the in-memory billing snapshot atomically. `PRICING_ALLOWED_HOSTS` restricts
custom `PRICING_REMOTE_URL` and `PRICING_HASH_URL` hosts; HTTPS is required by
default.

Migration behavior is controlled by `MIGRATIONS_MODE`:

- `apply` (default): validate applied checksums and apply pending migrations.
- `validate`: fail when a checksum changed or a migration is pending.
- `off`: do not inspect or apply migrations.

`SETUP_MIGRATION_TIMEOUT_SECONDS` bounds the complete migration or validation
operation, including advisory-lock wait and SQL execution. A zero value uses
the existing 60-second setup default.

## Verify

```bash
make test-rust
```

Or directly:

```bash
cargo fmt --manifest-path backend-rust/Cargo.toml --all -- --check
cargo clippy --manifest-path backend-rust/Cargo.toml --all-targets --locked -- -D warnings
cargo test --manifest-path backend-rust/Cargo.toml --all-targets --locked
cargo run --manifest-path backend-rust/Cargo.toml --example route_coverage --locked
```

The destructive migration integration test requires `TEST_DATABASE_URL` to
name a disposable database ending in `_test` and must be enabled explicitly:

```bash
TEST_DATABASE_URL='postgresql://sub2api:password@127.0.0.1/sub2api_rust_test' \
  make test-rust-integration
```

## Redis replacement rules

The rewrite does not translate Redis commands one-for-one. PostgreSQL owns
durable and cross-instance correctness; bounded in-process caches may only be
used where stale data cannot violate billing, quota, or scheduling rules.

| Existing responsibility | PostgreSQL-only replacement |
| --- | --- |
| Distributed leader locks | Session advisory locks on one pinned connection |
| Work queues | Lease rows claimed with `FOR UPDATE SKIP LOCKED` |
| Idempotency and deduplication | Unique constraints plus transactional inserts |
| Concurrency permits | Expiring lease rows updated atomically |
| Rate-limit counters | Atomic bucket upserts with database timestamps |
| Cache invalidation | Version columns and `LISTEN/NOTIFY` as a wake-up hint |
| Scheduler state | Existing scheduler outbox and snapshot tables |
| Read-through caches | Bounded process memory with PostgreSQL as source of truth |

`LISTEN/NOTIFY` is never the durable queue: consumers always recover state from
tables after reconnecting or missing a notification.

## Release checks

Before directing production traffic to a build, run the ignored tests against
a migrated disposable PostgreSQL database, exercise the route coverage example,
and build and start the deployment image in the target container runtime.
