# Sub2API

[![CI](https://github.com/bailangvvkruner/sub2api/actions/workflows/backend-ci.yml/badge.svg)](https://github.com/bailangvvkruner/sub2api/actions/workflows/backend-ci.yml)
[![Security Scan](https://github.com/bailangvvkruner/sub2api/actions/workflows/security-scan.yml/badge.svg)](https://github.com/bailangvvkruner/sub2api/actions/workflows/security-scan.yml)
[![License: LGPL-3.0](https://img.shields.io/badge/License-LGPL--3.0-blue.svg)](LICENSE)

[English](README.md) · [简体中文](README_CN.md) · [日本語](README_JA.md)

Sub2API is a self-hosted AI API gateway and operations platform. It presents
Anthropic-, OpenAI-, and Gemini-compatible APIs, routes traffic across multiple
upstream account types, and keeps authentication, quota, billing, payments,
scheduling, monitoring, and administration in one deployment.

The supported production backend is written in Rust. PostgreSQL 18 is the only
required state service: Redis and a Go runtime are not used by the active build,
release, or deployment path.

## Highlights

- **Multi-protocol gateway** — Anthropic Messages, OpenAI Chat Completions,
  Responses, embeddings, image and video APIs, plus Gemini `v1beta` model APIs.
- **Streaming transports** — buffered JSON, SSE, and bidirectional OpenAI
  Responses WebSocket sessions with cancellation, timeout, and usage handling.
- **Provider adapters** — Anthropic, OpenAI, Gemini, Antigravity, Grok, AWS
  Bedrock, and Google Vertex AI account flows.
- **Routing and resilience** — account groups, priorities, load factors, model
  mapping, proxy fallback, TLS fingerprints, failover, and dynamic policies.
- **Exact usage and billing** — token/media accounting, pricing snapshots,
  balance and subscription charging, reservations, refunds, and durable usage
  writes.
- **Authentication and access** — password login, JWT sessions, OAuth/OIDC,
  email verification, TOTP, API keys, group access, IP rules, and administrator
  compliance gates.
- **Control plane** — users, accounts, channels, groups, proxies, subscriptions,
  payment providers, announcements, pages, moderation, and batch operations.
- **Operations** — real-time metrics, alerts, logs, scheduled tests, channel
  monitors, cleanup jobs, pricing refresh, backup/restore, and controlled
  redeployment requests.
- **PostgreSQL-native coordination** — advisory locks, transactional outboxes,
  leases, `FOR UPDATE SKIP LOCKED`, `LISTEN/NOTIFY`, and bounded in-process L1
  caches replace Redis-backed coordination.

## Architecture

```mermaid
flowchart LR
    Clients["API clients"] --> Gateway["Rust gateway and control plane"]
    Browser["Admin and user browser"] --> UI["Embedded Vue SPA"]
    UI --> Gateway
    Gateway <--> PostgreSQL["PostgreSQL 18"]
    Gateway --> Providers["AI providers"]
    Payments["Payment providers"] --> Gateway
```

| Layer | Implementation |
| --- | --- |
| API and runtime | Rust (edition 2024), Axum, Tokio, SQLx |
| Transport security | rustls with AWS-LC |
| Persistent state | PostgreSQL 18 |
| Web application | Vue 3, TypeScript, Vite, Pinia |
| Packaging | One application image with the Rust binary and built Vue assets |
| Coordination | PostgreSQL transactions, locks, outboxes, leases, and notifications |

## API Surfaces

| Compatibility surface | Representative endpoints |
| --- | --- |
| Anthropic | `/v1/messages`, `/v1/messages/count_tokens` |
| OpenAI | `/v1/chat/completions`, `/v1/responses`, `/v1/embeddings`, `/v1/images/*`, `/v1/videos/*` |
| Gemini | `/v1beta/models`, `/v1beta/models/{model}:generateContent` |
| User and administrator APIs | `/api/v1/*` |
| Setup and health | `/setup/*`, `/health`, `/ready` |

The compatibility inventory contains 532 registration records and 531 unique
method/path keys. Rust mounts all 531 supported keys and deliberately omits only
the retired `POST /setup/test-redis` probe. This measures route registration,
not blanket semantic identity with every historical implementation detail.

## Quick Start

### Managed Docker Compose setup

The deployment helper checks out the Rust application, creates a protected
`.env`, generates independent PostgreSQL/JWT/TOTP secrets, and prepares the
application and PostgreSQL volumes:

```sh
SUB2API_PATH=/data/sub2api
mkdir -p "$SUB2API_PATH"
cd "$SUB2API_PATH"

curl -fsSL \
  https://raw.githubusercontent.com/bailangvvkruner/sub2api/main/deploy/docker-deploy.sh \
  | sh

DOCKER_BUILDKIT=1 docker compose up -d --build --remove-orphans
docker compose logs -f sub2api
```

Open `http://localhost:8080`. When `ADMIN_PASSWORD` is empty on a new database,
the application writes a one-time generated administrator password to the log:

```sh
docker compose logs sub2api | grep 'admin password'
```

### Docker Hub Rust channel

Verified main builds publish `<dockerhub-user>/sub2api:rust` to the Docker Hub
repository configured by the `DOCKERHUB_USERNAME` repository secret. Release
workflows also publish versioned tags, while main builds retain immutable
`sha-*` tags. The moving `:rust` tag is convenient for evaluation; pin a
version or digest in production. Main builds currently publish `linux/amd64`;
tagged releases publish both `linux/amd64` and `linux/arm64`.

With a prepared deployment directory and `.env`:

```sh
export SUB2API_RUST_IMAGE='<dockerhub-user>/sub2api:rust'
docker compose pull
docker compose up -d --no-build --remove-orphans
```

For an externally managed PostgreSQL server, use
[`deploy/docker-compose.standalone.yml`](deploy/docker-compose.standalone.yml)
and configure the `DATABASE_*` variables.

## Persistent Data

The default Compose deployment treats these paths as one recovery unit:

| Path | Contents |
| --- | --- |
| `.env` | Database credential, JWT secret, TOTP encryption key, deployment settings |
| `data/` | Setup state, pricing data, backups, and public overrides |
| `postgres_data/` | PostgreSQL cluster data |

Back up all three together. Replacing `.env` for an existing database can make
database access, JWT sessions, and encrypted application secrets unrecoverable.
The supplied stack currently targets PostgreSQL 18; upgrade older clusters with
`pg_upgrade` or a tested logical backup/restore before switching.

## Configuration

Environment variables are the supported deployment contract. Important values
include:

| Variable | Purpose |
| --- | --- |
| `DATABASE_URL` or `DATABASE_*` | PostgreSQL connection and pool settings |
| `JWT_SECRET` | Signs application JWTs |
| `TOTP_ENCRYPTION_KEY` | Encrypts stored TOTP material; use 64 hexadecimal characters |
| `ADMIN_EMAIL`, `ADMIN_PASSWORD` | Empty-database administrator bootstrap |
| `SERVER_HOST`, `SERVER_PORT` | Listener address |
| `CORS_ALLOWED_ORIGINS` | Exact allowed browser origins; empty denies cross-origin access |
| `TRUST_PROXY_HEADERS` | Enables trusted reverse-proxy address handling |
| `MIGRATIONS_MODE` | Direct-runtime behavior: `apply`, `validate`, or `off`; supplied Compose uses `apply` |
| `PRICING_*` | Signed pricing catalog source and host allowlist |
| `RUST_LOG` | Runtime logging filters |

See [`deploy/.env.example`](deploy/.env.example) for the deployment template and
[`backend-rust/README.md`](backend-rust/README.md) for the complete runtime
behavior. Terminate TLS at a reviewed reverse proxy and keep the application
data directory private.

When running the binary directly, environment variables take precedence over
legacy configuration. The supplied Compose stack defaults
`SETUP_CONFIG_OVERRIDES_ENV=true`; after web setup, the persisted
`data/rust-setup.json` may therefore override database and listener bootstrap
values. Set it to `false` when deployment configuration must stay authoritative.

## Local Development

Requirements:

- Rust 1.97 with `rustfmt` and Clippy (the pinned CI toolchain; crate MSRV is 1.94)
- Node.js 20 or newer and pnpm 9
- PostgreSQL 18 for integration tests

```sh
corepack enable
pnpm --dir frontend install --frozen-lockfile
make build
make test
```

Focused checks:

```sh
cargo fmt --manifest-path backend-rust/Cargo.toml --all -- --check
cargo clippy --manifest-path backend-rust/Cargo.toml --all-targets --locked -- -D warnings
cargo test --manifest-path backend-rust/Cargo.toml --all-targets --locked
pnpm --dir frontend run lint:check
pnpm --dir frontend run typecheck
pnpm --dir frontend run test:run
```

PostgreSQL integration tests are destructive and require a disposable database
whose name ends in `_test`:

```sh
export TEST_DATABASE_URL='postgresql://sub2api:password@127.0.0.1:5432/sub2api_test?sslmode=disable'
make test-rust-integration
```

Never point the integration suite at a production database.

## Repository Layout

```text
backend-rust/   Rust gateway, control plane, migrations, and pricing resources
frontend/       Vue web application
deploy/         Compose files, environment template, and deployment helpers
docs/           Product, payment, legal, and operational documentation
backend/        Retired Go implementation; read-only behavior reference
```

The active Rust build does not read source, migrations, or resources from
`backend/`. That directory is excluded from the production Docker build context
and is not part of supported CI, release, installation, or deployment paths.

## Migrating from the Retired Go/Redis Stack

- Back up `.env`, application data, and PostgreSQL before cutover.
- Run the first Compose start with `--remove-orphans` to remove the retired
  Redis container from an existing Compose project.
- Redis-backed refresh sessions are not imported. Users holding those refresh
  tokens must sign in again after the switch.
- A bounded compatibility layer reads supported legacy `config.yaml` values.
  Unsupported non-default authentication, security, proxy, or critical gateway
  settings fail startup with the exact key instead of being silently ignored.
- Legacy backup metadata and guarded `.sql.gz` restores remain supported; new
  backups use PostgreSQL custom archives with persisted SHA-256 digests.

## Documentation

- [Rust backend and runtime behavior](backend-rust/README.md)
- [Production deployment](deploy/README.md)
- [Development guide](DEV_GUIDE.md)
- [Payment integration](docs/PAYMENT.md)
- [Route parity inventory](backend-rust/docs/go-parity-inventory.md)

## License

Sub2API is distributed under the [GNU Lesser General Public License v3.0](LICENSE).
