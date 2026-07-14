# Development Guide

Sub2API production development is Rust-first and PostgreSQL-only. The retired
implementation under `backend/` is read-only reference material and must not be
added to build, test, release, or deployment automation.

## Toolchain

- Rust 1.97 with `rustfmt` and `clippy`
- Node.js 20 or newer and pnpm 9
- PostgreSQL 18 for integration tests
- Docker BuildKit for production image validation

No Redis service or Go toolchain is needed.

## Repository Layout

```text
backend-rust/   Rust API gateway and control plane
frontend/       Vue frontend
frontend-dist/  generated frontend production bundle
backend/        retired behavior reference only
deploy/         Rust/PostgreSQL deployment assets
docs/           product and operational documentation
```

The Rust build owns and embeds SQL migrations from `backend-rust/migrations`
and model-pricing data from `backend-rust/resources`. Nothing in the active
build reads from the retired backend tree.

## Build And Test

```sh
pnpm --dir frontend install --frozen-lockfile
make build
make test
```

The equivalent focused commands are:

```sh
cargo fmt --manifest-path backend-rust/Cargo.toml --all -- --check
cargo clippy --manifest-path backend-rust/Cargo.toml --all-targets --locked -- -D warnings
cargo test --manifest-path backend-rust/Cargo.toml --all-targets --locked
pnpm --dir frontend run typecheck
```

For PostgreSQL integration tests, create an isolated database and export a
connection URL before running the integration target:

```sh
export TEST_DATABASE_URL='postgresql://sub2api:password@127.0.0.1:5432/sub2api_test?sslmode=disable'
make test-rust-integration
```

Never point tests at a production database.

## Production Image

```sh
docker build \
  --build-arg SUB2API_BUILD_VERSION=development \
  -t sub2api:development \
  -f Dockerfile .
```

The root `Dockerfile` is authoritative. Do not add parallel backend images or
deployment-specific Dockerfiles.

## Change Checklist

- Format and lint Rust with warnings denied.
- Add focused tests for changed behavior.
- Run frontend type checking for API contract changes.
- Run PostgreSQL integration tests for schema, repository, authentication,
  billing, scheduler, or cross-instance changes.
- Keep the default Compose and environment example in sync when adding a
  production environment variable.
- Do not introduce Go or Redis into supported automation.
