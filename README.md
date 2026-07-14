# Sub2API

[简体中文](README_CN.md) | [日本語](README_JA.md)

Sub2API is a self-hosted AI API gateway. The production backend is Rust and
PostgreSQL is the only required state service.

## Runtime Contract

- `backend-rust/` is the sole supported backend implementation.
- PostgreSQL 18 stores application state, sessions, rate limits, jobs, and
  coordination data. Redis is not used or required.
- The Vue frontend is built into the production container.
- `backend/` contains the retired implementation for migration archaeology and
  behavior comparison only. It is not built, tested, released, or deployed by
  any supported workflow.
- Environment variables remain authoritative. A bounded compatibility layer
  reads legacy `config.yaml` values needed for cutover; unsupported non-default
  authentication, security, proxy, and gateway behavior fails startup with the
  exact key instead of being ignored.
- Redis-backed refresh sessions are not imported. After switching from Go,
  existing refresh tokens require users to sign in again.

## Docker Deployment

The deployment helper creates persistent secrets, checks the PostgreSQL data
directory, and prepares the Rust Compose stack:

```sh
mkdir sub2api-deploy
cd sub2api-deploy
curl -fsSL https://raw.githubusercontent.com/bailangvvkruner/sub2api/main/deploy/docker-deploy.sh | sh
DOCKER_BUILDKIT=1 docker compose up -d --build --remove-orphans
```

Open `http://localhost:8080`. Operational commands:

```sh
docker compose ps
docker compose logs -f sub2api
docker compose pull
docker compose up -d --build --remove-orphans
```

The default stack persists `./data` and `./postgres_data`. Back up both the
PostgreSQL database and `.env`; authentication and encrypted secrets depend on
the persistent values in `.env`.

For an externally managed PostgreSQL server, use
`deploy/docker-compose.standalone.yml` and configure the `DATABASE_*`
variables in `deploy/.env.example`.

## Development

Requirements are Rust 1.97, Node.js 20 or newer, pnpm 9, and PostgreSQL 18 for
integration tests.

```sh
pnpm --dir frontend install --frozen-lockfile
make build
make test
```

PostgreSQL integration tests require `TEST_DATABASE_URL`:

```sh
export TEST_DATABASE_URL='postgresql://sub2api:password@127.0.0.1:5432/sub2api_test?sslmode=disable'
make test-rust-integration
```

See [DEV_GUIDE.md](DEV_GUIDE.md) for repository conventions and
[deploy/README.md](deploy/README.md) for production operations.

## License

See [LICENSE](LICENSE).
