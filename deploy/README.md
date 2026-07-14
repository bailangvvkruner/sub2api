# Rust/PostgreSQL Deployment

The supported production stack consists of the Rust application and
PostgreSQL 18. It has no Redis service and does not execute the retired backend.

## Files

| File | Purpose |
| --- | --- |
| `docker-compose.yml` | Application plus local PostgreSQL |
| `docker-compose.standalone.yml` | Application with external PostgreSQL |
| `.env.example` | Supported environment variables |
| `docker-deploy.sh` | Stable compatibility entry point |
| `docker-deploy-rust.sh` | Source checkout, secret generation, and rollback preparation |
| `sub2api.service` | Optional unit for a manually installed Rust binary |

The removed local/dev/rust Compose variants and native installer were part of
the retired stack and are no longer supported.

## First Deployment

```sh
mkdir sub2api-deploy
cd sub2api-deploy
curl -fsSL https://raw.githubusercontent.com/bailangvvkruner/sub2api/main/deploy/docker-deploy.sh | sh
DOCKER_BUILDKIT=1 docker compose up -d --build --remove-orphans
docker compose logs -f sub2api
```

The helper generates `.env` with restricted permissions and creates `data/`
and `postgres_data/`. Preserve `.env` across upgrades and restores.

For a checked-out repository, you may instead copy `.env.example` to `.env`,
generate `POSTGRES_PASSWORD`, `JWT_SECRET`, and `TOTP_ENCRYPTION_KEY` with
`openssl rand -hex 32`, then run
`docker compose up -d --build --remove-orphans`.

## External PostgreSQL

Configure `DATABASE_HOST`, `DATABASE_PASSWORD`, and the other `DATABASE_*`
values, then run:

```sh
docker compose -f docker-compose.standalone.yml up -d --build --remove-orphans
```

TLS defaults to `require` in this mode. Override `DATABASE_SSLMODE` only when
the database network is otherwise protected and the risk is understood.

## Upgrade And Rollback

Run the deployment helper again to fetch `main`, validate persistent state, and
record the previous immutable revision:

```sh
sh docker-deploy.sh
DOCKER_BUILDKIT=1 docker compose up -d --build --remove-orphans
```

For a pinned deployment, set `SUB2API_RUST_REF` to a full 40-character commit
SHA. Never reuse an old application image with a database schema it does not
support.

## Backup And Restore

Create logical PostgreSQL backups with the PostgreSQL tools shipped in the
application image or database container:

```sh
docker compose exec -T postgres pg_dump -U sub2api -d sub2api -Fc > sub2api.dump
```

Also back up `.env` and `data/`. Test restores regularly in an isolated
environment. Stop application traffic before a destructive restore.

## Health And Logs

```sh
docker compose ps
docker compose logs --tail=200 sub2api
curl --fail http://127.0.0.1:8080/ready
```

The application is ready only after PostgreSQL is reachable and migrations
have completed.
