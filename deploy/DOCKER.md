# Sub2API Container

This image contains the Rust backend and the built Vue frontend. PostgreSQL is
the only external state service; Redis and a Go runtime are not required.

Use the repository's `deploy/docker-compose.yml` for a complete deployment:

```sh
cp .env.example .env
# Set POSTGRES_PASSWORD, JWT_SECRET, and TOTP_ENCRYPTION_KEY.
docker compose up -d --build --remove-orphans
```

The container listens on port `8080`, stores mutable files under `/app/data`,
and exposes `/health` and `/ready`. Supported configuration is supplied through
environment variables documented in `deploy/.env.example`.

For production, pin a version or immutable digest, persist `.env` and
PostgreSQL backups, and place TLS termination in front of the service.
